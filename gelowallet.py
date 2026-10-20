#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
gelowallet.py - Carteira Bitcoin BIP84 de terminal com montador de
transacoes P2WPKH (baseado em darkwallet.py + utx0.py).

Melhorias em relacao aos dois scripts originais:
  - wallets.json gravado de forma ATOMICA (tmp + fsync + os.replace) e com
    permissao 0600 (antes ficava 0644, legivel por outros usuarios).
    O diretorio tambem e sincronizado (fsync) apos o replace.
  - Argon2id (memory-hard) para derivar a chave da Senha Mestra; arquivos
    antigos em PBKDF2 (600k iteracoes) continuam abrindo e sao migrados
    para Argon2id na proxima gravacao.
  - Senha mestra exige minimo de 12 caracteres (avisa se parecer fraca);
    passphrase e mnemonic digitados com getpass (sem aparecer na tela nem
    no historico).
  - Mnemonic so e exibido na criacao/importacao (nao ao carregar carteira).
  - Arquivo corrompido detectado e reportado com clareza; quando a senha
    falha, o programa tenta abrir o cofre sem senha para distinguir
    "senha errada" de "arquivo adulterado".
  - Timeout em TODAS as requisicoes HTTP (antes: podia travar para sempre).
  - Derivacao da cadeia interna (change) m/84'/0'/0'/1/i.
  - Transacao com: filtro de UTXOs confirmados, RBF sinalizado, dust correto
    para P2WPKH (294 sats), aviso de taxa excessiva (percentual OU valor
    absoluto), conferencia de valor minimo do destino, exportacao de HEX
    assinado e de PSBT (sem assinar, com derivacoes de entrada e de troco).
  - Verificacao de seguranca: endereco derivado pela embit deve bater com
    o endereco derivado pela implementacao propria antes de assinar.
  - Dados de derivacao (conta, cadeia, indices ja usados) sao salvos junto
    com o mnemonic; ao gastar, a origem pode ser qualquer endereco
    (externo ou de troco) de qualquer conta, selecionado por carteira.
  - Montagem de transacao em perguntas simples: endereco de origem (pode
    ser copiado do menu), endereco de destino, valor e taxa. A taxa e
    consultada na rede e o programa mostra qual esta sendo usada.
  - Saldos e troco sao lidos do mesmo endereco de origem, sem varrer a rede,
    mantendo a privacidade. O troco volta para o endereco de origem.

AVISO: use por sua conta e risco. Nao transmite
transacoes: o HEX/PSBT gerado deve ser transmitido manualmente. Por padrao
as consultas vao para mempool.space, que VE os enderecos publicos
consultados; use GELOWALLET_API para apontar a um node proprio ou via Tor.
"""

import base64
import getpass
import hashlib
import hmac
import json
import math
import os
import re
import sys
import tempfile

import base58
import bech32
import requests
from Crypto.Hash import RIPEMD160
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import ecdsa
from mnemonic import Mnemonic
import qrcode

from embit import ec, psbt, script, transaction

# ==========================================================
# CONFIGURACAO GERAL
# ==========================================================

ARQUIVO_CARTEIRAS = "wallets.json"

# Derivacao de chave da Senha Mestra.
# Padrao atual: Argon2id (memory-hard), resistente a ataque offline por GPU
# muito melhor que PBKDF2. Parametros escolhidos para ~0,1s por tentativa
# nesta classe de maquina (OWASP: minima de 19 MiB; usamos 64 MiB).
KDF_ATUAL = "argon2id"
ARGON2_ITERACOES = 3
ARGON2_LANES = 4
ARGON2_MEMORIA_KIB = 64 * 1024  # 64 MiB

# Formato antigo (PBKDF2), mantido apenas para ABRIR arquivos ja existentes.
# Arquivos com este KDF sao migrados para Argon2id ao serem abertos.
ITERACOES_PBKDF2 = 600_000
KDF_LEGADO = "pbkdf2-sha256"

TAMANHO_SALT = 16
# Piso de senha: 12 caracteres (mais entropia contra forca bruta offline).
MIN_TAMANHO_SENHA = 12

QTD_ENDERECOS = 20

# Pode ser sobrescrito para node proprio ou instancia Tor:
#   GELOWALLET_API="http://127.0.0.1:3000/api" python3 gelowallet.py
API_BASE = os.environ.get(
    "GELOWALLET_API", "https://mempool.space/api"
).rstrip("/")
REQUEST_TIMEOUT = 20

# Padrao da API publica. Se o usuario nao trocar por um node proprio/ Tor,
# os enderecos consultados ficam visiveis para terceiros.
USANDO_API_PUBLICA = "mempool.space" in API_BASE

# Conta BIP84 padrao: m/84'/0'/0'. Contas adicionais sao descobertas na
# consulta de saldo e persistidas junto com o mnemonic.
CONTA_PADRAO = 0

# Dust real para saida P2WPKH:
#   valor minimo economico = 3000 sat/kvB * (tamanho_spk + 67) / 1000
#   spk P2WPKH = 22 bytes  ->  3000 * (22 + 67) / 1000 = 267 sats
#   arredondado para 294 (margem segura). A formula do comentario antigo
#   (3 * (31 + 141) / 1000 * 3) estava errada; a constante estava certa.
DUST_TROCO_P2WPKH = 294
# Limite conservador para AVISAR sobre valor minimo do destino
# (cobre P2PKH, que tem o maior dust da rede: 546 sats).
DUST_DESTINO_AVISO = 546

# Sinaliza RBF (BIP125): permite substituir a transacao por taxa maior.
# ATENCAO: este programa NAO implementa bumpfee/substituicao; o sinal
# apenas permite que outra ferramenta (ou o proprio destinatario) faca isso.
SEQUENCE_RBF = 0xFFFFFFFD

# Salvaguardas de taxa: avisa se a taxa passar de FRACAO_MAX_TAXA do valor
# OU de TAXA_MINIMA_ABSOLUTA sats (o "OU" e proposital: sem ele, envios
# pequenos com taxa de centenas de % passariam sem aviso).
TAXA_MAX_PERSONALIZADA = 1000.0  # sat/vB - acima disso, confirmacao extra
FRACAO_MAX_TAXA = 0.10  # 10% do valor enviado
TAXA_MINIMA_ABSOLUTA = 10_000  # sats - piso do aviso de taxa alta

SATOSHIS_POR_BTC = 100_000_000
MAX_MONEY_SATS = 2_100_000 * SATOSHIS_POR_BTC

# Sequencia exata de contas/paths usada ao montar o PSBT.
HARDENED = 0x80000000


class ArquivoCorrompido(Exception):
  """wallets.json ilegivel (JSON invalido ou chaves ausentes)."""


def erro(mensagem):
  print(f"\nERRO: {mensagem}")


def limpar_tela():
  os.system("clear" if os.name == "posix" else "cls")


# ==========================================================
# CRIPTOGRAFIA E ARMAZENAMENTO SEGURO
# ==========================================================


def ripemd160(data: bytes) -> bytes:
  h = RIPEMD160.new()
  h.update(data)
  return h.digest()


def gerar_chave_fernet(master_password: str, salt: bytes, kdf=None) -> bytes:
  """Deriva a chave Fernet a partir da Senha Mestra.

  kdf=None usa o padrao atual (Argon2id). Para abrir arquivos antigos,
  informe kdf="pbkdf2-sha256" (formato legado).
  """
  if kdf == KDF_LEGADO:
    derivador = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=ITERACOES_PBKDF2,
    )
    chave = derivador.derive(master_password.encode())
  else:
    derivador = Argon2id(
        salt=salt,
        length=32,
        iterations=ARGON2_ITERACOES,
        lanes=ARGON2_LANES,
        memory_cost=ARGON2_MEMORIA_KIB,
    )
    chave = derivador.derive(master_password.encode())
  return base64.urlsafe_b64encode(chave)


def _escrever_json_atomico(caminho: str, dados: dict):
  """Grava JSON de forma atomica, com fsync e permissao 0600.

  Evita destruir o banco de carteiras se o processo for interrompido
  no meio da escrita (o darkwallet original abria direto com 'w').
  """
  diretorio = os.path.dirname(os.path.abspath(caminho))
  tmp = tempfile.NamedTemporaryFile(
      "w", dir=diretorio, prefix=".tmp_wallets_", delete=False
  )
  try:
    with tmp as f:
      json.dump(dados, f, indent=4)
      f.flush()
      os.fsync(f.fileno())
    os.chmod(tmp.name, 0o600)
    os.replace(tmp.name, caminho)
    _fsync_diretorio(diretorio)
  except BaseException:
    try:
      os.unlink(tmp.name)
    except OSError:
      pass
    raise


def _fsync_diretorio(diretorio: str):
  """Sincroniza o diretorio para o rename sobreviver a queda de energia."""
  try:
    fd = os.open(diretorio, os.O_RDONLY)
  except OSError:
    return
  try:
    os.fsync(fd)
  except OSError:
    pass
  finally:
    os.close(fd)


def _corrigir_permissoes():
  """Garante que wallets.json nao seja legivel por outros usuarios."""
  try:
    modo = os.stat(ARQUIVO_CARTEIRAS).st_mode
    if modo & 0o077:
      os.chmod(ARQUIVO_CARTEIRAS, 0o600)
      print(
          "Aviso: permissao do wallets.json era aberta; corrigida para 600."
      )
  except OSError:
    pass


def carregar_dados_criptografados(master_password: str):
  """Retorna os dados, None se a senha estiver errada.

  Levanta ArquivoCorrompido se o arquivo estiver ilegivel.
  """
  if not os.path.exists(ARQUIVO_CARTEIRAS):
    return {}
  try:
    with open(ARQUIVO_CARTEIRAS, "r") as f:
      conteudo = json.load(f)
  except (OSError, json.JSONDecodeError) as e:
    raise ArquivoCorrompido(
        f"nao foi possivel ler {ARQUIVO_CARTEIRAS}: {e}"
    )

  if not isinstance(conteudo, dict) or not all(
      k in conteudo for k in ("salt", "encrypted_data")
  ):
    raise ArquivoCorrompido(
        f"{ARQUIVO_CARTEIRAS} nao tem a estrutura esperada."
    )

  try:
    salt = base64.b64decode(conteudo["salt"], validate=True)
    kdf = conteudo.get("kdf", KDF_LEGADO)
    chave = gerar_chave_fernet(master_password, salt, kdf=kdf)
    fernet = Fernet(chave)
    dados_decriptados = fernet.decrypt(
        conteudo["encrypted_data"].encode()
    ).decode()
    return json.loads(dados_decriptados)
  except InvalidToken:
    return None
  except (ValueError, json.JSONDecodeError, UnicodeDecodeError) as e:
    # base64 invalido, salt curto demais, JSON interno quebrado: trata
    # VARCHAR como corrupcao (senha errada continua sendo None acima).
    raise ArquivoCorrompido(f"conteudo ilegivel: {e}")

  finally:
    _corrigir_permissoes()


def conteudo_fernet_malformado(caminho: str = None) -> bool:
  """True se 'encrypted_data' nem tem a cara de um token Fernet.

  Um token Fernet valido sempre comeca com a versao 0x80 (base64 "gA...").
  Se nem isso confere, a senha nunca poderia dar certo: o arquivo esta
  adulterado/truncado. Isso permite distinguir "senha errada" de
  "corrupcao" num fast-path barato, sem rodar o KDF (Argon2id/PBKDF2).
  """
  if caminho is None:
    caminho = ARQUIVO_CARTEIRAS
  try:
    with open(caminho, "r") as f:
      conteudo = json.load(f)
    token = conteudo["encrypted_data"]
    if not isinstance(token, str):
      return True
    return not token.startswith("gA")
  except (OSError, ValueError, TypeError, KeyError):
    return False


def salvar_dados_criptografados(dados: dict, master_password: str):
  """Recriptografa tudo com o MESMO salt e grava de forma atomica.

  Sempre grava no formato atual (Argon2id). Se o arquivo existente estava
  no formato legado (PBKDF2), ele e migrado automaticamente na proxima
  gravacao (o salt e reaproveitado).
  """
  if os.path.exists(ARQUIVO_CARTEIRAS):
    try:
      with open(ARQUIVO_CARTEIRAS, "r") as f:
        conteudo = json.load(f)
      salt = base64.b64decode(conteudo["salt"], validate=True)
    except (OSError, ValueError, KeyError, json.JSONDecodeError) as e:
      raise ArquivoCorrompido(
          f"nao foi possivel reaproveitar o salt: {e}"
      )
  else:
    salt = os.urandom(TAMANHO_SALT)

  chave = gerar_chave_fernet(master_password, salt)
  fernet = Fernet(chave)
  dados_criptografados = fernet.encrypt(
      json.dumps(dados).encode()
  ).decode()
  payload = {
      "kdf": KDF_ATUAL,
      "salt": base64.b64encode(salt).decode(),
      "encrypted_data": dados_criptografados,
  }
  _escrever_json_atomico(ARQUIVO_CARTEIRAS, payload)


def _senha_fraca(senha: str) -> bool:
  """Heuristica simples de senha fraca (avisar, nao impedir).

  Considera fraca se tiver menos de 16 caracteres E pouca variedade de
  classes (minusculas/maiusculas/digitos/simbolos) OU se for um padrao
  muito comum. Nao e um medidor de entropia serio, apenas um alerta.
  """
  comuns = {
      "password", "123456789012", "senha123456", "qwertyuiop12",
      "administrador", "minhasenha123", "bitcoinbitcoin",
  }
  if senha.lower() in comuns:
    return True
  classes = sum(
      bool(re.search(padrao, senha))
      for padrao in (r"[a-z]", r"[A-Z]", r"[0-9]", r"[^a-zA-Z0-9]")
  )
  return len(senha) < 16 and classes < 3


def obter_dados_e_autenticar():
  """Cria/desbloqueia o banco de dados com a senha mestra.

  Retorna (dados, senha_mestra). Levanta ArquivoCorrompido.
  """
  if not os.path.exists(ARQUIVO_CARTEIRAS):
    print("\n--- CRIAR SENHA MESTRA ---")
    print(
        f"Defina uma Senha Mestra (minimo {MIN_TAMANHO_SENHA} caracteres)"
        "\npara proteger as carteiras salvas neste computador."
    )
    while True:
      pwd1 = getpass.getpass("Digite a nova Senha Mestra: ")
      pwd2 = getpass.getpass("Confirme a Senha Mestra: ")
      if pwd1 != pwd2:
        print("As senhas nao coincidem. Tente novamente.\n")
        continue
      if len(pwd1) < MIN_TAMANHO_SENHA:
        print(
            f"A Senha Mestra precisa de pelo menos "
            f"{MIN_TAMANHO_SENHA} caracteres.\n"
        )
        continue
      if _senha_fraca(pwd1):
        print(
            "Aviso: essa senha parece fraca (curta em variedade ou muito"
            "\nobvia). Contra forca bruta offline, prefira uma frase longa"
            "\n(ex.: 4+ palavras aleatorias) ou use um gerador de senhas."
        )
        conf = input(
            'Digite "CONFIRMAR" para usar assim mesmo: '
        ).strip().upper()
        if conf != "CONFIRMAR":
          print("Tente escolher outra senha.\n")
          continue
      return {}, pwd1
  else:
    # Se o token Fernet estiver malformado, nenhuma senha funcionara:
    # aborta cedo em vez de enganar o usuario para sempre.
    if conteudo_fernet_malformado():
      raise ArquivoCorrompido(
          "o campo 'encrypted_data' nao contem um token Fernet valido"
      )
    while True:
      pwd = getpass.getpass(
          "\nDigite sua Senha Mestra para desbloquear o banco de dados: "
      )
      dados = carregar_dados_criptografados(pwd)
      if dados is not None:
        _avisar_migracao_legado()
        return dados, pwd
      print("Senha Mestra incorreta! Tente novamente.")


def _kdf_do_arquivo(caminho: str = None) -> str:
  """Le o campo 'kdf' do arquivo; ausente => formato legado (PBKDF2)."""
  if caminho is None:
    caminho = ARQUIVO_CARTEIRAS
  try:
    with open(caminho, "r") as f:
      conteudo = json.load(f)
    return conteudo.get("kdf", KDF_LEGADO)
  except (OSError, ValueError, json.JSONDecodeError):
    return KDF_LEGADO


def _avisar_migracao_legado():
  """Informa que o arquivo sera migrado de PBKDF2 para Argon2id ao salvar."""
  if _kdf_do_arquivo() == KDF_LEGADO:
    print(
        "\nNOTA: este arquivo usa o formato antigo (PBKDF2). Ele sera"
        "\nmigrado automaticamente para Argon2id na proxima gravacao."
    )


# ==========================================================
# DERIVACAO BIP32 / BIP84 (IMPLEMENTACAO PROPRIA)
# ==========================================================


def hmac_sha512(key: bytes, data: bytes) -> bytes:
  return hmac.new(key, data, hashlib.sha512).digest()


def pub_compressed_de_priv(priv_bytes: bytes) -> bytes:
  sk = ecdsa.SigningKey.from_string(priv_bytes, curve=ecdsa.SECP256k1)
  vk = sk.get_verifying_key()
  prefix = b"\x02" if vk.pubkey.point.y() % 2 == 0 else b"\x03"
  return prefix + vk.pubkey.point.x().to_bytes(32, byteorder="big")


def ckd_priv(parent_priv: bytes, parent_chain: bytes, index: int):
  is_hardened = index >= 0x80000000
  if is_hardened:
    data = b"\x00" + parent_priv + index.to_bytes(4, byteorder="big")
  else:
    data = pub_compressed_de_priv(parent_priv) + index.to_bytes(
        4, byteorder="big"
    )

  h = hmac_sha512(parent_chain, data)
  il, ir = h[0:32], h[32:64]
  il_int = int.from_bytes(il, byteorder="big")
  order = ecdsa.SECP256k1.order

  if il_int >= order:
    raise ValueError("Derivacao invalida (il >= order)")

  child_priv_int = (il_int + int.from_bytes(parent_priv, "big")) % order
  if child_priv_int == 0:
    raise ValueError("Derivacao invalida (child_priv == 0)")

  return child_priv_int.to_bytes(32, byteorder="big"), ir


def priv_to_wif(priv_bytes: bytes) -> str:
  payload = b"\x80" + priv_bytes + b"\x01"  # 0x01 = chave comprimida
  checksum = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
  return base58.b58encode(payload + checksum).decode("utf-8")


def priv_to_bech32_address(priv_bytes: bytes) -> str:
  pubkey_hash = ripemd160(hashlib.sha256(pub_compressed_de_priv(priv_bytes)).digest())
  data = bech32.convertbits(list(pubkey_hash), 8, 5)
  return bech32.bech32_encode("bc", [0] + data)


def derivar_carteira_bip84(mnemonic: str, passphrase: str):
  """Retorna dict com fingerprint da raiz e as cadeias da conta indicada.

  Caminhos: externa m/84'/0'/conta'/0/i e interna m/84'/0'/conta'/1/i.
  """
  mnemo = Mnemonic("english")
  seed_bytes = mnemo.to_seed(mnemonic, passphrase=passphrase)

  # Raiz BIP32 + fingerprint (primeiros 4 bytes do HASH160 da pubkey raiz)
  h = hmac_sha512(b"Bitcoin seed", seed_bytes)
  priv, chain = h[0:32], h[32:64]
  root_pub = pub_compressed_de_priv(priv)
  fingerprint = ripemd160(hashlib.sha256(root_pub).digest())[:4]

  # Conta m / 84' / 0' / conta'
  for indice in (84, 0, CONTA_PADRAO):
    priv, chain = ckd_priv(priv, chain, indice + HARDENED)

  ext_priv, ext_chain = ckd_priv(priv, chain, 0)  # .../0 (receber)
  int_priv, int_chain = ckd_priv(priv, chain, 1)  # .../1 (troco)

  return {
      "fingerprint": fingerprint,
      "ext": derivar_lista_enderecos(ext_priv, ext_chain),
      "int": derivar_lista_enderecos(int_priv, int_chain),
  }


def derivar_lista_enderecos(chain_priv: bytes, chain_code: bytes, qtd=None):
  lista = []
  for i in range(qtd or QTD_ENDERECOS):
    addr_priv, _ = ckd_priv(chain_priv, chain_code, i)
    lista.append(
        {
            "index": i,
            "publico": priv_to_bech32_address(addr_priv),
            "privado": priv_to_wif(addr_priv),
        }
    )
  return lista


def enderecos_da_conta(mnemonic, passphrase, conta):
  """Deriva as listas ext/int de uma conta especifica (m/84'/0'/conta')."""
  mnemo = Mnemonic("english")
  h = hmac_sha512(
      b"Bitcoin seed", mnemo.to_seed(mnemonic, passphrase=passphrase)
  )
  priv, chain = h[0:32], h[32:64]
  for indice in (84, 0, conta):
    priv, chain = ckd_priv(priv, chain, indice + HARDENED)
  ext_priv, ext_chain = ckd_priv(priv, chain, 0)
  int_priv, int_chain = ckd_priv(priv, chain, 1)
  return derivar_lista_enderecos(ext_priv, ext_chain), derivar_lista_enderecos(
      int_priv, int_chain
  )


# ==========================================================
# QR CODE E CONSULTA DE SALDO
# ==========================================================


def exibir_qr_code(dados_texto):
  qr = qrcode.QRCode(border=2)
  qr.add_data(dados_texto)
  qr.make(fit=True)
  print("\n--- QR CODE ---")
  qr.print_ascii(invert=True)
  print("---------------")


def consultar_saldo_endereco(address):
  """Consulta a API (mempool.space por padrao) para o endereco."""
  print(f"\nConsultando saldo de:\n{address}\n")
  dados = _consultar_endereco(address)
  if dados is None:
    return
  if dados == "vazio":
    erro("a API retornou uma resposta inesperada.")
    return
  confirmado, nao_confirmado, total_tx = dados
  print("--- STATUS DO ENDERECO ---")
  print(f"Saldo confirmado   : {confirmado:.8f} BTC")
  print(f"Nao confirmado     : {nao_confirmado:.8f} BTC")
  print(f"Total de transacoes: {total_tx}")
  print("--------------------------")


def _consultar_endereco(address):
  """Retorna (btc_confirmado, btc_nao_confirmado, tx_count).

  Retorna None em falha de rede e a string "vazio" se a resposta nao
  tiver o formato esperado.
  """
  url = f"{API_BASE}/address/{address}"
  try:
    response = requests.get(url, timeout=REQUEST_TIMEOUT)
    response.raise_for_status()
    data = response.json()
    chain = data["chain_stats"]
    mempool = data["mempool_stats"]
    confirmado = (
        chain["funded_txo_sum"] - chain["spent_txo_sum"]
    ) / SATOSHIS_POR_BTC
    nao_confirmado = (
        mempool["funded_txo_sum"] - mempool["spent_txo_sum"]
    ) / SATOSHIS_POR_BTC
    total_tx = chain["tx_count"] + mempool["tx_count"]
    return confirmado, nao_confirmado, total_tx
  except (requests.RequestException, ValueError) as e:
    erro(f"falha ao consultar a API: {e}")
    return None
  except (KeyError, TypeError):
    return "vazio"


def wif_para_endereco_p2wpkh(wif):
  """Converte uma WIF no endereco P2WPKH correspondente (ou None)."""
  try:
    chave = ec.PrivateKey.from_wif(wif)
    return script.p2wpkh(chave.get_public_key()).address()
  except Exception:
    return None


# ==========================================================
# ESTIMATIVA DE TAXA E TAMANHO (P2WPKH)
# ==========================================================


def output_vbytes(script_pubkey):
  script_length = len(script_pubkey.data)
  if script_length < 253:
    prefix_length = 1
  elif script_length <= 0xFFFF:
    prefix_length = 3
  elif script_length <= 0xFFFFFFFF:
    prefix_length = 5
  else:
    prefix_length = 9
  return 8 + prefix_length + script_length


def estimar_vsize(input_count, output_scripts):
  # 68 vB por entrada P2WPKH; 10.5 vB de base (conservador, inclui
  # marker/flag do segwit).
  return math.ceil(
      10.5 + 68 * input_count + sum(
          output_vbytes(s) for s in output_scripts
      )
  )


def estimar_taxa(input_count, output_scripts, fee_rate):
  vsize = estimar_vsize(input_count, output_scripts)
  return math.ceil(vsize * fee_rate), vsize


def escolher_taxa():
  """Consulta as taxas recomendadas e retorna a escolhida em sat/vB.

  Mostra a taxa atualmente em uso (a que sera aplicada) e a estimativa
  de custo; retorna None se o usuario cancelar.
  """
  print("\nConsultando a taxa atual na rede (mempool). Aguarde...")
  url = f"{API_BASE}/v1/fees/recommended"
  try:
    response = requests.get(url, timeout=REQUEST_TIMEOUT)
    response.raise_for_status()
    fees = response.json()
  except (requests.RequestException, ValueError) as e:
    erro(f"nao foi possivel consultar as taxas: {e}")
    return None

  campos = [
      "fastestFee", "halfHourFee", "hourFee", "economyFee", "minimumFee",
  ]
  for campo in campos:
    valor = fees.get(campo)
    if (
        not isinstance(valor, (int, float))
        or isinstance(valor, bool)
        or not math.isfinite(valor)
        or valor <= 0
    ):
      erro(f"taxa invalida recebida da API: {campo}")
      return None

  minimum = float(fees["minimumFee"])
  opcoes = [
      ("1", "Rapida (proximo bloco, ~10 min)", "fastestFee"),
      ("2", "Media rapida (~30 min)", "halfHourFee"),
      ("3", "Normal (~1 hora)", "hourFee"),
      ("4", "Economica (sem pressa)", "economyFee"),
  ]

  print("\n--- TAXA DE REDE (mempool.space) ---")
  for numero, rotulo, campo in opcoes:
    taxa = max(float(fees[campo]), minimum)
    print(f"{numero}. {rotulo}: {taxa:g} sat/vB")
  print(f"5. Usar a taxa personalizada que eu digitar")
  print(f"   (minima aceita pela rede: {minimum:g} sat/vB)")

  escolha = input(
      "\nQual taxa usar? (1-5, Enter = 3 Normal): "
  ).strip() or "3"

  if escolha in ("1", "2", "3", "4"):
    campo = next(o[2] for o in opcoes if o[0] == escolha)
    taxa = max(float(fees[campo]), minimum)
    rotulo = next(o[1] for o in opcoes if o[0] == escolha)
  elif escolha == "5":
    bruto = input("Digite a taxa em sat/vB: ").strip().replace(",", ".")
    try:
      taxa = float(bruto)
    except ValueError:
      erro("a taxa informada nao e um numero valido.")
      return None
    if not math.isfinite(taxa) or taxa < minimum:
      erro(f"informe uma taxa igual ou superior a {minimum:g} sat/vB.")
      return None
    if taxa > TAXA_MAX_PERSONALIZADA:
      print(
          f"\nATENCAO: {taxa:g} sat/vB e uma taxa absurdamente alta."
      )
      conf = input('Digite "CONFIRMAR" para aceitar: ').strip().upper()
      if conf != "CONFIRMAR":
        print("Operacao cancelada.")
        return None
    rotulo = "personalizada"
  else:
    erro("opcao de taxa invalida.")
    return None

  print(f"\n>> Taxa em uso: {taxa:g} sat/vB ({rotulo}).")
  return taxa


# ==========================================================
# UTXOS
# ==========================================================


def obter_utxos(address, incluir_nao_confirmados=False):
  """Retorna lista de UTXOs validos ({txid, vout, value}) ou None."""
  url = f"{API_BASE}/address/{address}/utxo"
  try:
    response = requests.get(url, timeout=REQUEST_TIMEOUT)
    response.raise_for_status()
    utxos_raw = response.json()
  except (requests.RequestException, ValueError) as e:
    erro(f"nao foi possivel consultar os UTXOs: {e}")
    return None

  if not isinstance(utxos_raw, list):
    erro("a API retornou uma resposta inesperada.")
    return None

  utxos = []
  for item in utxos_raw:
    if not isinstance(item, dict):
      erro("a API retornou dados de UTXO invalidos.")
      return None
    if not incluir_nao_confirmados:
      status = item.get("status")
      if not (isinstance(status, dict) and status.get("confirmed")):
        continue
    try:
      txid = bytes.fromhex(item["txid"])
      vout = int(item["vout"])
      value = int(item["value"])
    except (KeyError, TypeError, ValueError):
      erro("foi encontrado um UTXO com dados invalidos.")
      return None
    if len(txid) != 32 or vout < 0 or value <= 0:
      erro("foi encontrado um UTXO com valores invalidos.")
      return None
    utxos.append({"txid": txid, "vout": vout, "value": value})

  if not incluir_nao_confirmados:
    ignorados = len(utxos_raw) - len(utxos)
    if ignorados:
      print(
          f"Aviso: {ignorados} UTXO(s) nao confirmado(s) foram ignorados."
      )

  utxos.sort(key=lambda u: u["value"], reverse=True)
  return utxos


# ==========================================================
# UTILITARIOS DE ENTRADA
# ==========================================================


def eh_endereco_mainnet(endereco):
  endereco = endereco.strip()
  return (
      endereco.lower().startswith("bc1")
      or endereco.startswith("1")
      or endereco.startswith("3")
  )


def pedir_indice(rotulo, padrao=None, maximo=QTD_ENDERECOS - 1):
  """Le um indice inteiro [0, maximo]. Retorna padrao se vazio, None se erro."""
  bruto = input(rotulo).strip()
  if bruto == "" and padrao is not None:
    return padrao
  try:
    valor = int(bruto)
  except ValueError:
    return None
  if 0 <= valor <= maximo:
    return valor
  return None


def salvar_conteudo_em_arquivo(nome_padrao, conteudo, descricao):
  caminho = input(
      f"Arquivo para salvar {descricao} (Enter = {nome_padrao}): "
  ).strip()
  caminho = caminho or nome_padrao
  try:
    with open(caminho, "w") as f:
      f.write(conteudo)
      f.flush()
      os.fsync(f.fileno())
    print(f"Salvo em: {caminho}")
  except OSError as e:
    erro(f"nao foi possivel salvar: {e}")


# ==========================================================
# CRIACAO DE TRANSACAO P2WPKH
# ==========================================================


def montar_entradas(naturezas, valor, taxa_vb, spk_destino):
  """Seleciona UTXOs (maior primeiro) ate cobrir valor + taxa (destino+troco).

  naturezas: lista de grupos {"natureza", "scriptPubKey", "utxos", "meta"}.
  Retorna (entradas, total). Cada entrada carrega o proprio scriptPubKey
  e a meta (conta/cadeia/indice/fingerprint) da origem, o que permite
  gastar varios enderecos numa mesma transacao.
  """
  todas = []
  for grupo in naturezas:
    for u in grupo["utxos"]:
      todas.append(
          {
              "txid": u["txid"],
              "vout": u["vout"],
              "value": u["value"],
              "scriptPubKey": grupo["scriptPubKey"],
              "natureza": grupo["meta"]["natureza"],
              "conta": grupo["meta"]["conta"],
              "index": grupo["meta"]["index"],
              "fingerprint": grupo["meta"]["fingerprint"],
          }
      )
  todas.sort(key=lambda u: u["value"], reverse=True)

  entradas = []
  total = 0
  # Troco ainda nao definido: dimensiona com o script de destino + um
  # script P2WPKH de mesmo tamanho, para nao subestimar a taxa.
  scripts_pior_caso = [spk_destino, script.p2wpkh(_pubkey_placeholder())]
  for utxo in todas:
    entradas.append(utxo)
    total += utxo["value"]
    taxa_com_troco, _ = estimar_taxa(
        len(entradas), scripts_pior_caso, taxa_vb
    )
    if total >= valor + taxa_com_troco + DUST_TROCO_P2WPKH:
      break
  return entradas, total


def _pubkey_placeholder():
  """Pubkey deterministica usada so para medir tamanho de script P2WPKH."""
  return ec.PrivateKey((1).to_bytes(32, "big")).get_public_key()


def _assinar_e_serializar(entradas, saidas, chaves):
  """Assina cada entrada P2WPKH com a sua chave e devolve (tx, raw_hex).

  chaves mapeia scriptPubKey.serialize() -> (PrivateKey, PublicKey).
  A conferencia de que a chave corresponde ao script e feita pelo
  chamador (antes de chegar aqui).
  """
  entradas_tx = [
      transaction.TransactionInput(
          txid=item["txid"], vout=item["vout"], sequence=SEQUENCE_RBF
      )
      for item in entradas
  ]
  tx = transaction.Transaction(vin=entradas_tx, vout=saidas)
  for i, item in enumerate(entradas):
    chave, pub_key = chaves[item["scriptPubKey"].serialize()]
    spk_code = script.p2pkh_from_p2wpkh(item["scriptPubKey"])
    sighash = tx.sighash_segwit(
        i, spk_code, item["value"], sighash=transaction.SIGHASH.ALL
    )
    entradas_tx[i].witness = script.witness_p2wpkh(
        chave.sign(sighash), pub_key
    )
  return tx, tx.serialize().hex()


def _fingerprint_hex(carteira):
  """Fingerprint da raiz em hex (JSON-friendly)."""
  fp = carteira["fingerprint"]
  return fp.hex() if isinstance(fp, (bytes, bytearray)) else fp


def _caminho_psbt_entrada(chave_meta):
  """DerivationPath BIP84 (ext/int, conta, indice) para o PSBT."""
  cadeia = 0 if chave_meta["natureza"] == "ext" else 1
  fp = chave_meta["fingerprint"]
  if isinstance(fp, str):
    fp = bytes.fromhex(fp)
  return psbt.DerivationPath(
      fp,
      [
          84 + HARDENED, 0 + HARDENED, chave_meta["conta"] + HARDENED,
          cadeia, chave_meta["index"],
      ],
  )


def _meta_de_entrada(item):
  """Normaliza as metas de uma entrada para as chaves do PSBT."""
  return {
      "natureza": item["natureza"],
      "conta": item["conta"],
      "index": item["index"],
      "fingerprint": item["fingerprint"],
  }


def _marcar_troco_no_psbt(p, saidas, endereco_troco, origens):
  """Se a saida de troco for nossa, adiciona PSBT_OUT_BIP32_DERIVATION.

  Ajuda a outra carteira a reconhecer o troco automaticamente.
  """
  alvo = None
  for origem in origens:
    if origem["meta"]["endereco"] == endereco_troco:
      alvo = origem["meta"]
      break
  if alvo is None:
    return
  for indice, saida in enumerate(saidas):
    if saida.script_pubkey.address().lower() != endereco_troco.lower():
      continue
    wif = alvo.get("wif")
    if not wif:
      return
    try:
      pub = ec.PrivateKey.from_wif(wif).get_public_key()
    except Exception:
      return
    p.outputs[indice].bip32_derivations[pub] = _caminho_psbt_entrada(alvo)


def resolver_origem(carteira, opcao, enderecos_conhecidos):
  """Resolve 'conta/cadeia/indice', 'cadeia/indice' ou uma WIF.

  Retorna (meta, script_pubkey, chave). meta None se invalido.
  """
  mnemonic = carteira.get("_mnemonic")
  passphrase = carteira.get("_passphrase", "")
  fingerprint = _fingerprint_hex(carteira)

  # WIF?
  if re.fullmatch(r"[5KLc9][1-9A-HJ-NP-Za-km-z]{50,51}", opcao):
    endereco = wif_para_endereco_p2wpkh(opcao)
    if endereco is None:
      erro("WIF invalida.")
      return None, None, None
    meta = enderecos_conhecidos.get(_chave_meta_por_endereco(
        enderecos_conhecidos, endereco
    ))
    if meta is None or meta.get("endereco", "").lower() != endereco.lower():
      meta = {
          "endereco": endereco,
          "wif": opcao,
          "natureza": "ext",
          "conta": CONTA_PADRAO,
          "index": 0,
          "fingerprint": fingerprint,
      }
    chave = ec.PrivateKey.from_wif(opcao)
    return meta, script.p2wpkh(chave.get_public_key()), chave

  # conta/cadeia/indice ou cadeia/indice ou indice
  partes = opcao.split("/")
  try:
    if len(partes) == 3:
      conta, cadeia, indice = (int(p) for p in partes)
    elif len(partes) == 2:
      conta = CONTA_PADRAO
      cadeia, indice = (int(p) for p in partes)
    else:
      conta = CONTA_PADRAO
      cadeia, indice = 0, int(opcao)
  except ValueError:
    erro("origem invalida; use conta/cadeia/indice ou uma WIF.")
    return None, None, None

  if cadeia not in (0, 1) or indice < 0 or indice >= QTD_ENDERECOS:
    erro("cadeia deve ser 0/1 e indice deve estar em "
         f"[0, {QTD_ENDERECOS - 1}].")
    return None, None, None

  # Antes de derivar do seed, procura a chave no catalogo de enderecos
  # conhecidos. E ali que WIFs importadas (inclusive carteiras sem mnemonic)
  # guardam a chave privada, com o path (conta/cadeia/indice) ja registrado.
  chave_meta = f"{conta}/{cadeia}/{indice}"
  meta_catalogo = enderecos_conhecidos.get(chave_meta)
  if isinstance(meta_catalogo, dict) and meta_catalogo.get("wif"):
    endereco_meta = meta_catalogo.get("endereco")
    if endereco_meta and eh_endereco_mainnet(endereco_meta):
      try:
        chave = ec.PrivateKey.from_wif(meta_catalogo["wif"])
        spk = script.p2wpkh(chave.get_public_key())
        if spk.address().lower() == endereco_meta.lower():
          meta = {
              "endereco": endereco_meta,
              "wif": meta_catalogo["wif"],
              "natureza": meta_catalogo.get(
                  "natureza", "ext" if cadeia == 0 else "int"
              ),
              "conta": conta,
              "index": indice,
              "fingerprint": meta_catalogo.get("fingerprint", fingerprint),
          }
          return meta, spk, chave
      except Exception:
        pass

  if mnemonic:
    try:
      ext, inter = enderecos_da_conta(mnemonic, passphrase, conta)
    except Exception as e:
      erro(f"falha ao derivar a conta {conta}: {e}")
      return None, None, None
  else:
    erro("esta carteira nao tem mnemonic em memoria; use uma WIF.")
    return None, None, None

  item = (ext if cadeia == 0 else inter)[indice]
  meta = {
      "endereco": item["publico"],
      "wif": item["privado"],
      "natureza": "ext" if cadeia == 0 else "int",
      "conta": conta,
      "index": indice,
      "fingerprint": fingerprint,
  }
  chave = ec.PrivateKey.from_wif(item["privado"])
  return meta, script.p2wpkh(chave.get_public_key()), chave


def _chave_meta_por_endereco(enderecos_conhecidos, endereco):
  for chave_meta, meta in enderecos_conhecidos.items():
    if not isinstance(meta, dict):
      continue
    if meta.get("endereco", "").lower() == endereco.lower():
      return chave_meta
  return None


def resolver_origem_por_endereco(carteira, endereco, enderecos_conhecidos):
  """Dado um endereco, acha a chave privada (WIF) correspondente.

  Procura primeiro no catalogo conhecido e, se a carteira tiver mnemonic,
  deriva as contas conhecidas (e a conta padrao) para encontrar o indice
  do endereco. Retorna (meta, script_pubkey, chave) ou (None, ...).
  """
  endereco = endereco.strip()
  if not eh_endereco_mainnet(endereco):
    erro("isso nao parece ser um endereco Bitcoin da rede principal.")
    return None, None, None
  try:
    spk = script.address_to_scriptpubkey(endereco)
  except Exception as e:
    erro(f"endereco invalido: {e}")
    return None, None, None

  # 1) Ja esta no catalogo? (mais rapido e preserva conta/cadeia corretas)
  chave_meta = _chave_meta_por_endereco(enderecos_conhecidos, endereco)
  if chave_meta is not None:
    meta = enderecos_conhecidos[chave_meta]
    if meta.get("wif"):
      chave = ec.PrivateKey.from_wif(meta["wif"])
      return meta, script.p2wpkh(chave.get_public_key()), chave

  # 2) Deriva as contas conhecidas (e a padrao) para achar o indice.
  mnemonic = carteira.get("_mnemonic")
  if not mnemonic:
    erro(
        "nao encontrei a chave privada desse endereco nesta carteira.\n"
        "Importe a WIF como uma carteira (menu principal, opcao 4)."
    )
    return None, None, None

  passphrase = carteira.get("_passphrase", "")
  contas = sorted(set(metadados_contas(carteira)) | {CONTA_PADRAO})
  alvo = endereco.lower()
  for conta in contas:
    try:
      ext, inter = enderecos_da_conta(mnemonic, passphrase, conta)
    except Exception:
      continue
    for natureza, lista in (("ext", ext), ("int", inter)):
      for item in lista:
        if item["publico"].lower() != alvo:
          continue
        meta = {
            "endereco": item["publico"],
            "wif": item["privado"],
            "natureza": natureza,
            "conta": conta,
            "index": item["index"],
            "fingerprint": _fingerprint_hex(carteira),
        }
        chave = ec.PrivateKey.from_wif(item["privado"])
        return meta, spk, chave

  erro(
      "nao encontrei a chave privada desse endereco nesta carteira.\n"
      "Ele pode estar acima do indice derivado. Informe um endereco que\n"
      "faca parte desta carteira, ou importe a WIF como uma carteira\n"
      "(menu principal, opcao 4)."
  )
  return None, None, None


def metadados_contas(carteira):
  metadados = carteira.get("_metadados", {})
  contas = metadados.get("contas") or []
  return [int(c) for c in contas]


def _endereco_origem_sugerido(carteira, enderecos_conhecidos):
  """Primeiro endereco da carteira (0/0/0), para sugerir como origem."""
  chave_meta = _chave_meta_por_endereco(
      enderecos_conhecidos, "0/0/0"
  )
  if chave_meta and enderecos_conhecidos[chave_meta].get("endereco"):
    return enderecos_conhecidos[chave_meta]["endereco"]
  if enderecos_conhecidos:
    for meta in enderecos_conhecidos.values():
      if isinstance(meta, dict) and meta.get("endereco"):
        return meta["endereco"]
  ext = carteira.get("ext") or []
  if ext:
    return ext[0]["publico"]
  return None


def criar_transacao(carteira):
  """Monta e assina uma transacao P2WPKH a partir da carteira carregada.

  Fluxo simples: pergunta o endereco de ORIGEM (ou varias, separadas por
  virgula), o endereco de DESTINO, o valor e a taxa (consultada na rede).
  O troco volta para o primeiro endereco de origem.
  NAO transmite: imprime o HEX assinado e oferece exportacao em arquivo
  (.hex) e PSBT sem assinatura (.psbt).
  """
  mnemonic = carteira.get("_mnemonic")
  passphrase = carteira.get("_passphrase", "")
  metadados = carteira.get("_metadados", {})
  enderecos_conhecidos = metadados.get("enderecos", {})

  print("\n=== CRIAR TRANSACAO (P2WPKH) ===")

  # --- 1) Endereco(s) de ORIGEM ---
  sugestao = _endereco_origem_sugerido(carteira, enderecos_conhecidos)
  if sugestao:
    print(f"\nEndereco de origem sugerido (o primeiro da carteira):")
    print(f"  {sugestao}")
  print(
      "\nDe onde vai sair o dinheiro? Digite o endereco de origem"
      "\n(Enter = usar o sugerido; varios enderecos separados por virgula)."
  )
  resposta = input("Endereco de origem: ").strip()
  if not resposta:
    if not sugestao:
      erro("nenhum endereco de origem informado.")
      return
    resposta = sugestao

  origens = []
  for endereco in [e.strip() for e in resposta.split(",") if e.strip()]:
    meta, script_pubkey, chave_obj = resolver_origem_por_endereco(
        carteira, endereco, enderecos_conhecidos
    )
    if meta is None:
      return
    if any(
        o["scriptPubKey"].serialize() == script_pubkey.serialize()
        for o in origens
    ):
      print(f"  (endereco repetido ignorado: {endereco})")
      continue
    origens.append(
        {"meta": meta, "scriptPubKey": script_pubkey, "chave": chave_obj}
    )
    print(f"  + origem: {meta['endereco']}")

  if not origens:
    erro("nenhuma origem valida.")
    return

  # --- 2) Endereco de DESTINO ---
  endereco_destino = input("\nEndereco de destino: ").strip()
  if not endereco_destino:
    erro("o endereco de destino nao pode ficar vazio.")
    return
  if not eh_endereco_mainnet(endereco_destino):
    erro("o endereco de destino nao parece ser da rede principal.")
    return
  try:
    spk_destino = script.address_to_scriptpubkey(endereco_destino)
  except Exception as e:
    erro(f"endereco de destino invalido: {e}")
    return

  # --- 3) Valor ---
  bruto = input("Valor a enviar em satoshis: ").strip().replace(",", ".")
  try:
    valor = int(bruto)
  except ValueError:
    erro("o valor deve ser um numero inteiro de satoshis.")
    return
  if valor <= 0:
    erro("o valor deve ser um inteiro positivo.")
    return
  if valor > MAX_MONEY_SATS:
    erro("o valor excede o limite de dinheiro existente no Bitcoin.")
    return
  if valor < DUST_DESTINO_AVISO:
    print(
        f"\nATENCAO: {valor} sats e inferior ao dust conservador "
        f"({DUST_DESTINO_AVISO} sats). A rede pode REJEITAR a transacao e "
        "o destinatario pode nunca receber o valor."
    )
    conf = input('Digite "CONFIRMAR" para prosseguir assim: ').strip().upper()
    if conf != "CONFIRMAR":
      print("Operacao cancelada.")
      return

  # --- 4) Confere saldo das origens ---
  incluir_nc = input(
      "Incluir UTXOs ainda nao confirmados? (s/N): "
  ).strip().lower() == "s"

  naturezas = []
  for origem in origens:
    utxos = obter_utxos(
        origem["meta"]["endereco"], incluir_nao_confirmados=incluir_nc
    )
    if utxos is None:
      return
    if not utxos:
      print(f"  (sem UTXOs em {origem['meta']['endereco']})")
    naturezas.append(
        {
            "natureza": origem["meta"]["natureza"],
            "scriptPubKey": origem["scriptPubKey"],
            "utxos": utxos,
            "meta": origem["meta"],
        }
    )

  total_disponivel = sum(
      u["value"] for g in naturezas for u in g["utxos"]
  )
  if total_disponivel <= 0:
    erro(
        "nenhum UTXO encontrado nas origens informadas. "
        "Verifique se o endereco possui fundos."
    )
    return
  print(f"\nSaldo disponivel nessa origem: {total_disponivel} sats.")

  # WIF das origens (para assinar e para o PSBT).
  chaves = {}
  for origem in origens:
    meta = origem["meta"]
    wif = meta.get("wif")
    if not wif:
      erro(
          f"a origem {meta['endereco']} nao tem chave privada; "
          "nao e possivel assinar."
      )
      return
    try:
      chave = ec.PrivateKey.from_wif(wif)
      pub = chave.get_public_key()
      spk = script.p2wpkh(pub)
    except Exception as e:
      erro(f"falha ao processar a chave privada: {e}")
      return
    if spk.address().lower() != meta["endereco"].lower():
      erro("seguranca: a chave privada nao corresponde ao endereco.")
      return
    chaves[spk.serialize()] = (chave, pub)

  # --- 5) Endereco de troco: mesmo endereco da PRIMEIRA origem (padrao) ---
  endereco_troco = origens[0]["meta"]["endereco"]
  print(
      f"\nTroco voltara para o proprio endereco de origem:"
      f"\n  {endereco_troco}"
  )
  troco_informado = input(
      "Outro endereco de troco (Enter = o da origem): "
  ).strip()
  if troco_informado:
    endereco_troco = troco_informado
  if not eh_endereco_mainnet(endereco_troco):
    erro("o endereco de troco nao parece ser da rede principal.")
    return
  try:
    spk_troco = script.address_to_scriptpubkey(endereco_troco)
  except Exception as e:
    erro(f"endereco de troco invalido: {e}")
    return

  if endereco_destino == endereco_troco:
    print(
        "\nAVISO: destino igual ao endereco de troco; o troco se juntara"
        " ao valor enviado no mesmo endereco."
    )

  # --- 6) Taxa: consulta a rede e mostra a taxa em uso ---
  taxa_vb = escolher_taxa()
  if taxa_vb is None:
    return

  # --- Selecao de entradas ---
  entradas, total_entradas = montar_entradas(
      naturezas, valor, taxa_vb, spk_destino
  )

  taxa_um_output, vsize_um = estimar_taxa(
      len(entradas), [spk_destino], taxa_vb
  )
  taxa_dois_outputs, vsize_dois = estimar_taxa(
      len(entradas), [spk_destino, spk_troco], taxa_vb
  )

  if total_entradas < valor + taxa_um_output:
    erro(
        "saldo insuficiente.\n"
        f"  Entradas: {total_entradas} sats\n"
        f"  Valor:    {valor} sats\n"
        f"  Taxa:     {taxa_um_output} sats (1 output)"
    )
    return

  troco_potencial = total_entradas - valor - taxa_dois_outputs

  if troco_potencial >= DUST_TROCO_P2WPKH:
    valor_troco = troco_potencial
    taxa_calculada = taxa_dois_outputs
    vsize_final = vsize_dois
    tem_troco = True
    saidas = [
        transaction.TransactionOutput(value=valor, script_pubkey=spk_destino),
        transaction.TransactionOutput(
            value=valor_troco, script_pubkey=spk_troco
        ),
    ]
  else:
    valor_troco = 0
    taxa_calculada = total_entradas - valor
    vsize_final = vsize_um
    tem_troco = False
    if taxa_calculada < taxa_um_output:
      erro("o saldo nao cobre a taxa estimada.")
      return
    saidas = [
        transaction.TransactionOutput(value=valor, script_pubkey=spk_destino),
    ]
  taxa_efetiva = taxa_calculada / vsize_final

  # --- Salvaguarda de taxa excessiva ---
  # Dispara se passar do percentual OU do valor absoluto. Usar max()
  # deixava envios pequenos com taxa de centenas de % sem aviso.
  teto_percentual = int(valor * FRACAO_MAX_TAXA)
  if taxa_calculada > teto_percentual or taxa_calculada > TAXA_MINIMA_ABSOLUTA:
    percentual = 100 * taxa_calculada / valor
    motivos = []
    if taxa_calculada > teto_percentual:
      motivos.append(f"{percentual:.1f}% do valor enviado")
    if taxa_calculada > TAXA_MINIMA_ABSOLUTA:
      motivos.append(f"acima de {TAXA_MINIMA_ABSOLUTA} sats")
    print(
        f"\nATENCAO: a taxa ({taxa_calculada} sats) e alta "
        f"({'; '.join(motivos)})."
    )
    conf = input('Digite "TAXA ALTA" para prosseguir: ').strip().upper()
    if conf != "TAXA ALTA":
      print("Operacao cancelada.")
      return

  # --- Resumo ---
  print("\n" + "=" * 64)
  print("RESUMO DA TRANSACAO")
  print("=" * 64)
  for origem in origens:
    print(f"Origem              : {origem['meta']['endereco']}")
  print(f"Entradas utilizadas : {len(entradas)} de "
        f"{sum(len(g['utxos']) for g in naturezas)} UTXO(s)")
  print(f"Total das entradas  : {total_entradas} sats")
  print(f"Valor para destino  : {valor} sats ({endereco_destino})")
  print(f"Taxa total estimada : {taxa_calculada} sats")
  print(f"Taxa efetiva aprox. : {taxa_efetiva:.2f} sat/vB")
  print(f"Tamanho estimado    : {vsize_final} vB")
  if tem_troco:
    print(f"Valor do troco      : {valor_troco} sats ({endereco_troco})")
  else:
    print("Valor do troco      : (sem saida de troco)")
    if troco_potencial > 0:
      print(
          f"  Motivo: o troco calculado ({troco_potencial} sats) ficou abaixo"
          f"\n  do minimo de {DUST_TROCO_P2WPKH} sats (dust). Uma saida menor que"
          "\n  isso seria REJEITADA pela rede, por isso ela nao foi criada."
          "\n  Esse valor foi somado a taxa (nao se perdeu: foi para o"
          "\n  minerador). Para ter troco, envie um valor menor, de modo que"
          "\n  o troco ultrapasse o minimo."
      )
    else:
      print(
          "  Motivo: nao sobrou saldo alem do valor enviado e da taxa."
      )
  print("RBF                 : sinalizado (o programa NAO faz bumpfee;")
  print("                      use outra ferramenta se precisar)")
  print("=" * 64)

  print("\nA transacao ainda nao foi assinada nem transmitida.")
  conf = input("\nPara assinar e gerar o HEX, digite SIM: ").strip()
  if conf != "SIM":
    print("Operacao cancelada.")
    return

  # --- Montagem e assinatura (BIP143) ---
  try:
    tx, raw_hex = _assinar_e_serializar(entradas, saidas, chaves)
  except Exception as e:
    erro(f"erro ao assinar a transacao: {e}")
    return

  vsize_real = _vsize_real(raw_hex)
  taxa_real = taxa_calculada  # confirmada por construcao (soma dos inputs)
  print("\n" + "=" * 64)
  print("TRANSACAO ASSINADA - NAO TRANSMITIDA")
  print("=" * 64)
  print(f"Taxa total       : {taxa_real} sats")
  print(f"Tamanho real     : {vsize_real} vB (estimado: {vsize_final} vB)")
  print(f"Taxa efetiva real: {taxa_real / vsize_real:.2f} sat/vB")
  print("\nRAW HEX:")
  print(raw_hex)
  print("=" * 64)
  print(
      "\nA transacao NAO foi transmitida automaticamente. Confira o HEX, "
      "os valores e os enderecos antes do broadcast (ex.: mempool.space/tx/push)."
  )

  # --- Exportacao ---
  while True:
    print("\nOpcoes:")
    print("1 - Salvar HEX assinado em arquivo")
    print("2 - Salvar PSBT (sem assinatura) em arquivo")
    print("0 - Voltar")
    escolha = input("Escolha: ").strip()

    if escolha == "1":
      salvar_conteudo_em_arquivo(
          "transacao_assinada.hex", raw_hex + "\n", "o HEX assinado"
      )
    elif escolha == "2":
      try:
        tx_limpa = transaction.Transaction(
            vin=[
                transaction.TransactionInput(
                    txid=item["txid"], vout=item["vout"],
                    sequence=SEQUENCE_RBF,
                )
                for item in entradas
            ],
            vout=saidas,
        )
        p = psbt.PSBT(tx_limpa)
        for i, item in enumerate(entradas):
          chave, pub_key = chaves[item["scriptPubKey"].serialize()]
          p.inputs[i].witness_utxo = transaction.TransactionOutput(
              value=item["value"], script_pubkey=item["scriptPubKey"]
          )
          p.inputs[i].bip32_derivations[pub_key] = _caminho_psbt_entrada(
              _meta_de_entrada(item)
          )
        # Marca a saida de troco como nossa (PSBT_OUT_BIP32_DERIVATION),
        # para outra carteira reconhecer o troco automaticamente.
        _marcar_troco_no_psbt(p, saidas, endereco_troco, origens)
        psbt_b64 = base64.b64encode(p.serialize()).decode()
        salvar_conteudo_em_arquivo(
            "transacao.psbt", psbt_b64 + "\n", "o PSBT (base64)"
        )
      except Exception as e:
        erro(f"falha ao gerar o PSBT: {e}")
    elif escolha == "0":
      break


def _vsize_real(raw_hex):
  """vsize real de uma tx assinada (peso = 3*base + total)."""
  raw = bytes.fromhex(raw_hex)
  tx = transaction.Transaction.parse(raw)
  for inp in tx.vin:
    inp.witness = transaction.Witness([])
  base = len(tx.serialize())
  return -(-(base * 3 + len(raw)) // 4)


# ==========================================================
# MENU DA CARTEIRA
# ==========================================================


def menu_carteira(mnemonic, passphrase, exibir_mnemonic, metadados=None):
  mnemo = Mnemonic("english")
  if metadados is None:
    metadados = {"contas": [CONTA_PADRAO], "enderecos": {}}

  # A carteira pode carregar so o mnemonic; nesse caso valida-o.
  if mnemonic:
    if not mnemo.check(mnemonic):
      erro("o mnemonic armazenado nesta carteira e invalido.")
      return
    print("\nGerando chaves... Aguarde.")
    carteira = derivar_carteira_bip84(mnemonic, passphrase)
  else:
    # Carteira de enderecos apenas (sem mnemonic): deriva o que for
    # possivel a partir dos metadados e usa a conta padrao como vazia.
    print("\nCarteira sem mnemonic: usando os enderecos importados.")
    carteira = {
        "fingerprint": b"\x00\x00\x00\x00",
        "ext": [],
        "int": [],
    }

  carteira["_mnemonic"] = mnemonic
  carteira["_passphrase"] = passphrase
  carteira["_metadados"] = metadados

  # Garante que os enderecos ja conhecidos entrem no catalogo exibido.
  for chave_meta, meta in metadados.get("enderecos", {}).items():
    meta.setdefault("natureza", "ext")
    meta.setdefault("conta", CONTA_PADRAO)
    meta.setdefault("index", 0)
    meta.setdefault("fingerprint", _fingerprint_hex(carteira))

  if exibir_mnemonic and mnemonic:
    print(f"\nSemente (Mnemonic): {mnemonic}")
  else:
    print("\nSemente (Mnemonic): [PROTEGIDA - nao exibida ao carregar]")
  print(
      f"Passphrase: {'[CONFIGURADA]' if passphrase else '[NENHUMA]'}"
  )
  print(f"Fingerprint da raiz: {carteira['fingerprint'].hex()}")
  if USANDO_API_PUBLICA:
    print(
        "\nPRIVACIDADE: as consultas de saldo vao para mempool.space, que VE"
        "\nos enderecos consultados. Para um node proprio/Tor, use"
        "\nGELOWALLET_API."
    )
  if carteira["ext"]:
    print(f"\n--- {QTD_ENDERECOS} PRIMEIROS ENDERECOS (m/84'/0'/0'/0/i) ---")
    for item in carteira["ext"]:
      print(f"[{item['index']:02d}] {item['publico']}")
  else:
    print("\n--- ENDERECOS IMPORTADOS (sem mnemonic) ---")
    if metadados.get("enderecos"):
      for chave_meta in sorted(metadados["enderecos"]):
        print(f"  {chave_meta} -> {metadados['enderecos'][chave_meta]['endereco']}")
    else:
      print("  (nenhum endereco importado ainda)")

  while True:
    print("\nOpcoes da Carteira:")
    print("1 - Gerar QR Code do endereco publico")
    print("2 - Gerar QR Code da chave privada (WIF)  [CUIDADO]")
    print("3 - Consultar saldo e transacoes do endereco")
    print("4 - Criar transacao (enviar BTC)")
    print("5 - Exportar todas as chaves (WIF) em texto")
    print("0 - Voltar")

    esc = input("Escolha: ").strip()

    if esc == "0":
      break

    if esc in ("1", "2", "3"):
      item = escolher_endereco_conhecido(carteira)
      if item is None:
        continue
      if esc == "1":
        exibir_qr_code(item["publico"])
      elif esc == "2":
        exibir_chave_privada(item)
      else:
        consultar_saldo_endereco(item["publico"])

    elif esc == "4":
      criar_transacao(carteira)

    elif esc == "5":
      exportar_chaves(carteira)


def escolher_endereco_conhecido(carteira):
  """Deixa escolher origem (conta/cadeia) e indice; devolve o item."""
  enderecos = carteira.get("_metadados", {}).get("enderecos", {})
  print("\nEnderecos conhecidos:")
  if enderecos:
    for chave_meta in sorted(enderecos):
      print(f"  {chave_meta} -> {enderecos[chave_meta]['endereco']}")
  else:
    print("  (nenhum; usando a conta padrao derivada)")

  opcao = input(
      "Endereco (conta/cadeia/indice; Enter = o primeiro da lista): "
  ).strip()
  if not opcao and enderecos:
    opcao = sorted(enderecos)[0]
  opcao = opcao or "0/0/0"
  meta, spk, _ = resolver_origem(carteira, opcao, enderecos)
  if meta is None:
    return None
  wif = meta.get("wif")
  return {"index": meta["index"], "publico": meta["endereco"], "privado": wif}


def exibir_chave_privada(item):
  if not item.get("privado"):
    erro("esta origem nao tem chave privada (importada apenas por endereco).")
    return
  print(
      "\nATENCAO: o QR abaixo contem a CHAVE PRIVADA. Qualquer pessoa "
      "com acesso a ele rouba seus fundos. Evite telas compartilhadas "
      "e gravacoes."
  )
  input("Pressione Enter para exibir...")
  print(f"\nWIF: {item['privado']}")
  exibir_qr_code(item["privado"])


def exportar_chaves(carteira):
  print(
      "\nATENCAO: isso imprime na tela TODAS as chaves privadas desta "
      "carteira. Certifique-se de que ninguem esta observando."
  )
  conf = input('Digite "EXPORTAR" para prosseguir: ').strip().upper()
  if conf != "EXPORTAR":
    print("Exportacao cancelada.")
    return
  print("\n--- CHAVES (WIF) ---")
  for item in carteira["ext"]:
    print(f"[{item['index']:02d}] {item['publico']} | {item['privado']}")
  print("--------------------")


# ==========================================================
# FLUXOS: CRIAR / IMPORTAR / GERENCIAR
# ==========================================================


def perguntar_e_salvar_carteira(mnemonic, passphrase, metadados=None):
  resposta = input(
      "\nDeseja salvar essa carteira no sistema? (s/n): "
  ).strip().lower()
  if resposta != "s":
    return
  try:
    dados, master_password = obter_dados_e_autenticar()
    nome = input("\nDigite um nome/alias para esta carteira: ").strip()
    if not nome:
      print("Nome vazio; carteira nao salva.")
      return
    if nome in dados:
      print("Aviso: ja existe uma carteira com este nome; sera atualizada.")
    dados[nome] = {
        "mnemonic": mnemonic,
        "passphrase": passphrase,
        "metadados": metadados or {"contas": [CONTA_PADRAO], "enderecos": {}},
    }
    salvar_dados_criptografados(dados, master_password)
    print("Carteira criptografada e salva com sucesso!")
  except ArquivoCorrompido as e:
    erro(
        f"{ARQUIVO_CARTEIRAS} esta corrompido ({e}). A carteira NAO foi "
        "salva. Remova ou renomeie o arquivo para recomecar."
    )


def criar_carteira():
  limpar_tela()
  print("=== 1. CRIAR NOVA CARTEIRA ===")
  mnemo = Mnemonic("english")
  mnemonic = mnemo.generate(strength=128)
  passphrase = getpass.getpass(
      "Digite um Passphrase (ou Enter para deixar em branco, sem eco): "
  )
  metadados = {"contas": [CONTA_PADRAO], "enderecos": {}}

  criar_wallet_e_perguntar_salvar(mnemonic, passphrase, metadados)


def criar_wallet_e_perguntar_salvar(mnemonic, passphrase, metadados):
  menu_carteira(
      mnemonic, passphrase, exibir_mnemonic=True, metadados=metadados
  )
  perguntar_e_salvar_carteira(mnemonic, passphrase, metadados)
  input("\nPressione Enter para continuar...")


def importar_carteira():
  limpar_tela()
  print("=== 2. CARREGAR CARTEIRA EXISTENTE ===")
  print(
      "As palavras serao digitadas sem eco. Cole o mnemonic inteiro, com as"
      "\npalavras separadas por espaco."
  )
  mnemonic = getpass.getpass("Mnemonic (12/24 palavras): ").strip()

  mnemo = Mnemonic("english")
  if not mnemonic:
    # Sem mnemonic: carteira de enderecos avulsos (importados por WIF).
    print("\nNenhum mnemonic informado. Voce podera importar WIFs depois.")
    passphrase = ""
    metadados = {"contas": [], "enderecos": {}}
  elif not mnemo.check(mnemonic):
    print(
        "\nErro: Mnemonic invalido. Verifique se as palavras estao corretas"
        " (padrao BIP39)."
    )
    input("\nPressione Enter para voltar...")
    return
  else:
    passphrase = getpass.getpass(
        "Digite a Passphrase (ou Enter para deixar em branco, sem eco): "
    )
    metadados = {"contas": [CONTA_PADRAO], "enderecos": {}}

  criar_wallet_e_perguntar_salvar(mnemonic, passphrase, metadados)


def importar_wif_como_carteira():
  """Importa uma WIF existente e a salva como carteira no wallets.json.

  Cria uma carteira sem mnemonic, cujo unico endereco (0/0/0) e aquele
  correspondente a WIF informada. Assim a WIF fica guardada (criptografada
  pela Senha Mestra) e pode ser reaberta como qualquer outra carteira.
  """
  limpar_tela()
  print("=== 4. IMPORTAR WIF (CHAVE PRIVADA) EXISTENTE ===")
  print(
      "A chave sera digitada sem eco. Ela sera salva CRIPTOGRAFADA no"
      "\narquivo de carteiras, protegida pela sua Senha Mestra."
  )
  wif = getpass.getpass("\nDigite a WIF a importar (sem eco): ").strip()
  if not wif:
    erro("nenhuma WIF informada.")
    input("\nPressione Enter para voltar...")
    return

  endereco = wif_para_endereco_p2wpkh(wif)
  if endereco is None:
    erro("WIF invalida. Confira a chave e tente novamente.")
    input("\nPressione Enter para voltar...")
    return

  print(f"\nEndereco correspondente a esta WIF:\n  {endereco}")
  conf = input("Salvar esta WIF como uma carteira? (s/n): ").strip().lower()
  if conf != "s":
    print("Operacao cancelada.")
    input("\nPressione Enter para voltar...")
    return

  try:
    dados, master_password = obter_dados_e_autenticar()
  except ArquivoCorrompido as e:
    erro(
        f"{ARQUIVO_CARTEIRAS} esta corrompido ({e}). A WIF NAO foi salva."
        " Remova ou renomeie o arquivo para recomecar."
    )
    input("\nPressione Enter para voltar...")
    return

  nome = input("\nDigite um nome/alias para esta carteira: ").strip()
  if not nome:
    print("Nome vazio; WIF nao salva.")
    input("\nPressione Enter para voltar...")
    return
  if nome in dados:
    print("Aviso: ja existe uma carteira com este nome; sera atualizada.")

  metadados = {
      "contas": [CONTA_PADRAO],
      "enderecos": {
          "0/0/0": {
              "endereco": endereco,
              "wif": wif,
              "natureza": "ext",
              "conta": CONTA_PADRAO,
              "index": 0,
              "fingerprint": "00000000",
          }
      },
  }
  dados[nome] = {
      "mnemonic": "",
      "passphrase": "",
      "metadados": metadados,
  }
  try:
    salvar_dados_criptografados(dados, master_password)
  except ArquivoCorrompido as e:
    erro(
        f"falha ao salvar a carteira WIF ({e}). A chave NAO foi gravada."
    )
    input("\nPressione Enter para voltar...")
    return

  print(
      f"\nCarteira '{nome}' salva com a WIF importada. Abra-a pelo menu"
      "\nprincipal (opcao 3) para gerar QR, consultar saldo ou transacionar."
  )
  input("\nPressione Enter para voltar...")


def gerenciar_carteiras():
  while True:
    limpar_tela()
    print("=== 3. GERENCIAR CARTEIRAS SALVAS ===")

    if not os.path.exists(ARQUIVO_CARTEIRAS):
      print("Nenhuma carteira cadastrada.")
      input("\nPressione Enter para voltar...")
      return

    try:
      dados, master_password = obter_dados_e_autenticar()
    except ArquivoCorrompido as e:
      erro(
          f"{ARQUIVO_CARTEIRAS} esta corrompido ({e}). Remova ou renomeie "
          "o arquivo; as carteiras nele nao podem ser recuperadas por este"
          " programa."
      )
      input("\nPressione Enter para voltar...")
      return

    if not dados:
      print("Nenhuma carteira encontrada no arquivo.")
      input("\nPressione Enter para voltar...")
      return

    limpar_tela()
    print("=== CARTEIRAS DESBLOQUEADAS ===")
    nomes = list(dados.keys())
    for i, nome in enumerate(nomes):
      print(f"[{i}] - {nome}")

    print("\nOpcoes:")
    print("L - Carregar e visualizar uma carteira")
    print("D - Deletar uma carteira")
    print("0 - Voltar")

    esc = input("\nEscolha: ").strip().upper()

    if esc == "0":
      break
    if esc not in ("L", "D"):
      continue

    idx = pedir_indice(
        "Digite o numero da carteira: ", maximo=len(nomes) - 1
    )
    if idx is None:
      erro("indice invalido.")
      input("Pressione Enter...")
      continue

    nome_escolhido = nomes[idx]
    if esc == "L":
      carteira = dados[nome_escolhido]
      metadados = carteira.get("metadados")
      if metadados is None:
        metadados = {"contas": [CONTA_PADRAO], "enderecos": {}}
      try:
        menu_carteira(
            carteira.get("mnemonic", ""), carteira.get("passphrase", ""),
            exibir_mnemonic=False, metadados=metadados,
        )
      except ArquivoCorrompido as e:
        erro(f"falha ao salvar alteracoes: {e}")
        input("\nPressione Enter para continuar...")
        continue
      # Persiste os enderecos/metadados descobertos na sessao.
      if carteira.get("metadados") != metadados:
        carteira["metadados"] = metadados
        dados[nome_escolhido] = carteira
        try:
          salvar_dados_criptografados(dados, master_password)
          print("Enderecos/metadados atualizados e salvos.")
        except ArquivoCorrompido as e:
          erro(f"falha ao salvar os metadados: {e}")
      input("\nPressione Enter para continuar...")
    else:
      confirm = input(
          f"Tem certeza que deseja deletar '{nome_escolhido}'? (s/n): "
      ).strip().lower()
      if confirm != "s":
        continue
      try:
        del dados[nome_escolhido]
        salvar_dados_criptografados(dados, master_password)
        print("Carteira deletada com sucesso!")
      except ArquivoCorrompido as e:
        erro(f"falha ao salvar apos delecao: {e}")
      input("Pressione Enter...")


# ==========================================================
# PRINCIPAL
# ==========================================================


def main():
  while True:
    limpar_tela()
    print("=== GELOWALLET - Gerenciador de Enderecos e Lock Offline ===")
    print("1 - Criar nova carteira (12 palavras + Passphrase)")
    print("2 - Carregar carteira existente (12/24 palavras + Passphrase)")
    print("3 - Visualizar/Deletar/Transacionar carteiras cadastradas")
    print("4 - Importar uma WIF (chave privada) e salvar como carteira")
    print("0 - Sair")
    print("=" * 56)

    esc = input("Escolha uma opcao: ").strip()

    if esc == "1":
      criar_carteira()
    elif esc == "2":
      importar_carteira()
    elif esc == "3":
      gerenciar_carteiras()
    elif esc == "4":
      importar_wif_como_carteira()
    elif esc == "0":
      limpar_tela()
      print("Saindo...")
      break


if __name__ == "__main__":
  limpar_tela()
  print("=" * 56)
  print("  GELOWALLET = Gerenciador de Enderecos e Lock Offline")
  print("  Carteira Bitcoin BIP84 (P2WPKH)")
  print("=" * 56)
  try:
    main()
  except KeyboardInterrupt:
    print("\n\nInterrompido pelo usuario. Saindo...")
    sys.exit(130)
