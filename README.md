# GELOWALLET = Gerenciador de Endereços e Lock Offline

Carteira Bitcoin **BIP84 (P2WPKH)** de terminal, focada em gerar, guardar e assinar chaves
**offline** — e em montar transações que você transmite manualmente, quando quiser.

> **Aviso:** use por sua conta e risco. Este programa **não transmite transações**:
> o HEX/PSBT gerado deve ser transmitido manualmente (ex.: `mempool.space/tx/push`
> ou um node próprio). Leia a seção de segurança antes
> de usar com fundos reais.

---

## Índice

- [O que é](#o-que-é)
- [Recursos](#recursos)
- [Requisitos](#requisitos)
- [Instalação](#instalação)
- [Uso](#uso)
- [Fluxo de transação](#fluxo-de-transação)
- [Segurança](#segurança)
- [Privacidade e rede](#privacidade-e-rede)
- [Estrutura do projeto](#estrutura-do-projeto)
- [Perguntas frequentes](#perguntas-frequentes)
- [Limitações](#limitações)
- [Licença](#licença)

---

## O que é

O GELOWALLET é uma ferramenta de linha de comando que:

- **Gera** carteiras BIP84 (seed de 12 palavras + passphrase opcional);
- **Importa** carteiras existentes (mnemonic de 12/24 palavras);
- **Guarda** tudo criptografado em um único arquivo local (`wallets.json`);
- **Exibe** QR Code do endereço público e da chave privada (WIF);
- **Consulta** saldo e número de transações de um endereço;
- **Monta e assina** transações P2WPKH, exportando o HEX assinado e/ou um PSBT.

Ele foi pensado como um **cofre offline**: em vez de uma carteira online com
transmissão automática, o GELOWALLET produz a transação assinada e deixa a
decisão de transmitir para você.

---

## Recursos

### Carteira e chaves
- Derivação **BIP32 / BIP84** com caminho `m/84'/0'/conta'/cadeia/índice`
  (cadeia externa `0` = receber; cadeia interna `1` = troco).
- Seed de **12 palavras** na criação; aceita **12/24** ao importar (BIP39).
- **Passphrase** BIP39 opcional.
- Múltiplas contas (`m/84'/0'/conta'`) e múltiplos endereços por conta.
- Importação de uma **WIF avulsa** e a salvamento como carteira própria.

### Transações (P2WPKH / SegWit)
- Montagem em perguntas simples: **origem → destino → valor → taxa**.
- **Múltiplas origens** numa mesma transação (endereços separados por vírgula).
- **Taxa consultada na rede**, com o valor em uso exibido antes de assinar.
- **Troco** volta para o endereço de origem (ou outro que você informar).
- **Dust correto** para P2WPKH (294 sats): troco abaixo do mínimo vira taxa, com
  explicação do motivo na própria tela.
- **RBF** sinalizado (BIP125) — o programa não faz *bumpfee*, mas permite que
  outra ferramenta o faça.
- Salvaguardas: aviso de taxa excessiva, valor de destino abaixo do dust,
  UTXOs não confirmados ignorados por padrão.
- Exportação do **HEX assinado** (`.hex`) e do **PSBT** não assinado (`.psbt`).

### Segurança do cofre
- **Argon2id** (memory-hard, 64 MiB) para derivar a chave da Senha Mestra.
- **Migração automática** de arquivos antigos em PBKDF2 (600k iterações).
- Escrita **atômica** do arquivo (tmp + fsync + `os.replace`), com permissão `0600`.
- Senha Mestra com mínimo de **12 caracteres** e aviso de senha fraca.
- Mnemonic e WIF digitados **sem eco** (`getpass`).
- Detecção clara de arquivo corrompido × senha incorreta.

---

## Requisitos

- **Python 3.10+** (desenvolvido e testado em Python 3.14).
- Sistema com terminal (Linux/macOS; no Windows, use um terminal ANSI).

### Dependências

| Pacote (PyPI)   | Import         | Para quê                                      |
|-----------------|----------------|-----------------------------------------------|
| `embit`         | `embit`        | Assinatura, PSBT, scripts, parsing de tx      |
| `mnemonic`      | `mnemonic`     | BIP39 (seed, validação)                        |
| `qrcode`        | `qrcode`       | QR Code em ASCII                               |
| `base58`        | `base58`       | WIF                                            |
| `bech32`        | `bech32`       | Endereços SegWit (`bc1q...`)                   |
| `ecdsa`         | `ecdsa`        | Derivação de chaves (SECP256k1)                |
| `requests`      | `requests`     | Consultas à API (saldo, UTXOs, taxa)           |
| `cryptography`  | `cryptography` | Fernet + Argon2id + PBKDF2                     |
| `pycryptodome`  | `Crypto`       | RIPEMD160                                      |

---

## Instalação

```bash
# 1. (opcional) ambiente virtual
python3 -m venv .venv
source .venv/bin/activate        # Linux/macOS
# .venv\Scripts\activate         # Windows

# 2. dependências
pip install embit mnemonic qrcode base58 bech32 ecdsa requests cryptography pycryptodome
```

> Dica: você pode congelar isso num `requirements.txt`:
> ```bash
> pip freeze > requirements.txt
> ```
> e instalar depois com `pip install -r requirements.txt`.

---

## Uso

```bash
python3 gelowallet.py
```

Menu principal:

```
=== GELOWALLET - Gerenciador de Enderecos e Lock Offline ===
1 - Criar nova carteira (12 palavras + Passphrase)
2 - Carregar carteira existente (12/24 palavras + Passphrase)
3 - Visualizar/Deletar/Transacionar carteiras cadastradas
4 - Importar uma WIF (chave privada) e salvar como carteira
0 - Sair
```

Menu da carteira (após carregar):

```
Opcoes da Carteira:
1 - Gerar QR Code do endereco publico
2 - Gerar QR Code da chave privada (WIF)  [CUIDADO]
3 - Consultar saldo e transacoes do endereco
4 - Criar transacao (enviar BTC)
5 - Exportar todas as chaves (WIF) em texto
0 - Voltar
```

### Fluxo rápido

1. **Criar** (opção 1): o programa mostra a seed de 12 palavras. **Anote-a em papel.**
   Defina um passphrase (pode ficar em branco). Exiba o QR do endereço público e
   receba BTC nele.
2. **Guardar**: responda `s` para salvar a carteira — você define um nome e a
   Senha Mestra.
3. **Reabrir** (opção 3): digite a Senha Mestra, escolha a carteira.
4. **Enviar** (opção 4): informe origem, destino, valor e a taxa.
5. **Transmitir**: copie o HEX gerado e transmita manualmente.

---

## Fluxo de transação

```
Origem              : bc1q...
Entradas utilizadas : 1 de 1 UTXO(s)
Total das entradas  : 10686 sats
Valor para destino  : 10000 sats (bc1q...)
Taxa total estimada : 141 sats
Taxa efetiva aprox. : 1.00 sat/vB
Tamanho estimado    : 141 vB
Valor do troco      : 545 sats (bc1q...)      <- endereço de origem
RBF                 : sinalizado (o programa NAO faz bumpfee)
```

### A taxa que você escolhe vs. a taxa efetiva

A taxa escolhida (em **sat/vB**) dimensiona o **tamanho** da transação. Se o troco
calculado ficar **abaixo do dust** (294 sats para P2WPKH), a saída de troco não é
criada — porque a rede pode **rejeitar** (ou tornar inútil gastar) uma saída daquele
tamanho — e esse valor é somado à taxa. Foi para isso que a **taxa efetiva** sobe.

Exemplo real:

| | Taxa alvo 3 sat/vB | Taxa alvo 1 sat/vB |
|---|---|---|
| Taxa com 2 saídas (141 vB) | 423 sats | 141 sats |
| Troco potencial | 10686 − 10000 − 423 = **263** ❌ | 10686 − 10000 − 141 = **545** ✅ |
| Dust mínimo | 294 | 294 |
| Resultado | sem troco (263 < 294) | troco de 545 sats |

Quando o troco cai abaixo do dust, o programa explica isso na tela, com os
números do seu caso. Para **ter troco**, envie um valor menor, de modo que o
troco ultrapasse o mínimo.

> O valor `294` **não é configurável**: é uma regra da rede Bitcoin. Baixá-lo não
> daria troco — apenas criaria transações rejeitadas.

---

## Segurança

- **`wallets.json`** guarda tudo criptografado (Fernet) com chave derivada por
  **Argon2id** da sua Senha Mestra. Permissão `0600` (somente o seu usuário).
- **Backup**: a seed (12/24 palavras) **é** o backup. Guarde-a em papel, offline,
  em local seguro. Sem ela, nem você recupera os fundos.
- **Nunca** digite sua seed em sites ou programas que não sejam de sua confiança.
- A Senha Mestra protege o **arquivo local**; ela **não** substitui o backup da seed.
- O programa confere se a chave privada corresponde ao endereço antes de assinar e
  valida a derivação contra a biblioteca `embit`. Mesmo assim, **não é auditado**.

### Boas práticas

- Use uma **Senha Mestra longa** (frase de 4+ palavras aleatórias).
- Prefira um computador de confiança; considere usar um sistema **offline**
  (*air-gapped*) para guardar a seed.
- Faça backup da seed **antes** de receber qualquer valor.
- Teste com uma quantia pequena antes de movimentar valores grandes.

---

## Privacidade e rede

Por padrão, as consultas (saldo, UTXOs, taxa) vão para **`mempool.space`**.
Esse servidor **vê os endereços que você consulta** — o que pode ligar o endereço ao
seu IP. Para evitar isso, aponte para um node próprio ou instância via Tor:

```bash
# Node local (ex.: mempool/electrs na porta 3000)
GELOWALLET_API="http://127.0.0.1:3000/api" python3 gelowallet.py

# Serviço .onion via Tor (proxy SOCKS no 9050), exemplo de variável
GELOWALLET_API="http://seu-service.onion/api" python3 gelowallet.py
```

> A variável `GELOWALLET_API` sobrescreve a URL base da API.

### Nota sobre o troco

Por padrão o troco volta para o **mesmo endereço de origem**. Isso é simples, mas
tem um custo de privacidade: liga a entrada à saída na blockchain. Carteiras
convencionais enviam o troco para um **endereço novo da cadeia interna**
(`m/84'/0'/0'/1/i`). Você pode informar outro endereço de troco no próprio fluxo.

---

## Estrutura do projeto

```
gelowallet.py     # o programa (arquivo único)
README.md         # este arquivo
wallets.json      # cofre criptografado (gerado na 1ª gravação; permissão 0600)
```

`wallets.json` (formato):

```json
{
  "kdf": "argon2id",
  "salt": "<base64>",
  "encrypted_data": "<token Fernet>"
}
```

---

## Perguntas frequentes

**O programa transmite a transação?**
Não. Ele gera o HEX assinado e um PSBT não assinado. A transmissão é manual.

**Onde estão meus fundos?**
Na blockchain, sob o controle das chaves derivadas da sua seed. O GELOWALLET só
guarda as chaves (criptografadas).

**Perdi a Senha Mestra. E agora?**
O arquivo `wallets.json` não pode ser aberto. Você ainda recupera os fundos
**se tiver a seed** — importe-a novamente (opção 2).

**Por que minha taxa escolhida virou uma taxa efetiva maior?**
Porque o troco caiu abaixo do dust e foi absorvido pela taxa. Veja
[Fluxo de transação](#fluxo-de-transação).

**É seguro usar?**
Para uso pessoal, com os cuidados acima, sim. Não é auditado; use por sua conta e
risco e teste primeiro com valores pequenos.

---

## Limitações

- **Não transmite** transações.
- Somente **P2WPKH** (endereços `bc1q...`); não faz Taproot (`bc1p`) nem multisig.
- Não acompanha saldos automaticamente (a consulta é por endereço).
- **Não faz bumpfee** (apenas sinaliza RBF).
- Gera PSBT, mas **não assina** PSBT de hardware (não integra Ledger/Trezor).
- Não é auditado por terceiros.

---

## 📄 License

This project is licensed under the MIT License.

Copyright (c) 2026 Tadeu Cadilhe

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
