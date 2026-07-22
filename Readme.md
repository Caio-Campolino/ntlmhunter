<div align="center">

# NTLMHunter

**Ferramenta profissional de auditoria de segurança para cracking offline de hashes NTLM e validação online via Pass-the-Hash (SMB)**

[![Python](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-Educacional%2FAutorizado-lightgrey.svg)](#-licença)
[![Impacket](https://img.shields.io/badge/dep-impacket-orange.svg)](https://github.com/fortra/impacket)
[![Hashcat](https://img.shields.io/badge/dep-hashcat-yellow.svg)](https://hashcat.net/hashcat/)
[![Status](https://img.shields.io/badge/status-ativo-brightgreen.svg)](#)

</div>

---

## Sumário

- [Visão Geral](#-visão-geral)
- [Funcionalidades](#-funcionalidades)
- [Dependências](#-dependências)
- [Instalação](#-instalação)
- [Exemplos de Uso](#-exemplos-de-uso)
- [Estrutura de Arquivos](#-estrutura-de-arquivos)
- [Mecanismo de Validação](#️-mecanismo-de-validação)
- [Formatos de Saída](#-formatos-de-saída)
- [Configuração Avançada](#️-configuração-avançada)
- [Avisos Importantes](#️-avisos-importantes)
- [Solução de Problemas](#-solução-de-problemas)
- [Licença](#-licença)
- [Contribuições](#-contribuições)

---

## 🔍 Visão Geral

**NTLMHunter** é uma solução para auditorias de segurança em ambientes Windows, unindo em um único fluxo de trabalho:

-  **Cracking offline** de hashes NTLM utilizando **Hashcat**
-  **Validação online** via autenticação SMB com **Pass-the-Hash**
-  **Verificação dupla** de credenciais para eliminar falsos positivos
-  **Processamento paralelo** para testes em larga escala

---

## Funcionalidades

| Recurso | Descrição |
|---|---|
|  Múltiplos formatos de hash | Suporte a dumps `SAM` e listas `user:hash` |
|  Extração automática de domínio | Identifica o domínio a partir dos hashes fornecidos |
|  Dupla verificação | Validação via `listShares` + fallback `IPC$` |
|  Threading otimizado | Testes simultâneos configuráveis |
|  Múltiplos relatórios | Exportação em `TXT`, `JSON` e `CSV` |
|  Versionamento automático | Evita sobrescrever arquivos de saída existentes |
|  Permissões seguras | Arquivos de resultado salvos com permissão `600` |

---

## Dependências

- **Python 3.8+**
- **[Impacket](https://github.com/fortra/impacket)**

```bash
pip install impacket
```

- **[Hashcat](https://hashcat.net/hashcat/)** (necessário apenas para cracking offline)

---

## Instalação

```bash
git clone https://github.com/Caio-Campolino/ntlmhunter.git
cd ntlmhunter
chmod +x ntlmhunter.py
```

---

## Exemplos de Uso

### Cracking offline apenas

```bash
./ntlmhunter.py hashes.txt --crack --wordlist /path/to/rockyou.txt
```

### Teste online (Pass-the-Hash)

```bash
./ntlmhunter.py hashes.txt --targets targets.txt --threads 30 --timeout 5
```

### Modo completo (cracking + validação online)

```bash
./ntlmhunter.py hashes.txt --crack --targets targets.txt --output relatorio.json --format json
```

### Com debug e verbose

```bash
./ntlmhunter.py hashes.txt --crack --targets targets.txt --verbose --debug --threads 15
```

### Especificando domínio

```bash
./ntlmhunter.py hashes.txt --targets targets.txt --domain dominio.local --threads 20
```

---

## Estrutura de Arquivos

### Arquivo de Hashes

Suporta dois formatos:

**Formato SAM:**

```text
Administrador:500:aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c:::
Usuario:1001:aad3b435b51404eeaad3b435b51404ee:7c4a8d09ca3762af61e59520943dc264:::
```

**Formato `user:hash`:**

```text
usuario1:8846f7eaee8fb117ad06bdd830b7586c
usuario2:7c4a8d09ca3762af61e59520943dc264
```

### Arquivo de Alvos

Lista de IPs, um por linha:

```text
192.168.1.10
192.168.1.11
192.168.1.12
```

---

## Mecanismo de Validação

O NTLMHunter implementa uma validação em duas etapas para garantir a autenticidade das credenciais:

1. **`listShares()`** — tenta listar os compartilhamentos SMB do alvo.
2. **`connectTree('IPC$')`** — em caso de falha na etapa anterior, tenta acessar o pipe `IPC$` como fallback.

Essa abordagem elimina falsos positivos e garante que apenas autenticações realmente bem-sucedidas sejam reportadas no relatório final.

---

## Formatos de Saída

### TXT
Relatório legível, com seções organizadas para análise manual.

### JSON
Estrutura para integração com outras ferramentas:

```json
{
  "metadata": {
    "timestamp": "2024-01-15 14:30:00",
    "hashfile": "hashes.txt",
    "targets_file": "targets.txt"
  },
  "cracked_passwords": {
    "usuario1": "senha123"
  },
  "valid_pass_the_hash": [
    "admin@192.168.1.10 -> 8846f7eaee8fb117ad06bdd830b7586c"
  ]
}
```

### CSV
Formato tabular, pronto para importação em planilhas e ferramentas de análise.

---

## Configuração Avançada

### Ajuste de performance

| Parâmetro | Descrição | Padrão |
|---|---|---|
| `--threads` | Nº de testes simultâneos (aumente em redes rápidas) | `20` |
| `--timeout` | Tempo limite de conexão (ajuste conforme latência) | `5s` |
| `--hashcat-args` | Argumentos extras repassados ao Hashcat | — |

### Otimizações para Hashcat

```bash
./ntlmhunter.py hashes.txt --crack --hashcat-args "-O -w 4 --force"
```

---

## Avisos Importantes

> **Uso Autorizado:** esta ferramenta destina-se **apenas** a testes de segurança autorizados e estudos acadêmicos.

- **Responsabilidade:** o usuário é inteiramente responsável pelo uso da ferramenta.
- **Impacto de rede:** testes com alto número de threads podem gerar alertas em redes monitoradas.
- **Legalidade:** verifique as leis locais e obtenha autorização formal (contrato/escopo assinado) antes de utilizar ferramentas de auditoria de segurança em qualquer ambiente que não seja de sua propriedade.

---

## Solução de Problemas

<details>
<summary><strong>Erro: "Impacket não instalado"</strong></summary>

```bash
pip install impacket
```
</details>

<details>
<summary><strong>Erro: "hashcat não encontrado"</strong></summary>

- Verifique se o Hashcat está instalado e disponível no `PATH`.
- Ou informe o caminho manualmente: `--hashcat-path /caminho/para/hashcat`
</details>

<details>
<summary><strong>Erro: "Wordlist não encontrada"</strong></summary>

- Verifique o caminho da wordlist informado.
- Baixe wordlists comuns, como `rockyou.txt`.
</details>

<details>
<summary><strong>Conexões SMB falhando</strong></summary>

- Verifique se os alvos estão acessíveis na rede.
- Aumente o timeout: `--timeout 10`
- Considere que firewalls podem bloquear as portas SMB (`445`, `139`).
</details>

---


Este software é fornecido para fins **educacionais** e de **auditoria autorizada**.

---

## Contribuições

Contribuições são bem-vindas! Abra uma [issue](../../issues) ou um [pull request](../../pulls) para sugerir melhorias, relatar bugs ou propor novas funcionalidades.

<div align="center">

---

Desenvolvido para a comunidade de segurança da informação.

</div>
