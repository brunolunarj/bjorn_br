# <img src="https://github.com/user-attachments/assets/c5eb4cc1-0c3d-497d-9422-1614651a84ab" alt="thumbnail_IMG_0546" width="33"> Bjorn

![Python](https://img.shields.io/badge/Python-3776AB?logo=python&logoColor=fff)
![Status](https://img.shields.io/badge/Status-Development-blue.svg)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

[![Reddit](https://img.shields.io/badge/Reddit-Bjorn__CyberViking-orange?style=for-the-badge&logo=reddit)](https://www.reddit.com/r/Bjorn_CyberViking)
[![Discord](https://img.shields.io/badge/Discord-Join%20Us-7289DA?style=for-the-badge&logo=discord)](https://discord.com/invite/B3ZH9taVfT)

<p align="center">
  <img src="https://github.com/user-attachments/assets/c5eb4cc1-0c3d-497d-9422-1614651a84ab" alt="thumbnail_IMG_0546" width="150">
  <img src="https://github.com/user-attachments/assets/1b490f07-f28e-4418-8d41-14f1492890c6" alt="bjorn_epd-removebg-preview" width="150">
</p>

> **Nota deste repositório**  
> Este projeto é uma adaptação do **ramo [`ai`](https://github.com/infinition/Bjorn/tree/ai)** do repositório original `infinition/Bjorn`, com ajustes e tradução para **português (pt-BR)**.

Bjorn é uma ferramenta autônoma de segurança ofensiva e avaliação de vulnerabilidades, no estilo “Tamagotchi”, desenvolvida para rodar em Raspberry Pi com display e-Paper HAT de 2.13".

## 📚 Sumário

- [Introdução](#-introdução)
- [Recursos](#-recursos)
- [Primeiros Passos](#-primeiros-passos)
  - [Pré-requisitos](#-pré-requisitos)
  - [Instalação](#-instalação)
  - [Instalação via GitHub (bjorn_br)](#-instalação-via-github-bjorn_br)
- [Início Rápido](#-início-rápido)
- [Exemplo de Uso](#-exemplo-de-uso)
- [Contribuição](#-contribuição)
- [Licença](#-licença)
- [Contato](#-contato)

## 📄 Introdução

Bjorn foi projetado para realizar varredura de rede, avaliação de vulnerabilidades e coleta de dados de forma automatizada. A arquitetura modular e as várias opções de configuração permitem operações flexíveis e direcionadas.

Combinando diferentes ações de forma orquestrada, Bjorn ajuda a identificar riscos de segurança e a melhorar a visibilidade do ambiente.

O display e-Paper e a interface web permitem monitoramento em tempo real e controle operacional, enquanto a arquitetura extensível facilita a criação de novos módulos.

## 🌟 Recursos

- **Varredura de Rede**: identifica hosts ativos e portas abertas.
- **Avaliação de Vulnerabilidades**: executa varreduras com Nmap e outras técnicas.
- **Ataques de Serviço**: suporte a brute force em FTP, SSH, SMB, RDP, Telnet e SQL.
- **Coleta de Arquivos/Dados**: extração de dados em serviços vulneráveis.
- **Interface de Operação**: display e-Paper + interface web em tempo real.

![Bjorn Display](https://github.com/infinition/Bjorn/assets/37984399/bcad830d-77d6-4f3e-833d-473eadd33921)

## 🚀 Primeiros Passos

## 📌 Pré-requisitos

### 📋 Raspberry Pi Zero W (32 bits)

![image](https://github.com/user-attachments/assets/3980ec5f-a8fc-4848-ab25-4356e0529639)

- Raspberry Pi OS instalado.
  - Recomendado:
    - Sistema: 32-bit
    - Kernel: 6.6
    - Debian: 12 (bookworm) `2024-10-22-raspios-bookworm-armhf-lite`
- Usuário e hostname configurados como `bjorn`.
- Display e-Paper HAT 2.13" conectado ao GPIO.

### 📋 Raspberry Pi Zero 2 W (64 bits)

![image](https://github.com/user-attachments/assets/e8d276be-4cb2-474d-a74d-b5b6704d22f5)

Embora o desenvolvimento original tenha focado no Pi Zero W, há diversos relatos de instalação funcionando no Pi Zero 2 W (64 bits).

- Raspberry Pi OS instalado.
  - Recomendado:
    - Sistema: 64-bit
    - Kernel: 6.6
    - Debian: 12 (bookworm) `2024-10-22-raspios-bookworm-arm64-lite`
- Usuário e hostname configurados como `bjorn`.
- Display e-Paper HAT 2.13" conectado ao GPIO.

Atualmente os modelos de display v2 e v4 foram os mais testados. V1 e V3 podem funcionar, mas exigem validação adicional.

### 🔨 Instalação

Para instalação automática, use o script local deste repositório:

```bash
cd /home/bjorn/Bjorn
sudo chmod +x install_bjorn.sh
sudo ./install_bjorn.sh
```

### 🔗 Instalação via GitHub (bjorn_br)

Se você vai instalar diretamente do repositório bjorn_br:

```bash
cd /home/bjorn
git clone https://github.com/brunolunarj/bjorn_br.git
cd bjorn_br
git checkout main
sudo chmod +x install_bjorn.sh
sudo ./install_bjorn.sh
```

Se preferir a branch de desenvolvimento:

```bash
git checkout ai
sudo ./install_bjorn.sh
```

Para detalhes completos, veja: [Guia de Instalação](INSTALL.md)

## ⚡ Início Rápido

Está com dificuldade para encontrar o IP do Bjorn após instalar?
Use o utilitário:

[https://github.com/infinition/bjorn-detector](https://github.com/infinition/bjorn-detector)

![ezgif-1-a310f5fe8f](https://github.com/user-attachments/assets/182f82f0-5c3a-48a9-a75e-37b9cfa2263a)

Para solução de problemas detalhada:
[Solução de Problemas](TROUBLESHOOTING.md)

## 💡 Exemplo de Uso

Exemplo (simulado) de execução:

```bash
# Reconhecimento
[NetworkScanner] Descobrindo hosts ativos...
[+] Host encontrado: 192.168.1.100
    ├── Portas: 22,80,445,3306
    └── MAC: 00:11:22:33:44:55

# Sequência de ataque
[NmapVulnScanner] Vulnerabilidades encontradas em 192.168.1.100
    ├── MySQL 5.5 < 5.7 - Enumeração de usuários
    └── SMB - Candidato a EternalBlue

[SSHBruteforce] Quebrando credenciais...
[+] Sucesso! user:password123
[StealFilesSSH] Extraindo arquivos sensíveis...

# Coleta automatizada
[SQLBruteforce] Banco acessado!
[StealDataSQL] Exportando tabelas...
[SMBBruteforce] Compartilhamento acessível
[+] Configs, credenciais e backups encontrados...
```

Os resultados reais variam conforme o ambiente e os alvos.

Os dados descobertos são organizados em `data/output/`, visíveis tanto na interface web quanto nos indicadores do display.

⚠️ **Uso exclusivamente educacional e para testes autorizados** ⚠️

## 🤝 Contribuição

Contribuições bem-vindas em:

- Novos módulos de ataque
- Correções de bugs
- Documentação
- Melhorias de arquitetura e performance

Mais detalhes:
[Contribuição](CONTRIBUTING.md), [Código de Conduta](CODE_OF_CONDUCT.md), [Desenvolvimento](DEVELOPMENT.md)

## 📫 Contato

- **Issues (GitHub)**: abra no GitHub
- **Boas práticas**:
  - Siga princípios éticos e legais
  - Documente passos de reprodução
  - Inclua logs e contexto

- **Autor original**: __infinition__
- **Projeto original**: [infinition/Bjorn](https://github.com/infinition/Bjorn)

## 🌠 Stargazers

[![Star History Chart](https://api.star-history.com/svg?repos=infinition/bjorn&type=Date)](https://star-history.com/#infinition/bjorn&Date)

---

## 📜 Licença

2024 - Bjorn é distribuído sob licença MIT. Veja [LICENSE](LICENSE).
