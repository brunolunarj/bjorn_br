# 🖲️ Desenvolvimento do Bjorn

<p align="center">
  <img src="https://github.com/user-attachments/assets/c5eb4cc1-0c3d-497d-9422-1614651a84ab" alt="thumbnail_IMG_0546" width="98">
</p>

## 📚 Sumário

- [Design](#-design)
- [Aspectos educacionais](#-aspectos-educacionais)
- [Aviso](#-aviso)
- [Extensibilidade](#-extensibilidade)
- [Status do desenvolvimento](#-status-do-desenvolvimento)
- [Arquitetura e arquivos principais](#-arquitetura-e-arquivos-principais)
- [Ações](#-ações)
- [Estrutura de dados](#-estrutura-de-dados)
- [Execução do Bjorn](#-execução-do-bjorn)
- [Arquivos de configuração importantes](#-arquivos-de-configuração-importantes)
- [Display e-Paper](#-display-e-paper)
- [Diretrizes de desenvolvimento](#-diretrizes-de-desenvolvimento)
- [Interface web](#-interface-web)
- [Roadmap](#-roadmap)
- [Licença](#-licença)

## 🎨 Design

- **Portabilidade**: dispositivo autocontido para uso em testes de segurança.
- **Modularidade**: arquitetura extensível para inclusão de novas ações.
- **Interface visual**: suporte a e-Paper HAT para status e interação rápida.

## 📔 Aspectos educacionais

- Ferramenta voltada para aprendizagem de conceitos de cibersegurança.
- Permite prática de reconhecimento, avaliação e automação de testes.

## ✒️ Aviso

- Uso exclusivamente educacional e em ambientes autorizados.
- Autor e contribuidores não se responsabilizam por uso indevido.
- Uso malicioso não autorizado pode gerar consequências legais.

## 🧩 Extensibilidade

- O projeto é orientado à adição de novos módulos de ação.
- As ações seguem padrão modular, facilitando manutenção e evolução.

## 🔦 Status do desenvolvimento

- Desenvolvimento ativo.
- Instalação via script automático ou manual.
- Projeto em evolução contínua (estabilidade, performance e novos recursos).

## 🗂️ Arquitetura e arquivos principais

### Núcleo

- `Bjorn.py`: entrada principal e supervisão de execução (runtime).
- `orchestrator.py`: execução e coordenação de ações.
- `shared.py`: estado/configuração compartilhada.
- `runtime_state_updater.py`: atualização de estado para display/web.
- `display.py`: renderização/atualização do e-paper.
- `comment.py`: comentários e frases contextuais.
- `webapp.py`: servidor e rotas da interface web.
- `database.py` + `db_utils/`: persistência e operações no banco.

### Pastas relevantes

- `actions/`: módulos de ação ofensiva/recon.
- `web/` e `web_utils/`: frontend e utilitários da interface.
- `resources/`: recursos (assets), padrões (defaults) e drivers e-paper.
- `data/`: entradas, logs e saídas de execução.

## ▶️ Ações

Exemplos de ações:

- `scanning.py`: descoberta de hosts e portas.
- `nmap_vuln_scanner.py`: varredura de vulnerabilidades.
- `*_bruteforce.py`: tentativas de autenticação em protocolos.
- `steal_*`: coleta de arquivos/dados após acesso.

## 📇 Estrutura de dados

- `data/` contém logs, resultados de varredura e artefatos coletados.
- O banco (`data/bjorn.db`) mantém estado, fila, hosts, credenciais, vulnerabilidades etc.

## ▶️ Execução do Bjorn

### Inicialização manual

```bash
cd /home/bjorn/Bjorn
sudo python3 Bjorn.py
```

### Controle por serviço

```bash
sudo systemctl start bjorn.service
sudo systemctl stop bjorn.service
sudo systemctl status bjorn.service
sudo journalctl -u bjorn.service -f
```

### Reset (início limpo)

Limpe somente dados gerados (logs/saídas/db) antes de reiniciar o serviço, mantendo código e recursos.

## ❇️ Arquivos de configuração importantes

### `config/shared_config.json`

Controla modos, rede, tempos, display, IA, blacklist, portas, etc.

### Definições de ações

As ações são lidas dinamicamente dos módulos em `actions/` e sincronizadas no banco para orquestração.

## 📟 Display e-Paper

- Suporte principal para família 2.13" (incluindo V2/V4).
- Para outros modelos, pode exigir ajuste fino e testes adicionais.

## ✍️ Diretrizes de desenvolvimento

### Como adicionar uma nova ação

1. Criar arquivo em `actions/`.
2. Definir metadados (`b_class`, `b_module`, `b_port`, etc.).
3. Implementar `execute(...)`.
4. Validar integração com orquestrador/DB/interface (UI).

### Testes

- Use ambiente isolado.
- Siga diretrizes éticas e legais.
- Documente casos de teste e resultados.

## 💻 Interface web

- Acesso: `http://[ip-do-dispositivo]:8000`
- Funções: monitoramento, configuração, inspeção de resultados e controle operacional.

## 🧭 Roadmap

### Foco atual

- Estabilidade
- Correções de bugs
- Confiabilidade do serviço
- Melhorias de documentação

### Planos futuros

- Novos módulos de ação
- Relatórios melhores
- Melhorias de UX/UI (experiência/interface)
- Expansão de protocolos suportados

---

## 📜 Licença

2024 - Bjorn é distribuído sob licença MIT. Para mais detalhes, consulte [LICENSE](LICENSE).
