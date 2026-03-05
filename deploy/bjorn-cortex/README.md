# Bjorn-cortex com Docker Compose

Este diretório contém um template para subir o servidor de IA (Bjorn-cortex) em um host separado.

## 1) Preparar ambiente

```bash
cd deploy/bjorn-cortex
cp .env.example .env
```

Edite o arquivo `.env` e confirme:

- `CORTEX_IMAGE`: imagem do servidor Bjorn-cortex
- `CORTEX_PORT`: porta no host (padrão `8001`)

## 2) Subir o serviço

```bash
docker compose up -d
docker compose logs -f
```

## 3) Apontar o Bjorn para o Cortex

No Raspberry Pi onde o Bjorn roda, ajuste `config/shared_config.json`:

- `ai_server_url`: `http://IP_DO_SERVIDOR_CORTEX:8001`

Exemplo:

```bash
cd /home/bjorn/Bjorn
python3 - << 'PY'
import json
from pathlib import Path
p = Path("config/shared_config.json")
d = json.loads(p.read_text(encoding="utf-8"))
d["ai_server_url"] = "http://192.168.1.40:8001"
p.write_text(json.dumps(d, ensure_ascii=False, indent=4) + "\n", encoding="utf-8")
print("ai_server_url atualizado com sucesso")
PY
sudo systemctl restart bjorn.service
```

## Endpoints usados pelo Bjorn

O cliente Bjorn consulta estes endpoints no servidor de IA:

- `GET /model/latest`
- `GET /model/download/bjorn_model_<versao>.json`
- `GET /model/download/bjorn_model_<versao>_weights.json`
- `POST /upload`
