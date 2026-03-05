## 🔧 Instalação e Configuração

<p align="center">
  <img src="https://github.com/user-attachments/assets/c5eb4cc1-0c3d-497d-9422-1614651a84ab" alt="thumbnail_IMG_0546" width="98">
</p>

## 📚 Sumário

- [Pré-requisitos](#-pré-requisitos)
- [Instalação rápida](#-instalação-rápida)
- [Instalação manual](#-instalação-manual)
- [Integração com servidor de IA (Bjorn-cortex)](#-integração-com-servidor-de-ia-bjorn-cortex)
- [Licença](#-licença)

Use o Raspberry Pi Imager para gravar o sistema:
https://www.raspberrypi.com/software/

### 📌 Pré-requisitos para Raspberry Pi Zero W (32 bits)

- Raspberry Pi OS instalado (Debian 12 / Bookworm recomendado)
- Usuário e hostname: `bjorn`
- Display e-Paper HAT 2.13" conectado ao GPIO

### 📌 Pré-requisitos para Raspberry Pi Zero 2 W (64 bits)

- Raspberry Pi OS instalado (Debian 12 / Bookworm recomendado)
- Usuário e hostname: `bjorn`
- Display e-Paper HAT 2.13" conectado ao GPIO

Modelos V2 e V4 do display são os mais testados.

### ⚡ Instalação rápida

Com o projeto já local:

```bash
cd /home/bjorn/Bjorn
sudo chmod +x install_bjorn.sh
sudo ./install_bjorn.sh
```

Selecione a opção `1` para instalação completa.

### 🧰 Instalação manual

#### Passo 1: Ativar SPI e I2C

```bash
sudo raspi-config
```

Em **Interface Options**, ative **SPI** e **I2C**.

#### Passo 2: Dependências do sistema

```bash
sudo apt-get update && sudo apt-get upgrade -y
sudo apt install -y \
  libjpeg-dev zlib1g-dev libpng-dev python3-dev libffi-dev libssl-dev \
  libgpiod-dev libi2c-dev libatlas-base-dev build-essential python3-pip \
  wget lsof git libopenjp2-7 nmap libopenblas-dev bluez-tools bluez \
  dhcpcd5 bridge-utils python3-pil smbclient dnsmasq hostapd \
  aircrack-ng tshark net-tools python3-dbus python3-paramiko

sudo nmap --script-updatedb
```

#### Passo 3: Dependências Python

```bash
cd /home/bjorn/Bjorn
sudo pip3 install -r requirements.txt --break-system-packages
```

#### Passo 4: Configurar tipo de display

Edite `config/shared_config.json` e ajuste `epd_type` para seu modelo:

- `epd2in13`
- `epd2in13_V2`
- `epd2in13_V3`
- `epd2in13_V4`
- `epd2in7`

#### Passo 5: Limites de file descriptors

Para evitar `Too many open files`:

- `/etc/security/limits.conf`
- `/etc/systemd/system.conf`
- `/etc/systemd/user.conf`
- `/etc/security/limits.d/90-nofile.conf`
- `/etc/sysctl.conf`

Use os mesmos valores definidos no instalador automático (`65535` e `fs.file-max=2097152`).

#### Passo 6: Serviços

Crie/ative:

- `bjorn.service`
- `usb-gadget.service`

Depois:

```bash
sudo systemctl daemon-reload
sudo systemctl enable bjorn.service
sudo systemctl enable systemd-networkd
sudo systemctl enable usb-gadget
```

#### Passo 7: Reinicie

```bash
sudo reboot
```

### Configuração USB Gadget (Windows)

No PC Windows:

- IP: `172.20.2.2`
- Máscara: `255.255.255.0`
- Gateway: `172.20.2.1`
- DNS: `8.8.8.8`, `8.8.4.4`

### 🧠 Integração com servidor de IA (Bjorn-cortex)

Se você quer usar treinamento/sincronização de IA externa:

1. Suba o servidor Bjorn-cortex em outra máquina usando os templates em:
   - `deploy/bjorn-cortex/docker-compose.yml`
   - `deploy/bjorn-cortex/.env.example`
   - `deploy/bjorn-cortex/README.md`
2. No Pi do Bjorn, ajuste `config/shared_config.json`:
   - `ai_server_url`: `http://IP_DO_SERVIDOR:8001`
3. Reinicie o serviço:

```bash
sudo systemctl restart bjorn.service
```

---

## 📜 Licença

2024 - Bjorn é distribuído sob licença MIT. Para mais detalhes, consulte [LICENSE](LICENSE).
