# 🐛 Problemas Conhecidos e Solução de Problemas

<p align="center">
  <img src="https://github.com/user-attachments/assets/c5eb4cc1-0c3d-497d-9422-1614651a84ab" alt="thumbnail_IMG_0546" width="98">
</p>

## 📚 Sumário

- [Problemas de desenvolvimento](#-problemas-de-desenvolvimento)
- [Passos de solução de problemas](#-passos-de-solução-de-problemas)
- [Licença](#-licença)

## 🪲 Problemas de desenvolvimento

### Execução longa (FD)

- **Problema**: `OSError: [Errno 24] Too many open files`
- **Status**: mitigado parcialmente com aumento de limites de descritores.
- **Monitoramento**:
  ```bash
  lsof -p $(pgrep -f Bjorn.py) | wc -l
  ```
- Os logs mostram periodicamente esse valor como `FD: XXX`.

## 🛠️ Passos de solução de problemas

### Problemas com serviço

```bash
# Acompanhar logs do serviço
journalctl -fu bjorn.service

# Ver status
sudo systemctl status bjorn.service

# Logs detalhados
sudo journalctl -u bjorn.service -f

# Ou logs da aplicação
sudo tail -f /home/bjorn/Bjorn/data/logs/*

# Verificar uso da porta 8000
sudo lsof -i :8000
```

### Problemas de display

```bash
# Verificar dispositivos SPI
ls /dev/spi*

# Verificar grupos/permissões
sudo usermod -a -G spi,gpio bjorn
```

### Problemas de rede

```bash
# Interfaces de rede
ip addr show

# Interface USB gadget
ip link show usb0
```

### Problemas de permissão

```bash
# Corrigir proprietário
sudo chown -R bjorn:bjorn /home/bjorn/Bjorn

# Corrigir permissões
sudo chmod -R 755 /home/bjorn/Bjorn
```

---

## 📜 Licença

2024 - Bjorn é distribuído sob licença MIT. Para mais detalhes, consulte [LICENSE](LICENSE).
