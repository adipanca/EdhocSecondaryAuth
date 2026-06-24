# Sample FreeRADIUS Config for EAP-EDHOC

Folder ini berisi baseline konfigurasi yang diperlukan untuk integrasi DN-AAA dengan Open5GS UPF (secondary authentication).

## Isi file

- `authorize`: sample user entries
- `clients.conf.sample`: client RADIUS untuk UPF
- `radcli-servers`: endpoint RADIUS server
- `radiusclient.conf`: sample konfigurasi radcli
- `rlm_eap_edhoc/`: skeleton module EAP-EDHOC
- `setup-freeradius.sh`: helper setup awal

## Cara pakai cepat

1. Jalankan `sudo bash setup-freeradius.sh`
2. Jalankan FreeRADIUS debug mode: `sudo radiusd -X`
3. Verifikasi port `1812/udp` aktif
