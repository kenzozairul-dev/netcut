# NetCut

Pemantau dan pengurus rangkaian rumah (LAN) — inventori peranti, kesan peranti baru, dan polisi akses.

> **Skop keselamatan:** NetCut ialah alat *defensif*. Ia memerhati rangkaian anda sendiri dan menghasilkan keputusan polisi (allow / throttle / block / quarantine). Ia **tidak** melakukan ARP spoofing, deauthentication, atau serangan DoS terhadap peranti lain. Untuk benar-benar menyekat atau memperlahankan peranti, polisi perlu dilaksanakan di **router** anda (lihat [Melaksanakan polisi](#melaksanakan-polisi)).

## Ciri

- **Inventori peranti** — IP, MAC, hostname, vendor (OUI), status up/down
- **Pengesan peranti baru** — log peristiwa apabila peranti tidak dikenali muncul
- **Kesan perubahan IP** — alert bila MAC yang sama bertukar IP
- **Enjin polisi** — allowlist, blocklist, guest mode (throttle peranti tidak dipercayai)
- **Dashboard web** — jadual peranti, butang Trust/Block, tetapan polisi, log peristiwa
- **Eksport JSON** — snapshot penuh untuk audit atau sandaran
- **CLI** — `netcut scan` untuk laporan pantas

## Keperluan

- Python 3.10+
- Windows / Linux / macOS
- Untuk ping sweep: `ping` mesti ada dalam PATH (biasanya ya)

## Pemasangan

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -e .
```

Salin konfigurasi:

```powershell
Copy-Item config.example.json config.json
```

## Penggunaan

### `npm run dev` (cara pantas)

```powershell
npm install          # sekali sahaja (tiada dependency, hanya daftar script)
npm run dev          # dashboard dengan auto-reload di http://127.0.0.1:8088
```

Script lain:

| Arahan | Fungsi |
|---|---|
| `npm run dev` | Serve dashboard + auto-reload bila fail berubah |
| `npm start` | Serve tanpa reload |
| `npm run scan` | Scan sekali, cetak jadual |
| `npm run scan:json` | Scan sekali, output JSON |
| `npm test` | Jalankan ujian pytest |
| `npm run install:deps` | Pasang pakej Python yang diperlukan |

> `npm run dev` memerlukan pakej Python sudah dipasang (`npm run install:deps`).

### Scan sekali (CLI)

```powershell
netcut scan
netcut scan --json
netcut scan --no-ping     # baca ARP sahaja, lebih pantas
```

Contoh output:

```
Subnet : 192.168.0.0/24
Gateway: 192.168.0.1
Devices: 4

IP              MAC                STATE  POLICY      VENDOR                   HOST
----------------------------------------------------------------------------------
192.168.0.1     10:71:b3:2f:73:30  up     allow       Zyxel                    gateway
192.168.0.30    7c:f1:7e:f4:98:16  up     allow       TP-Link
192.168.0.110   a8:93:4a:ea:18:0f  up     allow       Samsung
192.168.0.127   b2:2c:63:85:79:b3  up     allow       Private (randomised MAC)
```

### Dashboard web

```powershell
netcut serve --port 8088
```

Buka http://127.0.0.1:8088

Dashboard akan scan setiap 60 saat (boleh ubah), dan menyimpan inventori dalam `data/devices.json`.

> Layanan default hanya pada `127.0.0.1`. Jangan dedahkan ke `0.0.0.0` tanpa kata laluan/proxy.

## Konfigurasi

`config.json`:

| Kunci | Maksud |
|---|---|
| `subnet` | CIDR untuk ping sweep. `null` = auto-detect |
| `gateway` | IP router. `null` = auto-detect |
| `scan_interval_seconds` | Selang scan latar belakang (min 10) |
| `ping_timeout_ms` | Timeout ping setiap hos |
| `ping_concurrency` | Bilangan ping serentak |
| `allowlist` | Jika tidak kosong → hanya MAC ini dibenarkan, yang lain `quarantine` |
| `blocklist` | MAC yang disekat |
| `alert_on_new_device` | Log peristiwa untuk peranti baru |
| `guest_mode` | Throttle semua peranti tidak dipercayai |

## Melaksanakan polisi

NetCut menghasilkan **niat polisi**, bukan tindakan rangkaian. Untuk menguatkuasakannya:

1. **Router (disyorkan)** — gunakan Parental Controls / Access Control / Bandwidth Control pada router anda (contoh Zyxel, TP-Link, ASUS). Masukkan MAC dari senarai blocklist.
2. **Firewall hos** — untuk peranti anda sendiri, hadkan akses keluar.
3. **QoS** — hadkan lebar jalur mengikut peranti di router.

Dashboard menyediakan butang **Export JSON** supaya senarai MAC boleh dipindahkan ke router.

## Struktur projek

```
netcut/
├── netcut/
│   ├── app.py        # FastAPI + REST API
│   ├── cli.py        # entrypoint CLI
│   ├── config.py     # model konfigurasi
│   ├── monitor.py    # scanner latar belakang
│   ├── policy.py     # enjin polisi
│   ├── scanner.py    # ARP, ping, OUI
│   ├── store.py      # inventori JSON
│   └── web/index.html
├── tests/
├── config.example.json
└── pyproject.toml
```

## Ujian

```powershell
pip install pytest httpx
pytest -q
```

## Lesen

MIT
