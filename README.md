<div align="center">

```
  ____             _ZX              _   
 |  _ \           | |              | |  
 | |_) |_ __ _   _| |_ ___ _ __ ___| |_ 
 |  _ <| '__| | | | __/ _ \ '_ \ __| __|
 | |_) | |  | |_| | ||  __/ |_) |/ | |_ 
 |____/|_|   \__,_|\__\___| .__/_\__\__|
                          | |           
                          |_|           
```
# ⚡ Bruteport ⚡

**Advanced Python Port Scanner for Reconnaissance & Penetration Testing**

[![Python 3.x](https://img.shields.io/badge/Python-3.x-blue.svg)](https://python.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Maintenance](https://img.shields.io/badge/Maintained-Yes-green.svg)](https://github.com/yourusername/bruteport)

[Fitur](#-fitur-unggulan) • [Instalasi](#-instalasi) • [Penggunaan](#-cara-penggunaan) • [Disclaimer](#-disclaimer)

</div>

---

**Bruteport** adalah tool pemindai port modern yang dirancang untuk **kecepatan**, **visual**, dan **stealth**. Dibangun murni dengan Python Standard Library, Bruteport siap digunakan di mana saja tanpa perlu instalasi dependensi yang ribet.

Cocok untuk CTF, Bug Bounty, atau Network Administration.

## 🚀 Fitur Unggulan

### 🧠 Intelligence
- **OS Detection**: Menebak sistem operasi target (Windows/Linux) via TTL.
- **GeoIP Lookup**: Menampilkan lokasi fisik server dan ISP.
- **Nmap Bridge**: Integrasi otomatis dengan Nmap (`--nmap`) untuk deep scanning.

### 🛡️ WAF & Firewall Evasion
- **Random User-Agent**: Menipu WAF saat melakukan banner grabbing.
- **Stealth Mode**: Mengacak urutan port & delay dinamis (`--stealth`).
- **Proxy Support**: Tunnel scan melalui SOCKS5 / TOR (`--proxy`).

### ⚡ Performance & UX
- **Multi-threaded**: Scan ribuan port dalam hitungan detik.
- **Smart Presets**: Shortcut scan untuk `web`, `db`, `top100`, dll.
- **Rich Output**: Tampilan berwarna dengan progress bar futuristik.
- **No Dependencies**: Hanya butuh Python 3.

---

## 📦 Instalasi

Tidak perlu `pip install` library berat. Cukup clone dan jalankan.

```bash
# Clone repository
git clone https://github.com/yourusername/bruteport.git

# Masuk direktori
cd bruteport

# (Opsional) Cek kebutuhan
pip install -r requirements.txt 

# Jalankan!
python bruteport/bruteport.py --help
```

---

## 📖 Cara Penggunaan

### 1. Basic Scan
Scan IP spesifik atau seluruh jaringan (CIDR).

**Scan IP Spesifik:**
```bash
python bruteport/bruteport.py 127.0.0.1
```

**Scan Jaringan (CIDR):**
```bash
python bruteport/bruteport.py 127.0.0.0/24 --preset web
```

### 2. Stealth & WAF Bypass (Recommended)
Mode "Ninja" untuk menghindari blokir firewall.
```bash
python bruteport/bruteport.py target.com -p top100 -sV --stealth
```

### 3. Nmap Bridge
Bruteport menemukan port terbuka, Nmap menganalisanya.
```bash
python bruteport/bruteport.py 192.168.1.10 --preset all --nmap
```

### 4. Bulk Scan & Reporting
Scan banyak target dari file dan simpan laporan ke HTML.
```bash
python bruteport/bruteport.py -iL scope_target.txt -o laporan_final.html
```

### 5. Proxy / Tor Scan
Sembunyikan IP aslimu.
```bash
python bruteport/bruteport.py target.com --proxy 127.0.0.1:9050
```

---

## 🛠️ Opsi Lengkap

| Argumen | Deskripsi |
| :--- | :--- |
| `target` | IP, Domain, atau CIDR (misal: `192.168.1.0/24`) |
| `-iL FILE` | Gunakan file daftar target (Bulk Scan) |
| `-p PRESETS` | Preset: `web`, `db`, `mail`, `ftp`, `common`, `top100`, `all` |
| `-sV` | Deteksi versi service (Banner Grabbing) |
| `--stealth` | Mode Stealth (Random Delay, Shuffle Ports) |
| `--proxy HOST:PORT` | Gunakan SOCKS5 Proxy |
| `--nmap` | Auto-run Nmap pada port yang ditemukan |
| `-o FILE` | Simpan hasil ke output file (`.json` / `.html`) |
| `--timeout SEC` | Set timeout koneksi (default: 0.8s) |

---

## ⚠️ Disclaimer

Tool ini dibuat untuk tujuan **edukasi** dan **pengujian keamanan legal**.
Penulis tidak bertanggung jawab atas penyalahgunaan tool ini untuk menyerang sistem tanpa izin.
*Do not be evil.*

---

<div align="center">
    Made with ❤️ and Python by <b>NantzzSec</b>
</div>

