# OpenVPN Certificate & Client Management Tool

A **secure, all-in-one Python tool** for managing an OpenVPN infrastructure.  
It handles **CA creation, server configuration, client certificates, password-based auth, revocation, CRLs, expiration cleanup, and packaging** — all without Easy-RSA.

This script is designed for **Linux-based OpenVPN servers** and focuses on **security, automation, and portability**.

---

## ✨ Features

- 🔐 Full **Certificate Authority (CA)** management
- 🖥️ Generate **OpenVPN server certificates & config**
- 👤 Create **client certificates** (certificate-only or cert + username/password)
- 🔑 **Encrypted password storage** (AES + PBKDF2, master password protected)
- 🚫 **Certificate revocation** with automatic CRL updates
- ⏳ **Auto-clean expired certificates**
- 📦 Client **ZIP packages** ready to distribute
- 🧾 Audit logging for issued/revoked clients
- 🔒 Hardened crypto:
  - RSA 4096-bit keys
  - AES-256-CBC
  - TLS 1.2+
  - `tls-crypt` enabled
- ⚙️ Optional **systemd service file** generation

---

## 📁 Directory Structure

```
openvpn/
├── ca/
│   ├── ca.crt
│   ├── ca.key
│   ├── crl.pem
│   └── index.txt
├── server/
│   ├── server.crt
│   ├── server.key
│   ├── dh.pem
│   ├── server.ovpn
│   └── openvpn-server.service
├── clients/
│   └── <client_name>/
│       ├── <client>.ovpn
│       ├── <client>.crt
│       ├── <client>.key
│       ├── <client>.auth (optional)
│       ├── tls-crypt.key
│       └── <client>_openvpn_package.zip
├── tls-crypt.key
├── passwords.json
└── audit.log
```

---

## 🧰 Requirements

- Python **3.8+**
- OpenSSL installed
- Linux (recommended)

### Python dependencies
```bash
pip install cryptography
```

---

## ⚙️ Configuration

Edit these values at the top of the script before running:

```python
SERVER_PUBLIC_IP = "10.10.10.240"
SERVER_PRIVATE_IP = "10.8.0.1"
SERVER_NETWORK = "10.8.0.0"
SERVER_NETMASK = "255.255.255.0"
SERVER_PORT = 1194
```

---

## 🚀 Quick Start

### 1️⃣ Initialize everything (CA + server)
```bash
python3 genclient.py initall
```

---

## 👤 Client Management

```bash
python3 genclient.py alice
python3 genclient.py create bob --password
python3 genclient.py revoke alice
python3 genclient.py list
python3 genclient.py clean
```

---

## 🔐 Security Notes

- CA private key permissions: `600`
- Client keys: `600`
- Passwords encrypted with PBKDF2 + AES
- TLS control channel protected with `tls-crypt`

---

## 📜 License

MIT License
