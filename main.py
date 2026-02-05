#!/usr/bin/env python3
import os
import secrets
import sys
import shutil
import base64
from pathlib import Path
from datetime import datetime, timedelta

# cryptography imports (replacing pyOpenSSL)
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import (
    BestAvailableEncryption, NoEncryption, PrivateFormat
)

# =========================
# CONFIGURATION
# =========================
SERVER_PUBLIC_IP = "10.10.10.240"
SERVER_PORT = 1194
PROTOCOL = "udp"
CIPHER = "AES-256-CBC"
AUTH = "SHA256"

BASE_DIR = Path("openvpn")
CA_DIR = BASE_DIR / "ca"
CLIENTS_DIR = BASE_DIR / "clients"
TLS_CRYPT_KEY = BASE_DIR / "tls-crypt.key"
LOG_FILE = BASE_DIR / "audit.log"
INDEX_FILE = CA_DIR / "index.txt"  # Tracks issued certs

CA_CERT = CA_DIR / "ca.crt"
CA_KEY = CA_DIR / "ca.key"
CRL_FILE = CA_DIR / "crl.pem"

DEFAULT_CERT_DAYS = 365

# =========================
# UTILS
# =========================
def secure_mkdir(path):
    path.mkdir(parents=True, exist_ok=True)
    os.chmod(path, 0o700)

def log(msg):
    BASE_DIR.mkdir(exist_ok=True)
    with open(LOG_FILE, "a") as f:
        f.write(f"[{datetime.utcnow().isoformat()}] {msg}\n")

# =========================
# CA GENERATION
# =========================
def generate_ca(days=3650):
    """Generate a new CA certificate if one doesn't exist"""
    if CA_CERT.exists() and CA_KEY.exists():
        return
    
    secure_mkdir(CA_DIR)
    
    # Generate CA key
    ca_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=4096,
    )
    
    # Generate CA certificate
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "California"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "San Francisco"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "OpenVPN CA"),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "OpenVPN"),
        x509.NameAttribute(NameOID.COMMON_NAME, "OpenVPN CA"),
    ])
    
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.utcnow())
        .not_valid_after(datetime.utcnow() + timedelta(days=days))
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=0),
            critical=True,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=True,
                key_encipherment=True,
                data_encipherment=True,
                key_agreement=True,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )
    
    # Save CA private key
    with open(CA_KEY, "wb") as f:
        f.write(ca_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=NoEncryption(),
        ))
    os.chmod(CA_KEY, 0o600)
    
    # Save CA certificate
    with open(CA_CERT, "wb") as f:
        f.write(ca_cert.public_bytes(serialization.Encoding.PEM))
    
    # Initialize empty index and CRL files
    with open(INDEX_FILE, "w") as f:
        pass
    
    # Initialize empty CRL
    builder = x509.CertificateRevocationListBuilder()
    builder = builder.issuer_name(subject)
    builder = builder.last_update(datetime.utcnow())
    builder = builder.next_update(datetime.utcnow() + timedelta(days=365))
    crl = builder.sign(private_key=ca_key, algorithm=hashes.SHA256())
    
    with open(CRL_FILE, "wb") as f:
        f.write(crl.public_bytes(serialization.Encoding.PEM))
    
    print(f"[+] Generated new CA certificate (valid for {days} days)")
    log("CA generated")

# =========================
# TLS-CRYPT KEY
# =========================
def ensure_tls_crypt():
    if TLS_CRYPT_KEY.exists():
        return
    print("[+] Generating tls-crypt key")
    with open(TLS_CRYPT_KEY, "wb") as f:
        f.write(secrets.token_bytes(256))  # 2048-bit key = 256 bytes
    os.chmod(TLS_CRYPT_KEY, 0o600)
    log("tls-crypt key generated")

# =========================
# CA LOADING
# =========================
def load_ca():
    if not CA_CERT.exists() or not CA_KEY.exists():
        raise FileNotFoundError("CA certificate or key missing in ca/ directory")
    
    # Load CA certificate
    with open(CA_CERT, "rb") as f:
        ca_cert = x509.load_pem_x509_certificate(f.read())
    
    # Load CA private key
    with open(CA_KEY, "rb") as f:
        ca_key = serialization.load_pem_private_key(f.read(), password=None)
    
    return ca_cert, ca_key

# =========================
# CLIENT CERTIFICATE
# =========================
def generate_client_cert(client_name, days=DEFAULT_CERT_DAYS):
    client_dir = CLIENTS_DIR / client_name
    secure_mkdir(client_dir)

    # Generate private key
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=4096,
    )
    
    # Save unencrypted key
    key_file = client_dir / f"{client_name}.key"
    with open(key_file, "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=NoEncryption(),
        ))
    os.chmod(key_file, 0o600)

    # Sign certificate
    ca_cert, ca_key = load_ca()
    
    # Build client certificate
    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, client_name),
    ])
    
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.utcnow())
        .not_valid_after(datetime.utcnow() + timedelta(days=days))
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH]),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )

    # Save certificate
    crt_file = client_dir / f"{client_name}.crt"
    with open(crt_file, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    # Update index.txt
    with open(INDEX_FILE, "a") as f:
        expiry_str = (datetime.utcnow() + timedelta(days=days)).strftime("%y%m%d%H%M%SZ")
        serial_hex = format(cert.serial_number, 'X')
        f.write(f"V\t{expiry_str}\t{serial_hex}\tunknown\t/CN={client_name}\n")

    log(f"Client issued: {client_name} ({days} days)")
    return key_file, crt_file

# =========================
# OVPN GENERATION
# =========================
def generate_ovpn(client_name, key_file, crt_file):
    client_dir = CLIENTS_DIR / client_name
    ovpn_file = client_dir / f"{client_name}.ovpn"

    # Load files
    with open(CA_CERT, "r") as f:
        ca = f.read()
    with open(crt_file, "r") as f:
        cert = f.read()
    with open(key_file, "r") as f:
        key = f.read()
    
    # Read TLS crypt key as binary and encode to base64
    with open(TLS_CRYPT_KEY, "rb") as f:
        tls_key_bin = f.read()
    tls_key_b64 = base64.b64encode(tls_key_bin).decode('ascii')

    ovpn_content = f"""client
dev tun
proto {PROTOCOL}
remote {SERVER_PUBLIC_IP} {SERVER_PORT}
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
cipher {CIPHER}
auth {AUTH}
verb 3
tls-crypt tls-crypt.key

<ca>
{ca.strip()}
</ca>

<cert>
{cert.strip()}
</cert>

<key>
{key.strip()}
</key>

<tls-crypt>
{tls_key_b64}
</tls-crypt>
"""
    
    ovpn_file.write_text(ovpn_content)
    os.chmod(ovpn_file, 0o600)
    return ovpn_file

# =========================
# CLIENT MANAGEMENT
# =========================
def create_client(name, days=DEFAULT_CERT_DAYS):
    # Ensure CA exists
    generate_ca()
    ensure_tls_crypt()
    
    key_file, crt_file = generate_client_cert(name, days)
    ovpn_file = generate_ovpn(name, key_file, crt_file)
    print(f"[✓] Client '{name}' created → {ovpn_file}")

def revoke_client(name):
    client_dir = CLIENTS_DIR / name
    crt_file = client_dir / f"{name}.crt"
    
    if not crt_file.exists():
        print(f"[!] Certificate for '{name}' not found")
        return

    # Load CA
    ca_cert, ca_key = load_ca()
    
    # Load client certificate
    with open(crt_file, "rb") as f:
        client_cert = x509.load_pem_x509_certificate(f.read())
    
    # Load existing CRL
    revoked_certs = []
    if CRL_FILE.exists() and CRL_FILE.stat().st_size > 0:
        with open(CRL_FILE, "rb") as f:
            crl = x509.load_pem_x509_crl(f.read())
        revoked_certs = list(crl)
    
    # Add this certificate to revoked list
    revoked_cert = x509.RevokedCertificateBuilder(
    ).serial_number(
        client_cert.serial_number
    ).revocation_date(
        datetime.utcnow()
    ).build()
    
    revoked_certs.append(revoked_cert)
    
    # Build new CRL
    builder = x509.CertificateRevocationListBuilder()
    builder = builder.issuer_name(ca_cert.subject)
    builder = builder.last_update(datetime.utcnow())
    builder = builder.next_update(datetime.utcnow() + timedelta(days=365))
    
    for revoked in revoked_certs:
        builder = builder.add_revoked_certificate(revoked)
    
    new_crl = builder.sign(private_key=ca_key, algorithm=hashes.SHA256())
    
    # Save CRL
    with open(CRL_FILE, "wb") as f:
        f.write(new_crl.public_bytes(serialization.Encoding.PEM))
    
    # Update index.txt
    if INDEX_FILE.exists():
        lines = []
        with open(INDEX_FILE, "r") as f:
            for line in f:
                if line.strip() and f"/CN={name}" not in line:
                    lines.append(line)
        
        with open(INDEX_FILE, "w") as f:
            f.writelines(lines)
    
    # Mark as revoked in index
    with open(INDEX_FILE, "a") as f:
        expiry_str = datetime.utcnow().strftime("%y%m%d%H%M%SZ")
        serial_hex = format(client_cert.serial_number, 'X')
        f.write(f"R\t{expiry_str}\t{serial_hex}\tunknown\t/CN={name}\n")
    
    # Delete client files
    shutil.rmtree(client_dir, ignore_errors=True)
    
    log(f"Client revoked: {name}")
    print(f"[✓] Client '{name}' revoked")

def auto_clean_expired():
    removed = 0
    if not INDEX_FILE.exists():
        print("[i] No issued certificates found")
        return

    now = datetime.utcnow()
    lines = []
    
    with open(INDEX_FILE, "r") as f:
        for line in f:
            if not line.strip():
                continue
            parts = line.strip().split("\t")
            if len(parts) < 5:
                continue
                
            status, expiry_str, serial, _, cn_field = parts
            
            if status == "R":  # Already revoked, keep
                lines.append(line)
                continue
                
            try:
                expiry_dt = datetime.strptime(expiry_str, "%y%m%d%H%M%SZ")
                cn = cn_field.split("=")[-1]
                
                if expiry_dt < now:
                    print(f"[+] Revoking expired certificate: {cn}")
                    # Mark as revoked in index
                    lines.append(f"R\t{now.strftime('%y%m%d%H%M%SZ')}\t{serial}\tunknown\t{cn_field}\n")
                    
                    # Delete client directory
                    client_dir = CLIENTS_DIR / cn
                    if client_dir.exists():
                        shutil.rmtree(client_dir, ignore_errors=True)
                    
                    removed += 1
                else:
                    lines.append(line)
            except Exception as e:
                print(f"[!] Error processing line '{line}': {e}")
                lines.append(line)  # Keep malformed lines

    # Rewrite index.txt
    with open(INDEX_FILE, "w") as f:
        f.writelines(lines)

    print(f"[✓] Auto-clean complete ({removed} expired removed)")

# =========================
# MAIN
# =========================
if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("""
OpenVPN Client Management Tool
Usage:
  Create client:
    python3 generate_client.py create <name> [days]
  Revoke client:
    python3 generate_client.py revoke <name>
  Auto-clean expired:
    python3 generate_client.py clean
  Initialize CA (if needed):
    python3 generate_client.py initca
""")
        sys.exit(1)

    cmd = sys.argv[1]

    if cmd == "create":
        if len(sys.argv) < 3:
            print("Error: Client name required")
            sys.exit(1)
        name = sys.argv[2]
        days = int(sys.argv[3]) if len(sys.argv) == 4 else DEFAULT_CERT_DAYS
        create_client(name, days)

    elif cmd == "revoke":
        if len(sys.argv) < 3:
            print("Error: Client name required")
            sys.exit(1)
        revoke_client(sys.argv[2])

    elif cmd == "clean":
        auto_clean_expired()

    elif cmd == "initca":
        generate_ca()
        ensure_tls_crypt()
        print("[✓] CA and TLS crypt key initialized")

    else:
        print("Invalid command")