#!/usr/bin/env python3
import os
import secrets
import sys
import shutil
import base64
import subprocess
from pathlib import Path
from datetime import datetime, timedelta

# cryptography imports
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
SERVER_PRIVATE_IP = "10.8.0.1"
SERVER_NETWORK = "10.8.0.0"
SERVER_NETMASK = "255.255.255.0"
SERVER_PORT = 1194
PROTOCOL = "udp"
CIPHER = "AES-256-CBC"
AUTH = "SHA256"

BASE_DIR = Path("openvpn")
CA_DIR = BASE_DIR / "ca"
CLIENTS_DIR = BASE_DIR / "clients"
SERVER_DIR = BASE_DIR / "server"
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

def run_command(cmd, description=""):
    """Run shell command with error handling"""
    if description:
        print(f"[+] {description}")
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        if result.returncode != 0:
            print(f"[!] Command failed: {cmd}")
            print(f"    Error: {result.stderr}")
            return False
        return True
    except Exception as e:
        print(f"[!] Error running command '{cmd}': {e}")
        return False

# =========================
# CA GENERATION
# =========================
def generate_ca(days=3650):
    """Generate a new CA certificate if one doesn't exist"""
    if CA_CERT.exists() and CA_KEY.exists():
        print("[i] CA already exists, skipping generation")
        return True
    
    secure_mkdir(CA_DIR)
    
    # Generate CA key
    print("[+] Generating CA private key (4096-bit RSA)...")
    ca_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=4096,
    )
    
    # Generate CA certificate
    print("[+] Generating CA certificate...")
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
    
    print(f"[✓] Generated new CA certificate (valid for {days} days)")
    log("CA generated")
    return True

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
# DIFFIE-HELLMAN PARAMETERS
# =========================
def ensure_dh_params():
    dh_file = SERVER_DIR / "dh.pem"
    if dh_file.exists():
        return True
    
    print("[+] Generating Diffie-Hellman parameters (2048-bit)...")
    print("    This may take a few minutes on slower systems...")
    
    # Try to generate with openssl (faster)
    if run_command(f"openssl dhparam -out {dh_file} 2048", "Generating DH parameters with OpenSSL"):
        os.chmod(dh_file, 0o600)
        print("[✓] Diffie-Hellman parameters generated")
        return True
    
    # Fallback to Python implementation (slower)
    print("[+] Falling back to Python implementation...")
    try:
        # This is a simplified version - in production you might want to use cryptography library
        # or keep the OpenSSL dependency
        subprocess.run(["openssl", "dhparam", "-out", str(dh_file), "2048"], 
                      check=True, capture_output=True)
        os.chmod(dh_file, 0o600)
        print("[✓] Diffie-Hellman parameters generated")
        return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        print("[!] Failed to generate DH parameters. Please install OpenSSL:")
        print("    Ubuntu/Debian: sudo apt-get install openssl")
        print("    CentOS/RHEL: sudo yum install openssl")
        print("    Or create manually: openssl dhparam -out dh.pem 2048")
        return False

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
# SERVER CERTIFICATE
# =========================
def generate_server_cert(days=3650):
    """Generate server certificate for OpenVPN server"""
    secure_mkdir(SERVER_DIR)
    
    # Ensure CA exists
    if not generate_ca():
        return None
    
    # Load CA
    ca_cert, ca_key = load_ca()
    
    # Generate server key
    print("[+] Generating server private key (4096-bit RSA)...")
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=4096,
    )
    
    # Save server key
    key_file = SERVER_DIR / "server.key"
    with open(key_file, "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=NoEncryption(),
        ))
    os.chmod(key_file, 0o600)
    
    # Build server certificate
    print("[+] Generating server certificate...")
    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "OpenVPN Server"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "OpenVPN Server"),
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
                key_encipherment=True,
                content_commitment=False,
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
            x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )
    
    # Save server certificate
    cert_file = SERVER_DIR / "server.crt"
    with open(cert_file, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    
    # Update index.txt
    with open(INDEX_FILE, "a") as f:
        expiry_str = (datetime.utcnow() + timedelta(days=days)).strftime("%y%m%d%H%M%SZ")
        serial_hex = format(cert.serial_number, 'X')
        f.write(f"V\t{expiry_str}\t{serial_hex}\tunknown\t/CN=OpenVPN Server\n")
    
    print("[✓] Server certificate generated")
    log("Server certificate generated")
    return key_file, cert_file

# =========================
# SERVER CONFIGURATION
# =========================
def generate_server_config():
    """Generate OpenVPN server configuration file"""
    if not (SERVER_DIR / "server.crt").exists() or not (SERVER_DIR / "server.key").exists():
        print("[!] Server certificate not found. Generating server certificate first...")
        if not generate_server_cert():
            print("[!] Failed to generate server certificate")
            return None
    
    # Ensure required files exist
    ensure_tls_crypt()
    if not ensure_dh_params():
        print("[!] Cannot generate server config without DH parameters")
        return None
    
    # Paths to server files
    server_cert = SERVER_DIR / "server.crt"
    server_key = SERVER_DIR / "server.key"
    dh_file = SERVER_DIR / "dh.pem"
    
    # Read files for embedding
    with open(CA_CERT, "r") as f:
        ca_cert_content = f.read().strip()
    
    with open(server_cert, "r") as f:
        server_cert_content = f.read().strip()
    
    with open(server_key, "r") as f:
        server_key_content = f.read().strip()
    
    with open(dh_file, "r") as f:
        dh_content = f.read().strip()
    
    with open(TLS_CRYPT_KEY, "rb") as f:
        tls_key_bin = f.read()
    tls_key_b64 = base64.b64encode(tls_key_bin).decode('ascii')
    
    # Generate server configuration
    server_config_file = SERVER_DIR / "server.ovpn"
    
    server_config = f"""# OpenVPN Server Configuration
# Generated: {datetime.utcnow().isoformat()}

# Network Configuration
port {SERVER_PORT}
proto {PROTOCOL}
dev tun

# Encryption Settings
cipher {CIPHER}
auth {AUTH}
tls-crypt tls-crypt.key

# Certificate Files
<ca>
{ca_cert_content}
</ca>

<cert>
{server_cert_content}
</cert>

<key>
{server_key_content}
</key>

<dh>
{dh_content}
</dh>

<tls-crypt>
{tls_key_b64}
</tls-crypt>

# Network Settings
server {SERVER_NETWORK} {SERVER_NETMASK}
ifconfig-pool-persist ipp.txt
push "route 0.0.0.0 0.0.0.0"
push "redirect-gateway def1 bypass-dhcp"
push "dhcp-option DNS 8.8.8.8"
push "dhcp-option DNS 8.8.4.4"
push "block-outside-dns"

# Security
keepalive 10 120
user nobody
group nogroup
persist-key
persist-tun
crl-verify {CRL_FILE.relative_to(BASE_DIR)}
explicit-exit-notify 1

# Logging
status openvpn-status.log
verb 3

# Performance
sndbuf 393216
rcvbuf 393216
push "sndbuf 393216"
push "rcvbuf 393216"

# Security Hardening
remote-cert-tls client
tls-version-min 1.2
tls-cipher TLS-ECDHE-RSA-WITH-AES-256-GCM-SHA384:TLS-ECDHE-RSA-WITH-AES-256-CBC-SHA
"""
    
    server_config_file.write_text(server_config)
    
    # Generate separate file with just tls-crypt key for server
    tls_server_file = SERVER_DIR / "tls-crypt.key"
    with open(tls_server_file, "wb") as f:
        f.write(tls_key_bin)
    os.chmod(tls_server_file, 0o600)
    
    # Generate systemd service file (for Linux)
    if os.name == 'posix':
        service_file = SERVER_DIR / "openvpn-server.service"
        service_content = f"""[Unit]
Description=OpenVPN Server
After=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/sbin/openvpn --config {server_config_file}
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
"""
        service_file.write_text(service_content)
    
    print(f"[✓] Server configuration generated → {server_config_file}")
    log("Server configuration generated")
    
    # Print setup instructions
    print("\n" + "="*60)
    print("SERVER SETUP INSTRUCTIONS:")
    print("="*60)
    print("1. Copy these files to your OpenVPN server:")
    print(f"   - {server_config_file}")
    print(f"   - {SERVER_DIR / 'tls-crypt.key'}")
    print(f"   - {CA_CERT}")
    print(f"   - {CRL_FILE}")
    print("\n2. On the server, install OpenVPN:")
    print("   Ubuntu/Debian: sudo apt install openvpn")
    print("   CentOS/RHEL: sudo yum install openvpn")
    print("\n3. Start the server:")
    print(f"   sudo openvpn --config {server_config_file.name}")
    print("\n4. For auto-start on Linux:")
    print(f"   sudo cp {SERVER_DIR / 'openvpn-server.service'} /etc/systemd/system/")
    print("   sudo systemctl daemon-reload")
    print("   sudo systemctl enable openvpn-server")
    print("   sudo systemctl start openvpn-server")
    print("\n5. Configure firewall to allow UDP port 1194")
    print("="*60)
    
    return server_config_file

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

    ovpn_content = f"""# OpenVPN Client Configuration
# Generated: {datetime.utcnow().isoformat()}
# Client: {client_name}

client
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

# Uncomment for extra security (if server has compression disabled)
# comp-lzo no

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
    
    # Also create a standalone tls-crypt.key file for clients that need it
    tls_client_file = client_dir / "tls-crypt.key"
    with open(tls_client_file, "wb") as f:
        f.write(tls_key_bin)
    os.chmod(tls_client_file, 0o600)
    
    return ovpn_file

# =========================
# CLIENT MANAGEMENT
# =========================
def create_client(name, days=DEFAULT_CERT_DAYS):
    # Ensure CA exists
    generate_ca()
    ensure_tls_crypt()
    
    print(f"[+] Creating client '{name}'...")
    key_file, crt_file = generate_client_cert(name, days)
    ovpn_file = generate_ovpn(name, key_file, crt_file)
    print(f"[✓] Client '{name}' created → {ovpn_file}")
    
    # Print client instructions
    print(f"\nClient '{name}' setup:")
    print(f"1. Copy {ovpn_file} to your device")
    print("2. Install OpenVPN client:")
    print("   - Windows: https://openvpn.net/community-downloads/")
    print("   - macOS: Tunnelblick (https://tunnelblick.net)")
    print("   - Linux: sudo apt install openvpn")
    print("   - Android/iOS: OpenVPN Connect from app store")
    print(f"3. Import {ovpn_file.name} into your OpenVPN client")
    print("4. Connect to the VPN")
    
    return ovpn_file

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
    print(f"[✓] Client '{name}' revoked and added to CRL")

def list_clients():
    """List all issued clients"""
    if not INDEX_FILE.exists():
        print("[i] No clients have been issued")
        return
    
    print("\n" + "="*80)
    print("ISSUED CLIENTS")
    print("="*80)
    print(f"{'Status':<8} {'Client Name':<20} {'Expires':<20} {'Serial':<16}")
    print("-"*80)
    
    with open(INDEX_FILE, "r") as f:
        for line in f:
            if not line.strip():
                continue
            parts = line.strip().split("\t")
            if len(parts) < 5:
                continue
                
            status, expiry_str, serial, _, cn_field = parts
            cn = cn_field.split("=")[-1]
            
            try:
                expiry_dt = datetime.strptime(expiry_str, "%y%m%d%H%M%SZ")
                days_remaining = (expiry_dt - datetime.utcnow()).days
                
                status_display = "VALID" if status == "V" else "REVOKED"
                expiry_display = expiry_dt.strftime("%Y-%m-%d")
                
                if status == "V":
                    if days_remaining < 30:
                        expiry_display += f" ⚠ ({days_remaining} days)"
                    else:
                        expiry_display += f" ({days_remaining} days)"
                
                print(f"{status_display:<8} {cn:<20} {expiry_display:<20} {serial:<16}")
            except Exception as e:
                print(f"[!] Error parsing line: {line.strip()}")
    
    print("="*80)

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
                    print(f"[+] Auto-revoking expired certificate: {cn}")
                    # Don't call revoke_client to avoid recursion, just mark as revoked
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

    print(f"[✓] Auto-clean complete ({removed} expired certificates removed)")
    log(f"Auto-clean removed {removed} expired certificates")

# =========================
# INITIALIZATION
# =========================
def initialize_all():
    """Initialize complete OpenVPN setup"""
    print("[+] Initializing complete OpenVPN setup...")
    
    # Generate CA
    if not generate_ca():
        print("[!] Failed to generate CA")
        return False
    
    # Generate TLS crypt key
    ensure_tls_crypt()
    
    # Generate server certificate
    if not generate_server_cert():
        print("[!] Failed to generate server certificate")
        return False
    
    # Generate server configuration
    if not generate_server_config():
        print("[!] Failed to generate server configuration")
        return False
    
    print("\n" + "="*60)
    print("[✓] COMPLETE OPENVPN SETUP INITIALIZED")
    print("="*60)
    print("\nNext steps:")
    print("1. Update SERVER_PUBLIC_IP in the script with your server's actual IP")
    print("2. Copy server files from 'openvpn/server/' to your OpenVPN server")
    print("3. Start the OpenVPN server")
    print("4. Create clients with: python3 generate_client.py create <clientname>")
    print("="*60)
    
    return True

# =========================
# MAIN
# =========================
if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("""
OpenVPN Client & Server Management Tool
========================================

Usage:
  Initialize complete setup:
    python3 generate_client.py initall

  Server management:
    python3 generate_client.py genserver    - Generate server certificate & config
    python3 generate_client.py gencfg       - Generate server configuration only

  Client management:
    python3 generate_client.py create <name> [days]  - Create new client
    python3 generate_client.py revoke <name>         - Revoke client
    python3 generate_client.py list                  - List all clients
    python3 generate_client.py clean                 - Auto-clean expired clients

  CA management:
    python3 generate_client.py initca                - Initialize CA only

  Configuration:
    Edit the SERVER_PUBLIC_IP variable in the script to match your server's IP

Examples:
  python3 generate_client.py initall                # Complete setup
  python3 generate_client.py create alice 365       # 1-year client
  python3 generate_client.py revoke bob             # Revoke bob's access
  python3 generate_client.py list                   # Show all clients
""")
        sys.exit(1)

    cmd = sys.argv[1]

    if cmd == "initall":
        initialize_all()

    elif cmd == "genserver":
        generate_server_cert()
        generate_server_config()

    elif cmd == "gencfg":
        generate_server_config()

    elif cmd == "create":
        if len(sys.argv) < 3:
            print("Error: Client name required")
            print("Usage: python3 generate_client.py create <name> [days]")
            sys.exit(1)
        name = sys.argv[2]
        days = int(sys.argv[3]) if len(sys.argv) == 4 else DEFAULT_CERT_DAYS
        create_client(name, days)

    elif cmd == "revoke":
        if len(sys.argv) < 3:
            print("Error: Client name required")
            print("Usage: python3 generate_client.py revoke <name>")
            sys.exit(1)
        revoke_client(sys.argv[2])

    elif cmd == "list":
        list_clients()

    elif cmd == "clean":
        auto_clean_expired()

    elif cmd == "initca":
        generate_ca()
        ensure_tls_crypt()
        print("[✓] CA and TLS crypt key initialized")

    else:
        print(f"Invalid command: {cmd}")
        print("Use without arguments for help.")