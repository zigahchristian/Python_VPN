#!/usr/bin/env python3
import os
import secrets
import sys
import shutil
import base64
import subprocess
import zipfile
import json
from pathlib import Path
from datetime import datetime, timedelta
from getpass import getpass
import threading
import time
import schedule
import atexit
from typing import Dict, List

# cryptography imports
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import (
    BestAvailableEncryption, NoEncryption, PrivateFormat
)
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

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
PASSWORDS_FILE = BASE_DIR / "passwords.json"  # Stores encrypted passwords
EXPIRY_TRACKER_FILE = BASE_DIR / "expiry_tracker.json"  # Tracks certificates for auto-delete

CA_CERT = CA_DIR / "ca.crt"
CA_KEY = CA_DIR / "ca.key"
CRL_FILE = CA_DIR / "crl.pem"

DEFAULT_CERT_DAYS = 365
AUTO_DELETE_ENABLED = True  # Set to False to disable auto-delete
AUTO_DELETE_CHECK_INTERVAL = 3600  # Check every hour (in seconds)
AUTO_DELETE_GRACE_PERIOD = 7  # Days after expiry before deletion

# =========================
# EXPIRY TRACKER
# =========================
class ExpiryTracker:
    def __init__(self):
        self.tracker_file = EXPIRY_TRACKER_FILE
        self.tracker_data = self._load_tracker()
    
    def _load_tracker(self) -> Dict:
        """Load expiry tracker data from file"""
        if not self.tracker_file.exists():
            return {}
        
        try:
            with open(self.tracker_file, 'r') as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError):
            return {}
    
    def _save_tracker(self):
        """Save expiry tracker data to file"""
        BASE_DIR.mkdir(exist_ok=True)
        with open(self.tracker_file, 'w') as f:
            json.dump(self.tracker_data, f, indent=2, default=str)
    
    def add_certificate(self, client_name: str, expiry_date: datetime, cert_serial: str):
        """Add a certificate to expiry tracking"""
        self.tracker_data[client_name] = {
            'expiry_date': expiry_date.isoformat(),
            'cert_serial': cert_serial,
            'added_date': datetime.utcnow().isoformat(),
            'auto_delete_enabled': AUTO_DELETE_ENABLED,
            'notified': False
        }
        self._save_tracker()
        log(f"Added {client_name} to expiry tracker (expires: {expiry_date.date()})")
    
    def remove_certificate(self, client_name: str):
        """Remove a certificate from expiry tracking"""
        if client_name in self.tracker_data:
            del self.tracker_data[client_name]
            self._save_tracker()
            log(f"Removed {client_name} from expiry tracker")
            return True
        return False
    
    def get_expiring_certs(self, days_threshold: int = 30) -> List[Dict]:
        """Get certificates expiring within specified days"""
        expiring = []
        now = datetime.utcnow()
        
        for client_name, data in self.tracker_data.items():
            if 'expiry_date' not in data:
                continue
                
            expiry_date = datetime.fromisoformat(data['expiry_date'])
            days_remaining = (expiry_date - now).days
            
            if 0 < days_remaining <= days_threshold:
                expiring.append({
                    'client_name': client_name,
                    'expiry_date': expiry_date,
                    'days_remaining': days_remaining,
                    'cert_serial': data.get('cert_serial', 'N/A')
                })
        
        return sorted(expiring, key=lambda x: x['expiry_date'])
    
    def get_expired_certs(self, grace_period: int = AUTO_DELETE_GRACE_PERIOD) -> List[Dict]:
        """Get certificates that have expired (with optional grace period)"""
        expired = []
        now = datetime.utcnow()
        
        for client_name, data in self.tracker_data.items():
            if 'expiry_date' not in data:
                continue
                
            expiry_date = datetime.fromisoformat(data['expiry_date'])
            days_expired = (now - expiry_date).days
            
            if days_expired >= grace_period:
                expired.append({
                    'client_name': client_name,
                    'expiry_date': expiry_date,
                    'days_expired': days_expired,
                    'cert_serial': data.get('cert_serial', 'N/A'),
                    'auto_delete_enabled': data.get('auto_delete_enabled', True)
                })
        
        return sorted(expired, key=lambda x: x['expiry_date'])
    
    def update_notification_status(self, client_name: str, notified: bool = True):
        """Update notification status for a certificate"""
        if client_name in self.tracker_data:
            self.tracker_data[client_name]['notified'] = notified
            self._save_tracker()

# Initialize expiry tracker
expiry_tracker = ExpiryTracker()

# =========================
# PASSWORD ENCRYPTION UTILITIES
# =========================
class PasswordManager:
    def __init__(self, master_password=None):
        self.master_password = master_password
        self.passwords_file = PASSWORDS_FILE
        
    def derive_key(self, salt):
        """Derive encryption key from master password"""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,  # 256-bit key
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        return kdf.derive(self.master_password.encode())
    
    def encrypt_password(self, password):
        """Encrypt a password"""
        salt = secrets.token_bytes(16)
        key = self.derive_key(salt)
        iv = secrets.token_bytes(16)
        
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        encrypted = encryptor.update(password.encode()) + encryptor.finalize()
        
        return base64.b64encode(salt + iv + encrypted).decode('ascii')
    
    def decrypt_password(self, encrypted_password):
        """Decrypt a password"""
        data = base64.b64decode(encrypted_password)
        salt = data[:16]
        iv = data[16:32]
        encrypted = data[32:]
        
        key = self.derive_key(salt)
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted = decryptor.update(encrypted) + decryptor.finalize()
        
        return decrypted.decode('utf-8')
    
    def save_password(self, client_name, password):
        """Save encrypted password to file"""
        if not self.master_password:
            raise ValueError("Master password not set")
        
        # Load existing passwords
        passwords = self.load_all_passwords()
        
        # Encrypt and save new password
        encrypted = self.encrypt_password(password)
        passwords[client_name] = encrypted
        
        # Save back to file
        with open(self.passwords_file, 'w') as f:
            json.dump(passwords, f, indent=2)
        
        return encrypted
    
    def load_all_passwords(self):
        """Load all passwords from file"""
        if not self.passwords_file.exists():
            return {}
        
        with open(self.passwords_file, 'r') as f:
            return json.load(f)
    
    def get_password(self, client_name):
        """Get decrypted password for client"""
        if not self.master_password:
            raise ValueError("Master password not set")
        
        passwords = self.load_all_passwords()
        if client_name not in passwords:
            return None
        
        return self.decrypt_password(passwords[client_name])
    
    def remove_password(self, client_name):
        """Remove password for client"""
        passwords = self.load_all_passwords()
        if client_name in passwords:
            del passwords[client_name]
            with open(self.passwords_file, 'w') as f:
                json.dump(passwords, f, indent=2)
            return True
        return False

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

def generate_strong_password(length=16):
    """Generate a strong random password"""
    alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*"
    return ''.join(secrets.choice(alphabet) for _ in range(length))

def get_master_password():
    """Prompt for master password for password encryption"""
    print("\n" + "="*60)
    print("PASSWORD ENCRYPTION SETUP")
    print("="*60)
    print("A master password is required to encrypt/decrypt client passwords.")
    print("This password will NOT be stored. You must enter it each time.")
    print("="*60)
    
    master_pwd = getpass("Enter master password: ")
    confirm_pwd = getpass("Confirm master password: ")
    
    if master_pwd != confirm_pwd:
        print("[!] Passwords do not match!")
        return None
    
    if len(master_pwd) < 8:
        print("[!] Master password must be at least 8 characters!")
        return None
    
    return master_pwd

# =========================
# AUTO-DELETE SCHEDULER
# =========================
class AutoDeleteScheduler:
    def __init__(self):
        self.running = False
        self.thread = None
    
    def start(self):
        """Start the auto-delete scheduler"""
        if self.running:
            return
        
        self.running = True
        self.thread = threading.Thread(target=self._run_scheduler, daemon=True)
        self.thread.start()
        print(f"[✓] Auto-delete scheduler started (checks every {AUTO_DELETE_CHECK_INTERVAL//3600} hours)")
        log("Auto-delete scheduler started")
    
    def stop(self):
        """Stop the auto-delete scheduler"""
        self.running = False
        if self.thread:
            self.thread.join(timeout=2)
    
    def _run_scheduler(self):
        """Main scheduler loop"""
        while self.running:
            try:
                self.check_and_delete_expired()
                time.sleep(AUTO_DELETE_CHECK_INTERVAL)
            except Exception as e:
                log(f"Auto-delete scheduler error: {e}")
                time.sleep(60)  # Wait a minute before retrying on error
    
    def check_and_delete_expired(self):
        """Check for and delete expired certificates"""
        if not AUTO_DELETE_ENABLED:
            return
        
        expired_certs = expiry_tracker.get_expired_certs()
        
        if not expired_certs:
            return
        
        print(f"\n[+] Auto-delete: Checking {len(expired_certs)} expired certificates...")
        
        deleted_count = 0
        for cert in expired_certs:
            if not cert.get('auto_delete_enabled', True):
                continue
                
            client_name = cert['client_name']
            days_expired = cert['days_expired']
            
            print(f"    Deleting {client_name} (expired {days_expired} days ago)...")
            
            # Revoke certificate
            if revoke_client_internal(client_name, auto_delete=True):
                # Remove from expiry tracker
                expiry_tracker.remove_certificate(client_name)
                deleted_count += 1
                log(f"Auto-deleted expired client: {client_name} (expired {days_expired} days)")
        
        if deleted_count > 0:
            print(f"[✓] Auto-delete: Removed {deleted_count} expired certificates")
    
    def manual_check_now(self):
        """Manually trigger a check for expired certificates"""
        print("\n" + "="*60)
        print("MANUAL AUTO-DELETE CHECK")
        print("="*60)
        self.check_and_delete_expired()

# Initialize auto-delete scheduler
auto_delete_scheduler = AutoDeleteScheduler()

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
        x509.NameAttribute(NameOID.STATE_OR_PROVince_NAME, "California"),
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

    # Add to expiry tracker
    expiry_date = datetime.utcnow() + timedelta(days=days)
    expiry_tracker.add_certificate(client_name, expiry_date, serial_hex)
    
    log(f"Client issued: {client_name} ({days} days)")
    return key_file, crt_file, cert.serial_number

# =========================
# OVPN GENERATION WITH PASSWORD
# =========================
def generate_ovpn(client_name, key_file, crt_file, password=None):
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

    # Create auth file if password is provided
    auth_content = ""
    if password:
        auth_file = client_dir / f"{client_name}.auth"
        auth_content = f"{client_name}\n{password}"
        auth_file.write_text(auth_content)
        os.chmod(auth_file, 0o600)
        
        # Create embedded auth file in ovpn
        auth_embedded = f"""
<auth-user-pass>
{client_name}
{password}
</auth-user-pass>
"""
    else:
        auth_embedded = ""

    ovpn_content = f"""# OpenVPN Client Configuration
# Generated: {datetime.utcnow().isoformat()}
# Client: {client_name}
# Auto-delete: {'Enabled' if AUTO_DELETE_ENABLED else 'Disabled'}
# Expires: {(datetime.utcnow() + timedelta(days=DEFAULT_CERT_DAYS)).strftime('%Y-%m-%d')}

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
    
    # Add auth-user-pass if password is set
    if password:
        ovpn_content += f"""
# Username/Password Authentication
auth-user-pass {client_name}.auth
"""
    
    ovpn_file.write_text(ovpn_content)
    os.chmod(ovpn_file, 0o600)
    
    # Also create a standalone tls-crypt.key file for clients that need it
    tls_client_file = client_dir / "tls-crypt.key"
    with open(tls_client_file, "wb") as f:
        f.write(tls_key_bin)
    os.chmod(tls_client_file, 0o600)
    
    return ovpn_file

def create_zip_package(client_name, password=None):
    """Create a ZIP package with all client files"""
    client_dir = CLIENTS_DIR / client_name
    zip_file = client_dir / f"{client_name}_openvpn_package.zip"
    
    with zipfile.ZipFile(zip_file, 'w', zipfile.ZIP_DEFLATED) as zipf:
        # Add ovpn file
        ovpn_file = client_dir / f"{client_name}.ovpn"
        if ovpn_file.exists():
            zipf.write(ovpn_file, ovpn_file.name)
        
        # Add certificate files
        for ext in ['.crt', '.key']:
            file_path = client_dir / f"{client_name}{ext}"
            if file_path.exists():
                zipf.write(file_path, file_path.name)
        
        # Add auth file if exists
        auth_file = client_dir / f"{client_name}.auth"
        if auth_file.exists():
            zipf.write(auth_file, auth_file.name)
        
        # Add tls-crypt key
        tls_file = client_dir / "tls-crypt.key"
        if tls_file.exists():
            zipf.write(tls_file, "tls-crypt.key")
        
        # Add README
        readme_content = f"""OpenVPN Client Package for {client_name}

Files included:
1. {client_name}.ovpn - Main OpenVPN configuration file
2. {client_name}.crt - Client certificate
3. {client_name}.key - Client private key
4. tls-crypt.key - TLS encryption key
{f"5. {client_name}.auth - Username/password file" if password else ""}

Setup Instructions:
1. Extract all files to a secure location
2. Install OpenVPN client on your device
3. Import {client_name}.ovpn file into OpenVPN
{f"4. When prompted, use username '{client_name}' and the provided password" if password else ""}
5. Connect to the VPN

Generated: {datetime.utcnow().isoformat()}
Certificate Expires: {(datetime.utcnow() + timedelta(days=DEFAULT_CERT_DAYS)).strftime('%Y-%m-%d')}
Auto-delete: {'Enabled - Certificate will be automatically deleted after expiration' if AUTO_DELETE_ENABLED else 'Disabled'}
"""
        
        zipf.writestr("README.txt", readme_content)
    
    print(f"[✓] ZIP package created: {zip_file}")
    return zip_file

# =========================
# CLIENT MANAGEMENT
# =========================
def create_client(name, days=DEFAULT_CERT_DAYS, use_password=False, custom_password=None):
    # Ensure CA exists
    generate_ca()
    ensure_tls_crypt()
    
    print(f"[+] Creating client '{name}'...")
    
    # Generate password if needed
    password = None
    if use_password:
        if custom_password:
            password = custom_password
        else:
            password = generate_strong_password()
            print(f"[+] Generated password: {password}")
    
    # Generate certificates
    key_file, crt_file, serial_number = generate_client_cert(name, days)
    
    # Generate OVPN file with optional password
    ovpn_file = generate_ovpn(name, key_file, crt_file, password)
    
    # Create ZIP package
    zip_file = create_zip_package(name, password)
    
    # Save password if provided
    if password:
        master_pwd = get_master_password()
        if master_pwd:
            pm = PasswordManager(master_pwd)
            pm.save_password(name, password)
            print(f"[✓] Password saved (encrypted)")
        else:
            print(f"[!] Password NOT saved (master password incorrect)")
    
    print(f"[✓] Client '{name}' created successfully!")
    print(f"    OVPN file: {ovpn_file}")
    print(f"    ZIP package: {zip_file}")
    print(f"    Auto-delete: {'Enabled' if AUTO_DELETE_ENABLED else 'Disabled'}")
    
    # Display connection info
    print("\n" + "="*60)
    print("CLIENT CONNECTION INFORMATION:")
    print("="*60)
    print(f"Client Name: {name}")
    print(f"Server: {SERVER_PUBLIC_IP}:{SERVER_PORT}")
    print(f"Protocol: {PROTOCOL}")
    if password:
        print(f"Username: {name}")
        print(f"Password: {password}")
        print("IMPORTANT: Save this password! It cannot be recovered!")
    else:
        print("Authentication: Certificate only (no username/password)")
    print(f"Valid until: {(datetime.utcnow() + timedelta(days=days)).strftime('%Y-%m-%d')}")
    print(f"Auto-delete after: {(datetime.utcnow() + timedelta(days=days + AUTO_DELETE_GRACE_PERIOD)).strftime('%Y-%m-%d')}")
    print("="*60)
    
    return ovpn_file, zip_file, password

def revoke_client_internal(name, auto_delete=False):
    """Internal revoke function used by both manual revoke and auto-delete"""
    client_dir = CLIENTS_DIR / name
    crt_file = client_dir / f"{name}.crt"
    
    if not crt_file.exists():
        if not auto_delete:
            print(f"[!] Certificate for '{name}' not found")
        return False

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
    
    # Remove password from storage
    try:
        master_pwd = get_master_password()
        if master_pwd:
            pm = PasswordManager(master_pwd)
            pm.remove_password(name)
            if not auto_delete:
                print("[✓] Password removed from storage")
    except:
        pass
    
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
    
    if not auto_delete:
        log(f"Client revoked: {name}")
        print(f"[✓] Client '{name}' revoked and added to CRL")
    else:
        log(f"Client auto-deleted: {name}")
    
    return True

def revoke_client(name):
    """Manual revocation of client"""
    if revoke_client_internal(name, auto_delete=False):
        # Remove from expiry tracker
        expiry_tracker.remove_certificate(name)
        print(f"[✓] Removed {name} from expiry tracking")

def list_clients():
    """List all issued clients"""
    if not INDEX_FILE.exists():
        print("[i] No clients have been issued")
        return
    
    print("\n" + "="*100)
    print("ISSUED CLIENTS")
    print("="*100)
    print(f"{'Status':<8} {'Client Name':<20} {'Expires':<20} {'Serial':<16} {'Password':<10} {'Auto-Delete':<12}")
    print("-"*100)
    
    # Try to load passwords
    has_passwords = False
    pm = None
    if PASSWORDS_FILE.exists():
        try:
            master_pwd = get_master_password()
            if master_pwd:
                pm = PasswordManager(master_pwd)
                has_passwords = True
        except:
            pass
    
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
                    if days_remaining < 0:
                        status_display = "EXPIRED"
                        expiry_display += f" (EXPIRED {-days_remaining} days ago)"
                    elif days_remaining < 7:
                        expiry_display += f" ⚠ ({days_remaining} days)"
                    else:
                        expiry_display += f" ({days_remaining} days)"
                
                # Check if password exists
                password_info = "No"
                if has_passwords and pm:
                    if pm.get_password(cn):
                        password_info = "Yes"
                
                # Check auto-delete status
                auto_delete_info = "N/A"
                tracker_data = expiry_tracker.tracker_data.get(cn, {})
                if tracker_data:
                    auto_delete_info = "Yes" if tracker_data.get('auto_delete_enabled', AUTO_DELETE_ENABLED) else "No"
                
                print(f"{status_display:<8} {cn:<20} {expiry_display:<20} {serial:<16} {password_info:<10} {auto_delete_info:<12}")
            except Exception as e:
                print(f"[!] Error parsing line: {line.strip()}")
    
    print("="*100)
    
    # Show auto-delete summary
    if AUTO_DELETE_ENABLED:
        print("\nAUTO-DELETE STATUS:")
        print(f"  Enabled: {AUTO_DELETE_ENABLED}")
        print(f"  Check interval: {AUTO_DELETE_CHECK_INTERVAL//3600} hours")
        print(f"  Grace period: {AUTO_DELETE_GRACE_PERIOD} days after expiry")
        
        expiring = expiry_tracker.get_expiring_certs(days_threshold=30)
        if expiring:
            print(f"\n  Certificates expiring soon (next 30 days): {len(expiring)}")
            for cert in expiring[:5]:  # Show first 5
                print(f"    • {cert['client_name']}: {cert['days_remaining']} days left")
            if len(expiring) > 5:
                print(f"    ... and {len(expiring) - 5} more")
        
        expired = expiry_tracker.get_expired_certs(grace_period=0)
        if expired:
            print(f"\n  ⚠ Expired certificates: {len(expired)}")
            for cert in expired[:5]:  # Show first 5
                print(f"    • {cert['client_name']}: expired {cert['days_expired']} days ago")

def recover_password(client_name):
    """Recover password for a client"""
    if not PASSWORDS_FILE.exists():
        print("[!] No passwords stored")
        return
    
    master_pwd = get_master_password()
    if not master_pwd:
        print("[!] Master password incorrect")
        return
    
    pm = PasswordManager(master_pwd)
    password = pm.get_password(client_name)
    
    if password:
        print("\n" + "="*60)
        print(f"PASSWORD RECOVERY FOR: {client_name}")
        print("="*60)
        print(f"Username: {client_name}")
        print(f"Password: {password}")
        print("="*60)
    else:
        print(f"[!] No password found for client '{client_name}'")

def auto_clean_expired():
    """Legacy function for backward compatibility"""
    print("[i] Using new auto-delete system. Running manual check...")
    auto_delete_scheduler.manual_check_now()

def check_expiry_status():
    """Check and display expiry status of all certificates"""
    print("\n" + "="*60)
    print("CERTIFICATE EXPIRY STATUS")
    print("="*60)
    
    if not INDEX_FILE.exists():
        print("[i] No certificates issued")
        return
    
    # Get all valid certificates
    valid_certs = []
    with open(INDEX_FILE, "r") as f:
        for line in f:
            if not line.strip():
                continue
            parts = line.strip().split("\t")
            if len(parts) < 5:
                continue
            
            status, expiry_str, serial, _, cn_field = parts
            if status != "V":
                continue
            
            cn = cn_field.split("=")[-1]
            try:
                expiry_dt = datetime.strptime(expiry_str, "%y%m%d%H%M%SZ")
                days_remaining = (expiry_dt - datetime.utcnow()).days
                
                valid_certs.append({
                    'name': cn,
                    'expiry_date': expiry_dt,
                    'days_remaining': days_remaining,
                    'serial': serial
                })
            except:
                continue
    
    if not valid_certs:
        print("[i] No valid certificates found")
        return
    
    # Sort by days remaining
    valid_certs.sort(key=lambda x: x['days_remaining'])
    
    # Group by status
    expired = [c for c in valid_certs if c['days_remaining'] < 0]
    critical = [c for c in valid_certs if 0 <= c['days_remaining'] < 7]
    warning = [c for c in valid_certs if 7 <= c['days_remaining'] < 30]
    ok = [c for c in valid_certs if c['days_remaining'] >= 30]
    
    print(f"Total valid certificates: {len(valid_certs)}")
    print(f"  🔴 Expired: {len(expired)}")
    print(f"  🟠 Critical (<7 days): {len(critical)}")
    print(f"  🟡 Warning (7-30 days): {len(warning)}")
    print(f"  🟢 OK (>30 days): {len(ok)}")
    
    if expired:
        print("\nEXPIRED CERTIFICATES:")
        for cert in expired:
            print(f"  • {cert['name']}: expired {-cert['days_remaining']} days ago")
    
    if critical:
        print("\nCRITICAL (Expiring in <7 days):")
        for cert in critical:
            print(f"  • {cert['name']}: {cert['days_remaining']} days left")
    
    if AUTO_DELETE_ENABLED:
        print(f"\nAuto-delete is ENABLED")
        print(f"Certificates will be deleted {AUTO_DELETE_GRACE_PERIOD} days after expiry")
    
    print("="*60)

def toggle_auto_delete(client_name=None, enable=True):
    """Toggle auto-delete for a specific client or globally"""
    if client_name:
        # Toggle for specific client
        if client_name in expiry_tracker.tracker_data:
            expiry_tracker.tracker_data[client_name]['auto_delete_enabled'] = enable
            expiry_tracker._save_tracker()
            status = "enabled" if enable else "disabled"
            print(f"[✓] Auto-delete {status} for client '{client_name}'")
            log(f"Auto-delete {status} for client: {client_name}")
        else:
            print(f"[!] Client '{client_name}' not found in expiry tracker")
    else:
        # Toggle globally
        global AUTO_DELETE_ENABLED
        AUTO_DELETE_ENABLED = enable
        status = "enabled" if enable else "disabled"
        print(f"[✓] Global auto-delete {status}")
        log(f"Global auto-delete {status}")

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
    
    # Start auto-delete scheduler
    if AUTO_DELETE_ENABLED:
        auto_delete_scheduler.start()
    
    print("\n" + "="*60)
    print("[✓] COMPLETE OPENVPN SETUP INITIALIZED")
    print("="*60)
    print("\nAuto-delete features:")
    print(f"  • Auto-delete: {'ENABLED' if AUTO_DELETE_ENABLED else 'DISABLED'}")
    print(f"  • Check interval: Every {AUTO_DELETE_CHECK_INTERVAL//3600} hours")
    print(f"  • Grace period: {AUTO_DELETE_GRACE_PERIOD} days after expiry")
    print("\nNext steps:")
    print("1. Update SERVER_PUBLIC_IP in the script with your server's actual IP")
    print("2. Copy server files from 'openvpn/server/' to your OpenVPN server")
    print("3. Start the OpenVPN server")
    print("4. Create clients with: python3 generate_client.py create <clientname>")
    print("="*60)
    
    return True

# =========================
# CLEANUP HANDLER
# =========================
def cleanup():
    """Cleanup function to stop scheduler"""
    auto_delete_scheduler.stop()
    print("[✓] Auto-delete scheduler stopped")

# Register cleanup handler
atexit.register(cleanup)

# =========================
# SIMPLIFIED ARGUMENT PARSING
# =========================
if __name__ == "__main__":
    # Handle custom command line arguments
    args = sys.argv[1:]
    
    if not args:
        print("""
OpenVPN Client & Server Management Tool with Auto-Delete
========================================================

Usage:
  Initialize complete setup:
    python genclient.py initall

  Server management:
    python genclient.py genserver    - Generate server certificate & config
    python genclient.py gencfg       - Generate server configuration only

  Client management:
    python genclient.py <name> [days] [password] [--custom-pwd <pwd>]
    python genclient.py create <name> [days] [--password] [--custom-pwd <pwd>]
    python genclient.py revoke <name>         - Revoke client
    python genclient.py list                  - List all clients
    python genclient.py clean                 - Auto-clean expired clients
    python genclient.py recover <name>        - Recover client password
    python genclient.py status                - Check certificate expiry status

  Auto-delete management:
    python genclient.py autodel enable        - Enable auto-delete globally
    python genclient.py autodel disable       - Disable auto-delete globally
    python genclient.py autodel client <name> enable  - Enable for specific client
    python genclient.py autodel client <name> disable - Disable for specific client
    python genclient.py autodel check         - Manual check for expired certificates

  CA management:
    python genclient.py initca                - Initialize CA only

Examples:
  python genclient.py initall                # Complete setup
  python genclient.py alice                  # Simple client without password
  python genclient.py alice 365              # 1-year client
  python genclient.py create bob --password  # With random password
  python genclient.py create charlie --custom-pwd MySecurePwd123
  python genclient.py list                   # Show all clients
  python genclient.py status                 # Check expiry status
  python genclient.py recover alice          # Recover password
  python genclient.py revoke bob             # Revoke bob's access
  python genclient.py clean                  # Clean expired
  python genclient.py autodel check          # Manual auto-delete check
  python genclient.py autodel disable        # Disable auto-delete globally
""")
        sys.exit(1)
    
    cmd = args[0]
    
    # Special case: if first arg is not a known command, treat it as client name
    known_commands = ['initall', 'genserver', 'gencfg', 'create', 'revoke', 
                     'list', 'clean', 'recover', 'initca', 'status', 'autodel']
    
    if cmd not in known_commands:
        # Treat as create command with client name
        client_name = cmd
        days = DEFAULT_CERT_DAYS
        use_password = False
        custom_password = None
        
        # Parse remaining args
        remaining_args = args[1:]
        i = 0
        while i < len(remaining_args):
            if remaining_args[i].isdigit():
                days = int(remaining_args[i])
            elif remaining_args[i] == "--password":
                use_password = True
            elif remaining_args[i] == "--custom-pwd" and i + 1 < len(remaining_args):
                use_password = True
                custom_password = remaining_args[i + 1]
                i += 1
            i += 1
        
        create_client(client_name, days, use_password, custom_password)
        
    elif cmd == "initall":
        initialize_all()

    elif cmd == "genserver":
        generate_server_cert()
        generate_server_config()

    elif cmd == "gencfg":
        generate_server_config()

    elif cmd == "create":
        if len(args) < 2:
            print("Error: Client name required")
            print("Usage: python genclient.py create <name> [days] [--password] [--custom-pwd <password>]")
            sys.exit(1)
        
        name = args[1]
        days = DEFAULT_CERT_DAYS
        use_password = False
        custom_password = None
        
        # Parse arguments
        remaining_args = args[2:]
        i = 0
        while i < len(remaining_args):
            if remaining_args[i].isdigit():
                days = int(remaining_args[i])
            elif remaining_args[i] == "--password":
                use_password = True
            elif remaining_args[i] == "--custom-pwd" and i + 1 < len(remaining_args):
                use_password = True
                custom_password = remaining_args[i + 1]
                i += 1
            i += 1
        
        create_client(name, days, use_password, custom_password)

    elif cmd == "revoke":
        if len(args) < 2:
            print("Error: Client name required")
            print("Usage: python genclient.py revoke <name>")
            sys.exit(1)
        revoke_client(args[1])

    elif cmd == "list":
        list_clients()

    elif cmd == "recover":
        if len(args) < 2:
            print("Error: Client name required")
            print("Usage: python genclient.py recover <name>")
            sys.exit(1)
        recover_password(args[1])

    elif cmd == "clean":
        auto_clean_expired()

    elif cmd == "initca":
        generate_ca()
        ensure_tls_crypt()
        print("[✓] CA and TLS crypt key initialized")

    elif cmd == "status":
        check_expiry_status()

    elif cmd == "autodel":
        if len(args) < 2:
            print("Error: Auto-delete command required")
            print("Usage: python genclient.py autodel <enable|disable|check|client>")
            sys.exit(1)
        
        subcmd = args[1]
        if subcmd == "enable":
            toggle_auto_delete(None, True)
        elif subcmd == "disable":
            toggle_auto_delete(None, False)
        elif subcmd == "check":
            auto_delete_scheduler.manual_check_now()
        elif subcmd == "client":
            if len(args) < 4:
                print("Error: Client name and action required")
                print("Usage: python genclient.py autodel client <name> <enable|disable>")
                sys.exit(1)
            client_name = args[2]
            action = args[3]
            if action == "enable":
                toggle_auto_delete(client_name, True)
            elif action == "disable":
                toggle_auto_delete(client_name, False)
            else:
                print(f"Error: Invalid action '{action}'. Use 'enable' or 'disable'")
        else:
            print(f"Error: Invalid auto-delete command '{subcmd}'")

    else:
        print(f"Invalid command: {cmd}")
        print("Use without arguments for help.")

    # Start auto-delete scheduler if not already running
    if AUTO_DELETE_ENABLED and not auto_delete_scheduler.running:
        auto_delete_scheduler.start()