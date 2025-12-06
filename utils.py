import os
import fcntl
import yaml
import bcrypt
import ssl
import socket
import tempfile
import requests
import platform
import subprocess
from datetime import datetime, timezone
from urllib.parse import urlparse

# Constants
yaml_file = "websites.yml"
default_admin_pw = "secret"

# --- CA Bundle Detection ---
def get_system_ca_bundle():
    """
    Automatically detect and return the system CA bundle path.
    Handles common Linux distributions, macOS, and Windows.
    """
    system = platform.system().lower()

    # Common CA bundle locations by OS
    ca_paths = {
        'linux': [
            '/etc/ssl/certs/ca-certificates.crt',  # Debian/Ubuntu
            '/etc/pki/tls/certs/ca-bundle.crt',    # RHEL/CentOS/Fedora
            '/etc/ssl/ca-bundle.pem',              # OpenSUSE
            '/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem',  # RHEL/CentOS 7+
            '/etc/ssl/cert.pem',                   # Alpine Linux
            '/usr/local/share/certs/ca-root-nss.crt',  # FreeBSD
        ],
        'darwin': [  # macOS
            '/etc/ssl/cert.pem',
            '/usr/local/etc/openssl/cert.pem',     # Homebrew OpenSSL
            '/opt/local/share/curl/curl-ca-bundle.crt',  # MacPorts
        ],
        'windows': [
            # Windows uses the system certificate store, but we can check these paths
            'C:\\Windows\\System32\\curl-ca-bundle.crt',
            'C:\\curl\\bin\\curl-ca-bundle.crt',
        ]
    }

    # Check OS-specific paths
    if system in ca_paths:
        for path in ca_paths[system]:
            if os.path.isfile(path):
                print(f"[INFO] Using system CA bundle: {path}")
                return path

    # Try to use certifi as fallback (Python's bundled CAs)
    try:
        import certifi
        path = certifi.where()
        print(f"[INFO] Using certifi CA bundle: {path}")
        return path
    except ImportError:
        pass

    # Last resort: try to find via OpenSSL
    try:
        if system == 'linux' or system == 'darwin':
            result = subprocess.run(['openssl', 'version', '-d'],
                                  capture_output=True, text=True)
            if result.returncode == 0:
                # Extract directory from output like 'OPENSSLDIR: "/etc/ssl"'
                openssl_dir = result.stdout.split('"')[1]
                possible_paths = [
                    os.path.join(openssl_dir, 'certs', 'ca-certificates.crt'),
                    os.path.join(openssl_dir, 'cert.pem'),
                    os.path.join(openssl_dir, 'certs', 'ca-bundle.crt'),
                ]
                for path in possible_paths:
                    if os.path.isfile(path):
                        print(f"[INFO] Using OpenSSL CA bundle: {path}")
                        return path
    except (subprocess.SubprocessError, FileNotFoundError):
        pass

    print("[WARN] Could not find system CA bundle, using default SSL verification")
    return True  # Use default verification


def get_ca_bundle_for_site(site):
    """
    Get the appropriate CA bundle for a site.
    Supports custom CA bundles per site or falls back to system bundle.
    """
    # Check if site has custom CA bundle specified
    custom_ca = site.get("ca_bundle")
    if custom_ca and os.path.isfile(custom_ca):
        print(f"[INFO] Using custom CA bundle for {site['name']}: {custom_ca}")
        return custom_ca

    # Check if SSL verification is disabled
    if not site.get("verify_ssl", True):
        return False

    # Use system CA bundle
    return get_system_ca_bundle()


# --- File utilities ---
def load_data():
    if not os.path.exists(yaml_file):
        return {}
    with open(yaml_file, "r") as f:
        return yaml.safe_load(f) or {}


def save_data(data):
    if not os.path.exists(yaml_file):
        with open(yaml_file, "w") as f:
            yaml.safe_dump({}, f)
    with open(yaml_file, "r+") as f:
        fcntl.flock(f, fcntl.LOCK_EX)
        f.seek(0)
        yaml.safe_dump(data, f, default_flow_style=False)
        f.truncate()
        fcntl.flock(f, fcntl.LOCK_UN)


# --- Admin & auth ---
def ensure_admin_password():
    data = load_data()
    admin = data.setdefault("admin", {})
    password = admin.get("password")

    def _hash_pw(raw):
        return bcrypt.hashpw(raw.encode(), bcrypt.gensalt()).decode()

    if not password:
        admin["password"] = _hash_pw(default_admin_pw)
        save_data(data)
        return

    # Support plain-text seed passwords (e.g., "secret") by hashing on first run.
    if isinstance(password, str) and not password.startswith("$2"):
        admin["password"] = _hash_pw(password)
        save_data(data)


def check_login(pw):
    data = load_data()
    stored = data.get("admin", {}).get("password", "")
    return bool(stored) and bcrypt.checkpw(pw.encode(), stored.encode())


# --- Certificate retrieval & parsing ---
def _fetch_server_cert_dict(hostname, port=443, timeout=5):
    """Retrieve and parse the server's TLS certificate for ``hostname:port``"""
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    with socket.create_connection((hostname, port), timeout=timeout) as sock:
        with context.wrap_socket(sock, server_hostname=hostname) as ssock:
            cert_der = ssock.getpeercert(binary_form=True)

    pem = ssl.DER_cert_to_PEM_cert(cert_der)

    tmp = tempfile.NamedTemporaryFile(delete=False, suffix='.pem')
    tmp.write(pem.encode())
    tmp.close()

    try:
        cert_dict = ssl._ssl._test_decode_cert(tmp.name)
    finally:
        os.unlink(tmp.name)

    return cert_dict


def check_website_status(site):
    raw_url = site["url"]

    parsed = urlparse(raw_url)
    if not parsed.scheme:
        parsed = urlparse(f"https://{raw_url}")
    if parsed.scheme != "https":
        raise ValueError(f"Unsupported URL scheme for certificate check: {raw_url}")

    url = parsed.geturl()
    host = parsed.hostname or ""
    port = parsed.port or 443
    if not host:
        raise ValueError(f"Invalid URL provided: {raw_url}")

    # Get appropriate CA bundle for this site
    ca_bundle = get_ca_bundle_for_site(site)

    # Initialize variables
    http_status = "offline"
    timeout = site.get("timeout", 5)
    try:
        timeout = float(timeout)
    except (TypeError, ValueError):
        timeout = 5

    cert_days_left = None
    cert_info = {'issuer': 'Unknown', 'expires': 'Unknown', 'days_left': '?', 'expired': None}

    # ---- HTTP check ----
    try:
        # Disable SSL warnings if verification is disabled
        if ca_bundle is False:
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        # Check for authentication credentials
        auth = None
        if 'auth' in site and 'username' in site['auth'] and 'password' in site['auth']:
            auth = (site['auth']['username'], site['auth']['password'])

        r = requests.get(url, timeout=timeout, verify=ca_bundle, auth=auth)
        code = r.status_code

        # Handle authentication-protected sites
        if code == 401 and auth is None:
            # 401 means the server is responding but requires authentication
            # This is actually "online" from a monitoring perspective
            print(f"[INFO] {host} requires authentication (HTTP 401) - treating as online")
            http_status = "online"
        elif code >= 500:
            http_status = "offline"
        elif code >= 400:
            # Other 4xx errors (403, 404, etc.) are warnings
            http_status = "warning"
        else:
            http_status = "online"

    except requests.exceptions.SSLError as e:
        print(f"[WARN] SSL verification failed for {host}: {e}")
        print(f"[INFO] You may need to add your internal CA to the system trust store")
        http_status = "offline"
    except Exception as e:
        print(f"[WARN] HTTP fetch failed for {host}: {e}")
        http_status = "offline"

    # ---- Cert fetch + parse ----
    try:
        cd = _fetch_server_cert_dict(host, port=port, timeout=timeout)
        # parse issuer
        rdns = cd.get('issuer', [])
        issuer_dn = dict(rdn[0] for rdn in rdns)
        issuer_name = issuer_dn.get('organizationName') or issuer_dn.get('commonName') or 'Unknown'

        # parse expiration
        na = datetime.strptime(cd['notAfter'], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
        cert_days_left = (na - datetime.now(timezone.utc)).days

        cert_info = {
            'issuer': issuer_name,
            'expires': na.strftime('%Y-%m-%d'),
            'days_left': cert_days_left,
            'expired': cert_days_left <= 0
        }

    except Exception as e:
        print(f"[ERROR] cert parse failed for {host}: {e}")
        cert_info['error'] = str(e)

    # ---- Determine certificate health based on days remaining ----
    if isinstance(cert_days_left, int):
        if cert_days_left <= 0:
            cert_health = 'critical'
        elif cert_days_left < 7:
            cert_health = 'critical'
        elif cert_days_left < 30:
            cert_health = 'expiring'
        else:
            cert_health = 'healthy'
    else:
        cert_health = 'error'

    return {
        'status': cert_health,  # Use certificate health instead of connectivity
        'cert': cert_info,
        'http_status': http_status  # Keep HTTP status for potential future use
    }


# --- System CA Bundle Information ---
def get_system_info():
    """Get information about the system and CA bundle being used"""
    system = platform.system()
    ca_bundle = get_system_ca_bundle()

    info = {
        'system': system,
        'ca_bundle_path': ca_bundle if isinstance(ca_bundle, str) else 'Default SSL verification',
        'ca_bundle_exists': os.path.isfile(ca_bundle) if isinstance(ca_bundle, str) else True
    }

    return info
