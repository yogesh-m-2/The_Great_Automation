from flask import Flask, render_template, request, redirect, url_for, session, json
import csv
import os
import socket
import ssl
import threading
import time
import tempfile
import ipaddress
import psutil
import requests as req_lib
from requests.exceptions import RequestException
import subprocess as _sp

# ── Extracted modules ─────────────────────────────────────────────────────────
import storage
from storage import (
    TASKS_FILE, FIELDNAMES,
    load_tasks, save_tasks, get_task, update_task_fields,
)
# Keep the original private-looking names as aliases so existing call sites in
# this file remain byte-for-byte unchanged.
_runtime_get = storage.runtime_get
_runtime_set = storage.runtime_set
from tasks import MyThread
from tools import tools_bp

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "change-me-in-production")
app.register_blueprint(tools_bp)

# Blind SQL injection tool (optional — needs blindsql.py present).
try:
    from blindsql_routes import blindsql_bp
    app.register_blueprint(blindsql_bp)
    _BLINDSQL_AVAILABLE = True
except Exception as _e:
    print(f"[blindsql] not loaded: {_e}")
    _BLINDSQL_AVAILABLE = False

# ─── Pure-TCP intercepting proxy (no mitmproxy) ───────────────────────────────
_proxy_lock    = threading.Lock()
_proxy_queue   = []        # flows held waiting for forward/drop
_proxy_history = []
_proxy_running   = False
_proxy_intercept = False   # when False, requests pass through without holding
_proxy_server    = None
_flow_id_ctr     = 0

# ── Per-host cert cache (hostname → (cert_pem, key_pem)) ─────────────────────
_cert_cache      = {}
_cert_cache_lock = threading.Lock()

# ── CA bootstrap (generated once per process) ────────────────────────────────
_CA_KEY  = None   # cryptography private key object
_CA_CERT = None   # cryptography cert object
_CA_CERT_PEM = b""   # PEM bytes — sent to /proxy-ca-cert for browser install

_FIXED_CA_CERT_PEM = b"""
-----BEGIN CERTIFICATE-----
MIIDHTCCAgWgAwIBAgIUZ0EXE+YdTcftC9GGZ3esdCxTEiIwDQYJKoZIhvcNAQEL
BQAwPTEeMBwGA1UEAwwVVGhlR3JlYXRBdXRvbWF0aW9uIENBMRswGQYDVQQKDBJU
aGVHcmVhdEF1dG9tYXRpb24wIBcNMjYwNDIzMTY0MDQzWhgPMjEyNjAzMzAxNjQw
NDNaMD0xHjAcBgNVBAMMFVRoZUdyZWF0QXV0b21hdGlvbiBDQTEbMBkGA1UECgwS
VGhlR3JlYXRBdXRvbWF0aW9uMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKC
AQEAzUFU/s1egBmf18sHAzikMIQ2qLm4Qh86ZgR75Lfcf/Pt/4wurW1f3ATiBV2+
r9LV3yXVzCjolsBVMHrRisSk57AO4sCvXnl8XaznSQwxZB1zRq6MMD6SyIfUxB8s
GAFyapsnEP5a+edKOL9cHOWz/7fveIQQRsnZZYhBSLMKd/NXdPWvmx+P91bE8KSK
mhr85sscJ3Z+k4qWMX5mrwY0zSnUdWWk25m7ydKRyn6Gsng1G5N/gQWPqEnHRM7O
L2+ed3JS1Nlt+/ISeLojTuO/99tqMumnC3qJhMmBPO/B1wqBlcgw1ZseXWpTQfZQ
jt4NgHPPFywSXDuwHikRfhM/6QIDAQABoxMwETAPBgNVHRMBAf8EBTADAQH/MA0G
CSqGSIb3DQEBCwUAA4IBAQBpL7vbwfOfukbsTB15aseivfecIkTFEndir25Wo3gd
QCs243vDe73ARWRCR+hjbMclneuOEQF50oYgxzgSRaoUuUcBvTdHsw21ZagtF88f
wP4sY5XO5+wj5n0y6wWR69d5m4DLJ7f4xpQ4U9rWHw49OBv395LKNgrtXjzEBk1x
GVMIG0aUrpVEbwHpwpebz1B8sAwpuXIwToardm0nFt7yWby4q2Wi/19o0sfal4/y
dnGRitDwemMvPJx9zlNGWjdd1ilGjBoy2FI5Jf4Ay6xH8kr8KT+1+ab6VDKjp3es
yCQF5se/QAGP6x5uS7uIvQe4hW/wJKFIZbSQd42XqFaL
-----END CERTIFICATE-----
"""

_FIXED_CA_KEY_PEM = b"""
-----BEGIN RSA PRIVATE KEY-----
MIIEpQIBAAKCAQEAzUFU/s1egBmf18sHAzikMIQ2qLm4Qh86ZgR75Lfcf/Pt/4wu
rW1f3ATiBV2+r9LV3yXVzCjolsBVMHrRisSk57AO4sCvXnl8XaznSQwxZB1zRq6M
MD6SyIfUxB8sGAFyapsnEP5a+edKOL9cHOWz/7fveIQQRsnZZYhBSLMKd/NXdPWv
mx+P91bE8KSKmhr85sscJ3Z+k4qWMX5mrwY0zSnUdWWk25m7ydKRyn6Gsng1G5N/
gQWPqEnHRM7OL2+ed3JS1Nlt+/ISeLojTuO/99tqMumnC3qJhMmBPO/B1wqBlcgw
1ZseXWpTQfZQjt4NgHPPFywSXDuwHikRfhM/6QIDAQABAoIBAARNEKtjZ7RwFQXj
SfFuCYUmWBp40QNUGGSuRl+LrMUWBvaaaOX9PnHjvLRXe3K/jJGOMoJoy9e3QXG9
H4P0mYhs8e4b372vXQUXf1c40eLvrQxq0iKdEdu+FB3+xNOrjORUypPg4jL0MkpD
IRQbI7nBkHT3JRVeqHDbH8cWtve+Q37/g1vsEpSWcolF4oYfUEcOGNBJgL1O+t5v
n3NjheraImPVLujRV7awRp01EowwSJ9s/iNSoN8o6AnzD2AsYYSI7r92jcJsiIOX
EGDiTSTRm/jMRE4+37i4O64UjCIKD+HjDB3xe0G1FL34GPSwIgDaEUrbxI2LcS1g
lUOSvkkCgYEA/XdZTkhZ7sLdmvXRplNf9oeZrl66jTItNnEcj6B5A6QHYVYT2knU
ZkPZ66TnJ7UGYe1YeuwQRA6cPRBSWB3jaDKdx3E+lvvgH+DEfBucoCk5MPw46dbV
2d1xCWNfoAlzXx8ijER/xMdwjgp3rqF3w0AmZbkpzLpfW8P3UZjlEt0CgYEAz06a
8+lQClSMttRATDMmeRPBvIcToFN99o5ZxVhzQszGuh1BXEmoJ5qqPlZEG+0XJuDB
NEgpn003NKGhel5SBAceT6BIH998kYF2tlP6cpuVh9KGGx4qcW4zNFQuDt23SWVX
qnWOLg+HMTIxdARGRBo5ShndLIBmjNTl9x5jkn0CgYEA820VEu6/mGQD6pgdQg0e
w6jVera1mXdQHtIhKPtoXYvCHsRJisKPP6v4dazI58SenZwR9vQSZxpVCPxM6R3D
UkYSbAIhp2W9iUAX1E28bcFJkPcbPdE7TuKydd6/bvbEm91OE8KRpw4X1gLNkKS4
XYeVmOps75cqj/oz42Tg0+0CgYEAsgJqVfVK0IQHjFq3l3b4m1EWs989QBdRe2yC
s02fM4YJQvkqDagF53QMqZiDxYMRtUWbQVyRuQOh2uTLdvsU6/Z81ZzpMc1C9uK3
YBq+XLkybj2dAB4oDdy1xUJfhk5mO3T1ER7+ZpjY2qqiAmBFQedOuE17OOJMrLOH
gGos0DUCgYEAnwrwe3Z4ib4MnLPqBCbL4BeR9mrycLfkjlX3JQpW0O+7jTrkrUul
eqeioDHsuzwIYuEmp9AzXClQ+oQkOLffkaREVcK2UDiouG8LR3Z2pyOReHlUSqs3
XGlS5NBSWb56wo+ITU/7RM4hqiBzUtwHW/77pMo4b52X5uGlfC/OaRw=
-----END RSA PRIVATE KEY-----
"""

# def _ensure_ca():
#     global _CA_KEY, _CA_CERT, _CA_CERT_PEM
#     if _CA_KEY:
#         return
#     from cryptography import x509
#     from cryptography.x509.oid import NameOID
#     from cryptography.hazmat.primitives import hashes, serialization
#     from cryptography.hazmat.primitives.asymmetric import rsa
#     import datetime
#
#     key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
#     name = x509.Name([
#         x509.NameAttribute(NameOID.COMMON_NAME, u"TheGreatAutomation CA"),
#         x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"TheGreatAutomation"),
#     ])
#     now = datetime.datetime.utcnow()
#     cert = (
#         x509.CertificateBuilder()
#         .subject_name(name)
#         .issuer_name(name)
#         .public_key(key.public_key())
#         .serial_number(x509.random_serial_number())
#         .not_valid_before(now)
#         .not_valid_after(now + datetime.timedelta(days=3650))
#         .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
#         .sign(key, hashes.SHA256())
#     )
#     _CA_KEY  = key
#     _CA_CERT = cert
#     _CA_CERT_PEM = cert.public_bytes(serialization.Encoding.PEM)

def _ensure_ca():
    global _CA_KEY, _CA_CERT, _CA_CERT_PEM
    if _CA_KEY:
        return
    from cryptography.hazmat.primitives.serialization import load_pem_private_key
    from cryptography import x509
    _CA_KEY      = load_pem_private_key(_FIXED_CA_KEY_PEM, password=None)
    _CA_CERT     = x509.load_pem_x509_certificate(_FIXED_CA_CERT_PEM)
    _CA_CERT_PEM = _FIXED_CA_CERT_PEM

def _make_site_cert(hostname):
    """Return a cert for hostname signed by our CA, generating once and caching."""
    with _cert_cache_lock:
        if hostname in _cert_cache:
            return _cert_cache[hostname]

    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    import datetime

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hostname)])
    now  = datetime.datetime.utcnow()
    try:
        san = x509.IPAddress(ipaddress.ip_address(hostname))
    except ValueError:
        san = x509.DNSName(hostname)

    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(_CA_CERT.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=365))
        .add_extension(x509.SubjectAlternativeName([san]), critical=False)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, key_encipherment=True,
                content_commitment=False, key_agreement=False,
                key_cert_sign=False, crl_sign=False,
                encipher_only=False, decipher_only=False,
                data_encipherment=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([x509.ExtendedKeyUsageOID.SERVER_AUTH]),
            critical=False,
        )
        .sign(_CA_KEY, hashes.SHA256())
    )
    key_pem  = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    result = (cert_pem, key_pem)
    with _cert_cache_lock:
        _cert_cache[hostname] = result
    return result

# ── Flow helpers ──────────────────────────────────────────────────────────────
def _new_flow_id():
    global _flow_id_ctr
    with _proxy_lock:
        _flow_id_ctr += 1
        return _flow_id_ctr

def _serialise_queue():
    with _proxy_lock:
        return [{"id": e["id"], "method": e["method"],
                 "url": e["url"], "raw_request": e["raw_request"]}
                for e in _proxy_queue]

def _serialise_history():
    with _proxy_lock:
        return [{"id": e["id"], "method": e["method"],
                 "url": e["url"], "raw_request": e["raw_request"]}
                for e in _proxy_history]

def _proxy_forward(flow_id):
    with _proxy_lock:
        entry = next((e for e in _proxy_queue if e["id"] == flow_id), None)
        if entry:
            _proxy_queue.remove(entry)
            entry["action"] = "forward"
            entry["event"].set()

def _proxy_drop(flow_id):
    with _proxy_lock:
        entry = next((e for e in _proxy_queue if e["id"] == flow_id), None)
        if entry:
            _proxy_queue.remove(entry)
            entry["action"] = "drop"
            entry["event"].set()

# ── DNS cache (hostname -> (ip, timestamp)) ───────────────────────────────────
_dns_cache      = {}
_dns_cache_lock = threading.Lock()
_DNS_TTL        = 300  # seconds before re-resolving

def _resolve(hostname):
    """Return an IP for hostname, using a TTL-based DNS cache."""
    now = time.time()
    with _dns_cache_lock:
        entry = _dns_cache.get(hostname)
        if entry and now - entry[1] < _DNS_TTL:
            return entry[0]
    ip = socket.gethostbyname(hostname)
    with _dns_cache_lock:
        _dns_cache[hostname] = (ip, now)
    return ip

def _connect_upstream(host, port):
    """Open a TCP connection using the DNS cache."""
    ip = _resolve(host)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(15)
    sock.connect((ip, port))
    return sock

# ── Per-connection handler (keep-alive loop) ──────────────────────────────────
_KEEP_ALIVE_TIMEOUT = 30   # seconds to wait for next request on idle connection
_MAX_KEEPALIVE_REQS = 100  # max requests per TCP connection (match nginx default)

def _handle_conn(client_sock):
    try:
        client_sock.settimeout(_KEEP_ALIVE_TIMEOUT)
        req_count = 0

        while req_count < _MAX_KEEPALIVE_REQS:
            # Read enough to see the first line
            first = b""
            try:
                while b"\r\n" not in first:
                    chunk = client_sock.recv(_RECV_BUF)
                    if not chunk:
                        return   # client closed connection cleanly
                    first += chunk
            except socket.timeout:
                return   # idle timeout — close quietly

            first_line = first.split(b"\r\n")[0].decode(errors="replace")
            parts = first_line.split()
            if len(parts) < 2:
                return
            method = parts[0]
            req_count += 1

            if method == "CONNECT":
                # HTTPS tunnel — hand off; keep-alive is managed inside the TLS layer
                host_port = parts[1]
                host, _, port = host_port.partition(":")
                port = int(port) if port else 443
                client_sock.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                _handle_https(client_sock, host, port)
                return   # CONNECT consumes the connection; don't loop

            # Plain HTTP — handle one request and check whether to keep connection
            keep_going = _handle_http(client_sock, first, method)
            if not keep_going:
                return

    except Exception:
        pass
    finally:
        try:
            client_sock.close()
        except Exception:
            pass

_RECV_BUF = 65536  # 64 KiB — fits most headers + small bodies in one syscall

def _recv_full_request(sock):
    """Read headers + body from socket, return raw bytes."""
    data = b""
    while b"\r\n\r\n" not in data:
        chunk = sock.recv(_RECV_BUF)
        if not chunk:
            break
        data += chunk
    # Read body if Content-Length present
    header_part = data.split(b"\r\n\r\n")[0]
    body_part   = data[len(header_part)+4:]
    cl = 0
    for line in header_part.split(b"\r\n")[1:]:
        if line.lower().startswith(b"content-length:"):
            try:
                cl = int(line.split(b":")[1].strip())
            except Exception:
                pass
    while len(body_part) < cl:
        chunk = sock.recv(_RECV_BUF)
        if not chunk:
            break
        body_part += chunk
    return header_part + b"\r\n\r\n" + body_part

def _req_wants_keepalive(raw_bytes):
    """True if the request headers allow the connection to persist."""
    header_block = raw_bytes.split(b"\r\n\r\n")[0]
    first_line   = header_block.split(b"\r\n")[0]
    is_11 = b"HTTP/1.1" in first_line
    for line in header_block.split(b"\r\n")[1:]:
        if line.lower().startswith(b"connection:"):
            val = line.split(b":", 1)[1].strip().lower()
            return val != b"close"
    return is_11   # HTTP/1.1 defaults to keep-alive; 1.0 defaults to close

def _handle_http(client_sock, initial_data, method):
    """Handle one plain-HTTP request. Returns True if connection should stay open."""
    raw = _recv_full_request(client_sock) if b"\r\n\r\n" not in initial_data else initial_data
    first_line = raw.split(b"\r\n")[0].decode(errors="replace")
    parts = first_line.split()
    url = parts[1] if len(parts) > 1 else ""
    keep_alive = _req_wants_keepalive(raw)
    _intercept_and_forward(client_sock, raw, method, url, tls=False, host=None, port=80,
                           keep_alive=keep_alive)
    return keep_alive

def _handle_https(client_sock, host, port):
    """TLS-terminate then loop over requests on the same TLS socket (keep-alive)."""
    _ensure_ca()
    cert_pem, key_pem = _make_site_cert(host)  # cached after first call per host
    with tempfile.NamedTemporaryFile(delete=False, suffix=".pem") as f:
        f.write(cert_pem + key_pem)
        combined = f.name
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(combined)
        tls_sock = ctx.wrap_socket(client_sock, server_side=True)
        tls_sock.settimeout(_KEEP_ALIVE_TIMEOUT)

        req_count = 0
        while req_count < _MAX_KEEPALIVE_REQS:
            try:
                raw = _recv_full_request(tls_sock)
            except socket.timeout:
                break
            if not raw:
                break
            first_line = raw.split(b"\r\n")[0].decode(errors="replace")
            parts = first_line.split()
            method = parts[0] if parts else "GET"
            path   = parts[1] if len(parts) > 1 else "/"
            url    = f"https://{host}{path}"
            keep_alive = _req_wants_keepalive(raw)
            req_count += 1
            _intercept_and_forward(tls_sock, raw, method, url, tls=True,
                                   host=host, port=port, keep_alive=keep_alive)
            if not keep_alive:
                break
    except Exception:
        pass
    finally:
        os.unlink(combined)

def _intercept_and_forward(client_sock, raw, method, url, tls, host, port, keep_alive=False):
    """Intercept (if enabled), then forward one request."""
    fid   = _new_flow_id()
    event = threading.Event()
    entry = {
        "id":          fid,
        "method":      method,
        "url":         url,
        "raw_request": raw.decode(errors="replace"),
        "raw_bytes":   raw,
        "action":      None,
        "event":       event,
        "tls":         tls,
        "host":        host,
        "port":        port,
    }
    with _proxy_lock:
        _proxy_history.append(entry)
        if _proxy_intercept:
            _proxy_queue.append(entry)

    if not _proxy_intercept:
        entry["action"] = "forward"
        event.set()
    else:
        event.wait(timeout=120)

    action = entry.get("action") or "forward"
    if action == "drop":
        try:
            client_sock.sendall(
                b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            )
        except Exception:
            pass
        return

    # Forward — connect to real target using DNS cache, then relay
    try:
        raw_req = entry["raw_bytes"]
        if tls:
            upstream = _connect_upstream(host, port)
            uctx = ssl.create_default_context()
            uctx.check_hostname = False
            uctx.verify_mode    = ssl.CERT_NONE
            upstream = uctx.wrap_socket(upstream, server_hostname=host)
        else:
            h_host = host
            h_port = port
            for line in raw_req.split(b"\r\n")[1:]:
                if line.lower().startswith(b"host:"):
                    hv = line.split(b":", 1)[1].strip().decode()
                    if ":" in hv:
                        h_host, h_port = hv.rsplit(":", 1)
                        h_port = int(h_port)
                    else:
                        h_host = hv
                    break
            upstream = _connect_upstream(h_host, h_port)

        upstream.sendall(raw_req)
        upstream.settimeout(15)

        # Relay response back — stream with large buffer for fewer syscalls
        response_chunks = []
        try:
            while True:
                chunk = upstream.recv(65536)
                if not chunk:
                    break
                response_chunks.append(chunk)
                client_sock.sendall(chunk)
        except Exception:
            pass

        with _proxy_lock:
            entry["raw_response"] = b"".join(response_chunks).decode(errors="replace")

        upstream.close()
    except Exception as e:
        try:
            client_sock.sendall(
                f"HTTP/1.1 502 Bad Gateway\r\nContent-Length: {len(str(e))}\r\n\r\n{e}".encode()
            )
        except Exception:
            pass

# ── Proxy server listener ─────────────────────────────────────────────────────
def _proxy_listener(host, port):
    global _proxy_running, _proxy_server
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((host, port))
    srv.listen(64)
    srv.settimeout(1)
    _proxy_server  = srv
    _proxy_running = True
    while _proxy_running:
        try:
            conn, _ = srv.accept()
            t = threading.Thread(target=_handle_conn, args=(conn,), daemon=True)
            t.start()
        except socket.timeout:
            continue
        except Exception:
            break
    try:
        srv.close()
    except Exception:
        pass
    _proxy_running = False

def _start_proxy(host="127.0.0.1", port=8080):
    global _proxy_running
    if _proxy_running:
        return
    _ensure_ca()
    with _proxy_lock:
        _proxy_queue.clear()
        _proxy_history.clear()
    t = threading.Thread(target=_proxy_listener, args=(host, port), daemon=True)
    t.start()

def _stop_proxy():
    global _proxy_running, _proxy_server
    _proxy_running = False
    if _proxy_server:
        try:
            _proxy_server.close()
        except Exception:
            pass

# def _launch_browser(host, port):
#     def _run():
#         from playwright.sync_api import sync_playwright
#         import time
#         _ensure_ca()
#         with sync_playwright() as p:
#             browser = p.chromium.launch(
#                 headless=False,
#                 proxy={"server": f"http://{host}:{port}"},
#                 args=["--ignore-certificate-errors"],
#             )
#             ctx = browser.new_context(ignore_https_errors=True)
#             page = ctx.new_page()
#             page.goto("about:blank")
#             while True:
#                 try:
#                     if not browser.contexts:
#                         break
#                     if not browser.contexts[0].pages:
#                         break
#                     time.sleep(1)
#                 except Exception:
#                     break
#             try:
#                 browser.close()
#             except Exception:
#                 pass
#     threading.Thread(target=_run, daemon=True).start()

def _launch_browser(host, port):
    def _run():
        from playwright.sync_api import sync_playwright
        import time, tempfile, shutil
        _ensure_ca()

        user_data_dir = tempfile.mkdtemp(prefix="tga_browser_")
        ca_path = os.path.join(user_data_dir, "tga-ca.pem")
        with open(ca_path, "wb") as f:
            f.write(_CA_CERT_PEM)

        try:
            with sync_playwright() as p:
                ctx = p.chromium.launch_persistent_context(
                    user_data_dir=user_data_dir,
                    headless=False,
                    proxy={"server": f"http://{host}:{port}"},
                    ignore_https_errors=True,
                )
                page = ctx.new_page()
                page.goto("about:blank")
                while True:
                    try:
                        if not ctx.pages:
                            break
                        time.sleep(1)
                    except Exception:
                        break
                try:
                    ctx.close()
                except Exception:
                    pass
        finally:
            shutil.rmtree(user_data_dir, ignore_errors=True)

    threading.Thread(target=_run, daemon=True).start()

# Task persistence, runtime state, and the MyThread worker live in
# storage.py and tasks.py (imported above).


# ─── Auth ─────────────────────────────────────────────────────────────────────

@app.route("/", methods=["GET", "POST"])
def signin():
    if request.method == "POST":
        if request.form["username"] == "yogesh" and request.form["password"] == "password":
            session["username"] = request.form["username"]
            return redirect(url_for("dashboard"))
        return render_template("signin.html", error="Invalid username or password")
    return render_template("signin.html", error=None)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("signin"))


# ─── Dashboard ────────────────────────────────────────────────────────────────

@app.route("/dashboard")
def dashboard():
    if "username" not in session:
        return redirect(url_for("signin"))
    tasks = load_tasks()
    return render_template("dashboard.html", tasks=tasks)


# ─── Task CRUD ────────────────────────────────────────────────────────────────

@app.route("/add-task", methods=["POST"])
def add_task():
    if "username" not in session:
        return redirect(url_for("signin"))

    if request.is_json:
        data = request.get_json()
        task_name = data.get("name", "New Task")
        code = data.get("code", "")
        speed = data.get("speed", 1)
    else:
        task_name = request.form.get("name", "New Task")
        code = request.form.get("code", "")
        speed = request.form.get("speed", 1)

    tasks = load_tasks()
    ids = [int(t["id"]) for t in tasks]
    new_id = max(ids) + 1 if ids else 1

    tasks.append({
        "id": str(new_id),
        "name": task_name,
        "status": "Stopped",
        "progress": 0,
        "total": 1,
        "speed": speed,
        "code": code,
        "cpu_usage": ""
    })
    save_tasks(tasks)
    return redirect(url_for("dashboard"))


@app.route("/delete/<int:task_id>", methods=["POST"])
def delete_task(task_id):
    if "username" not in session:
        return redirect(url_for("signin"))
    for thread in threading.enumerate():
        if isinstance(thread, MyThread) and thread.task_id == task_id:
            thread.stop()
    # Remove from runtime state
    with storage._runtime_lock:
        storage._runtime.pop(task_id, None)
    tasks = [t for t in load_tasks() if int(t["id"]) != task_id]
    save_tasks(tasks)
    outfile = f"file_{task_id}"
    if os.path.exists(outfile):
        os.remove(outfile)
    return redirect(url_for("dashboard"))


@app.route("/restart/<int:task_id>", methods=["POST"])
def restart_task(task_id):
    if "username" not in session:
        return redirect(url_for("signin"))
    # Stop if running
    for thread in threading.enumerate():
        if isinstance(thread, MyThread) and thread.task_id == task_id:
            thread.stop()
    with storage._runtime_lock:
        storage._runtime.pop(task_id, None)
    update_task_fields(task_id, progress=0, status="Stopped")
    outfile = f"file_{task_id}"
    if os.path.exists(outfile):
        os.remove(outfile)
    return redirect(url_for("dashboard"))


# ─── Task control ─────────────────────────────────────────────────────────────

# Lock per task to prevent double-starts
_start_locks = {}
_start_locks_lock = threading.Lock()


def get_start_lock(task_id):
    with _start_locks_lock:
        if task_id not in _start_locks:
            _start_locks[task_id] = threading.Lock()
        return _start_locks[task_id]


@app.route("/start/<int:task_id>")
def start_task(task_id):
    if "username" not in session:
        return redirect(url_for("signin"))

    lock = get_start_lock(task_id)
    if not lock.acquire(blocking=False):
        return "<script>alert('Task start already in progress'); window.location.href='/dashboard'</script>"

    try:
        tasks = load_tasks()
        for t in tasks:
            if int(t["id"]) == task_id:
                # Check in-memory status first (more accurate than CSV)
                live_status = _runtime_get(task_id, "status")
                if live_status == "Running" or t["status"] == "Running":
                    return "<script>alert('Task is already running'); window.location.href='/dashboard'</script>"
                t["status"] = "Running"
                thread = MyThread(task_id, t["code"], t["speed"])
                thread.start()
                save_tasks(tasks)
                return redirect(url_for("dashboard"))
    finally:
        lock.release()

    return redirect(url_for("dashboard"))


@app.route("/stop/<int:task_id>")
def stop_task(task_id):
    if "username" not in session:
        return redirect(url_for("signin"))

    stopped = False
    for thread in threading.enumerate():
        if isinstance(thread, MyThread) and thread.task_id == task_id:
            thread.stop()
            stopped = True

    if stopped:
        _runtime_set(task_id, "status", "Stopped")
        # Flush current progress to CSV
        progress = _runtime_get(task_id, "progress", 0)
        update_task_fields(task_id, status="Stopped", progress=progress)
        return redirect(url_for("dashboard"))

    return "<script>alert('Task is not running'); window.location.href='/dashboard'</script>"


# ─── Speed control ────────────────────────────────────────────────────────────

@app.route("/increase-speed/<int:task_id>")
def increase_speed(task_id):
    if "username" not in session:
        return redirect(url_for("signin"))

    tasks = load_tasks()
    for t in tasks:
        if int(t["id"]) == task_id:
            new_speed = int(t["speed"]) + 1
            t["speed"] = new_speed
            # Update running thread via change_speed (handles semaphore)
            for thread in threading.enumerate():
                if isinstance(thread, MyThread) and thread.task_id == task_id:
                    thread.change_speed(new_speed)
            # Also update in-memory if thread not found
            _runtime_set(task_id, "speed", new_speed)
    save_tasks(tasks)
    return redirect(url_for("dashboard"))


@app.route("/decrease-speed/<int:task_id>")
def decrease_speed(task_id):
    if "username" not in session:
        return redirect(url_for("signin"))

    tasks = load_tasks()
    for t in tasks:
        if int(t["id"]) == task_id:
            new_speed = max(1, int(t["speed"]) - 1)
            t["speed"] = new_speed
            for thread in threading.enumerate():
                if isinstance(thread, MyThread) and thread.task_id == task_id:
                    thread.change_speed(new_speed)
            _runtime_set(task_id, "speed", new_speed)
    save_tasks(tasks)
    return redirect(url_for("dashboard"))


# ─── Code editor ──────────────────────────────────────────────────────────────

@app.route("/edit/<int:task_id>")
def edit_task(task_id):
    if "username" not in session:
        return redirect(url_for("signin"))
    t = get_task(task_id)
    if t:
        return render_template("editor.html", task=t, code=t["code"])
    return redirect(url_for("dashboard"))


@app.route("/save/<int:task_id>", methods=["POST"])
def save_code(task_id):
    if "username" not in session:
        return redirect(url_for("signin"))
    update_task_fields(task_id, code=request.form["code"])
    return redirect(url_for("dashboard"))


# ─── Output file viewer ───────────────────────────────────────────────────────

@app.route("/file_<task_id>")
def get_file(task_id):
    if "username" not in session:
        return "Unauthorized", 401
    filename = f"file_{task_id}"
    if os.path.exists(filename):
        # Cap read at 2MB to avoid massive responses
        with open(filename, "r", errors="ignore") as f:
            content = f.read(2 * 1024 * 1024)
        return content, 200, {"Content-Type": "text/plain"}
    return "No output yet.", 404


# ─── CPU usage (AJAX) ─────────────────────────────────────────────────────────

@app.route("/cpu-usage")
def cpu_usage():
    return json.dumps({"cpu_usage": psutil.cpu_percent(interval=0.5)})


# ─── Task status (AJAX polling) — served from memory, no CSV read ─────────────

@app.route("/task-status")
def task_status():
    tasks = load_tasks()
    result = []
    for t in tasks:
        task_id = int(t["id"])
        # Prefer live in-memory values if the task is running
        live = storage._runtime.get(task_id, {})
        progress = live.get("progress", int(t.get("progress", 0)))
        total = live.get("total", max(int(t.get("total", 1)), 1))
        speed = live.get("speed", t["speed"])
        status = live.get("status", t["status"])
        total = max(total, 1)
        pct = round((progress / total) * 100, 1)
        result.append({
            "id": t["id"],
            "status": status,
            "progress": pct,
            "speed": speed,
        })
    return json.dumps(result)


# ─── Tool routes ──────────────────────────────────────────────────────────────
# nmap / dirbuster / httpx / subfinder routes live in tools.py (registered as a
# Blueprint above).


import socket
import ssl
import tempfile
import ipaddress
import subprocess as _sp
import json as _json

_proxy_lock      = threading.Lock()
_proxy_running   = False
_proxy_intercept = False
_proxy_proc      = None

_STATE_DIR      = os.path.dirname(os.path.abspath(__file__))
_QUEUE_FILE     = os.path.join(_STATE_DIR, ".proxy_queue.json")
_HISTORY_FILE   = os.path.join(_STATE_DIR, ".proxy_history.json")
_INTERCEPT_FILE = os.path.join(_STATE_DIR, ".proxy_intercept")
_ACTION_DIR     = os.path.join(_STATE_DIR, ".proxy_actions")
_ADDON_FILE     = os.path.join(_STATE_DIR, ".proxy_addon.py")

_proxy_queue   = []
_proxy_history = []
_flow_id_ctr   = 0


def _write_addon():
    addon_code = r'''
import json, os, time, threading, socket
from mitmproxy import http, ctx

_orig_getaddrinfo = socket.getaddrinfo
def _ipv4_getaddrinfo(host, port, family=0, type=0, proto=0, flags=0):
    try:
        results = _orig_getaddrinfo(host, port, socket.AF_INET, type, proto, flags)
        if results:
            return results
    except Exception:
        pass
    return _orig_getaddrinfo(host, port, family, type, proto, flags)
socket.getaddrinfo = _ipv4_getaddrinfo

STATE_DIR      = os.path.dirname(os.path.abspath(__file__))
QUEUE_FILE     = os.path.join(STATE_DIR, ".proxy_queue.json")
HISTORY_FILE   = os.path.join(STATE_DIR, ".proxy_history.json")
INTERCEPT_FILE = os.path.join(STATE_DIR, ".proxy_intercept")
ACTION_DIR     = os.path.join(STATE_DIR, ".proxy_actions")

os.makedirs(ACTION_DIR, exist_ok=True)

_lock  = threading.Lock()
_queue = {}
_history = []
_fid = 0


def _next_id():
    global _fid
    _fid += 1
    return _fid


def _build_raw_request(req):
    path = req.path or "/"
    ver = req.http_version
    if ver.upper().startswith("HTTP/"):
        ver = ver[5:]
    raw = f"{req.method} {path} HTTP/{ver}\r\n"

    # Always ensure Host header is present — in HTTP/2 it comes as :authority
    # pseudo-header and mitmproxy may not include it in req.headers
    has_host = any(k.lower() == "host" for k in req.headers.keys())
    if not has_host:
        host = req.pretty_host
        if req.port and req.port not in (80, 443):
            host = f"{host}:{req.port}"
        raw += f"Host: {host}\r\n"

    for name, value in req.headers.items():
        # Skip HTTP/2 pseudo-headers (:method, :path, :authority, :scheme)
        if not name.startswith(":"):
            raw += f"{name}: {value}\r\n"

    raw += "\r\n"
    if req.content:
        try:
            raw += req.content.decode("utf-8", errors="replace")
        except Exception:
            pass
    return raw


def _save_queue():
    items = [{"id": fid, "method": f.request.method,
               "url": f.request.pretty_url,
               "raw_request": _build_raw_request(f.request)}
             for fid, f in _queue.items()]
    with open(QUEUE_FILE, "w") as fp:
        json.dump(items, fp)


def _save_history():
    with open(HISTORY_FILE, "w") as fp:
        json.dump(_history[-500:], fp)


def _is_intercept():
    return os.path.exists(INTERCEPT_FILE)


class TGAAddon:
    def request(self, flow: http.HTTPFlow):
        fid = _next_id()
        flow.metadata["tga_id"] = fid
        raw = _build_raw_request(flow.request)
        entry = {
            "id": fid,
            "method": flow.request.method,
            "url": flow.request.pretty_url,
            "raw_request": raw,
        }
        with _lock:
            _history.append(entry)
            _save_history()
        if _is_intercept():
            flow.intercept()
            with _lock:
                _queue[fid] = flow
                _save_queue()

    def running(self):
        def _poll():
            while True:
                time.sleep(0.05)
                with _lock:
                    pending = list(_queue.items())
                for fid, flow in pending:
                    action_file = os.path.join(ACTION_DIR, str(fid))
                    if os.path.exists(action_file):
                        try:
                            action = open(action_file).read().strip()
                            os.unlink(action_file)
                        except Exception:
                            action = "forward"
                        with _lock:
                            _queue.pop(fid, None)
                            _save_queue()
                        try:
                            if action == "drop":
                                flow.kill()
                            else:
                                flow.resume()
                        except Exception:
                            pass
        t = threading.Thread(target=_poll, daemon=True)
        t.start()


addons = [TGAAddon()]
'''
    with open(_ADDON_FILE, "w") as f:
        f.write(addon_code)


def _serialise_queue():
    try:
        if os.path.exists(_QUEUE_FILE):
            return _json.loads(open(_QUEUE_FILE).read())
    except Exception:
        pass
    return []


def _serialise_history():
    try:
        if os.path.exists(_HISTORY_FILE):
            return _json.loads(open(_HISTORY_FILE).read())
    except Exception:
        pass
    return []


def _proxy_forward(flow_id):
    os.makedirs(_ACTION_DIR, exist_ok=True)
    with open(os.path.join(_ACTION_DIR, str(flow_id)), "w") as f:
        f.write("forward")


def _proxy_drop(flow_id):
    os.makedirs(_ACTION_DIR, exist_ok=True)
    with open(os.path.join(_ACTION_DIR, str(flow_id)), "w") as f:
        f.write("drop")


def _get_mitm_ca_cert():
    ca_path = os.path.expanduser("~/.mitmproxy/mitmproxy-ca-cert.pem")
    if os.path.exists(ca_path):
        with open(ca_path, "rb") as f:
            return f.read()
    return b""


def _start_proxy(host="127.0.0.1", port=8080):
    global _proxy_running, _proxy_proc
    if _proxy_running:
        return
    _write_addon()
    for f in [_QUEUE_FILE, _HISTORY_FILE]:
        try: os.unlink(f)
        except: pass
    cmd = [
        "mitmdump",
        "--listen-host", host,
        "--listen-port", str(port),
        "--ssl-insecure",
        "-s", _ADDON_FILE,
        "--set", "connection_strategy=lazy",
        "--set", "keep_host_header=true",
    ]
    _proxy_proc = _sp.Popen(cmd, stdout=_sp.DEVNULL, stderr=_sp.DEVNULL)
    _proxy_running = True


def _stop_proxy():
    global _proxy_running, _proxy_proc, _proxy_intercept
    _proxy_running   = False
    _proxy_intercept = False
    try: os.unlink(_INTERCEPT_FILE)
    except: pass
    if _proxy_proc:
        try: _proxy_proc.terminate()
        except: pass
        _proxy_proc = None
    try:
        for item in _serialise_queue():
            _proxy_forward(item["id"])
    except: pass


def _set_intercept(enable: bool):
    global _proxy_intercept
    _proxy_intercept = enable
    if enable:
        open(_INTERCEPT_FILE, "w").close()
    else:
        try: os.unlink(_INTERCEPT_FILE)
        except: pass
        for item in _serialise_queue():
            _proxy_forward(item["id"])


# ─── Proxy routes ─────────────────────────────────────────────────────────────

@app.route("/proxy")
def proxy():
    if "username" not in session:
        return redirect(url_for("signin"))
    return render_template("proxy.html")


@app.route("/repeater")
def repeater():
    if "username" not in session:
        return redirect(url_for("signin"))
    return render_template("repeater.html")


@app.route("/proxy-ca-cert")
def proxy_ca_cert():
    from flask import Response
    cert = _get_mitm_ca_cert()
    return Response(cert, mimetype="application/x-pem-file",
                    headers={"Content-Disposition": "attachment; filename=mitmproxy-ca-cert.pem"})


@app.route("/proxy-start", methods=["POST"])
def proxy_start():
    if "username" not in session:
        return json.dumps({"error": "Unauthorized"}), 401
    data = request.get_json(silent=True) or {}
    host = data.get("host", "127.0.0.1")
    port = int(data.get("port", 8080))
    if not _proxy_running:
        _start_proxy(host, port)
    return json.dumps({"ok": True})


@app.route("/proxy-stop", methods=["POST"])
def proxy_stop():
    if "username" not in session:
        return json.dumps({"error": "Unauthorized"}), 401
    _stop_proxy()
    return json.dumps({"ok": True})


@app.route("/proxy-intercept", methods=["POST"])
def proxy_intercept_toggle():
    if "username" not in session:
        return json.dumps({"error": "Unauthorized"}), 401
    data = request.get_json(silent=True) or {}
    enable = data.get("enable", False)
    _set_intercept(bool(enable))
    return json.dumps({"ok": True, "intercept": _proxy_intercept})


@app.route("/proxy-status")
def proxy_status():
    if "username" not in session:
        return json.dumps({"error": "Unauthorized"}), 401
    return json.dumps({"running": _proxy_running, "intercept": _proxy_intercept})


@app.route("/proxy-queue")
def proxy_queue():
    if "username" not in session:
        return json.dumps([]), 401
    return json.dumps(_serialise_queue())


@app.route("/proxy-history")
def proxy_history():
    if "username" not in session:
        return json.dumps([]), 401
    return json.dumps(_serialise_history())


@app.route("/proxy-forward/<int:flow_id>", methods=["POST"])
def proxy_forward(flow_id):
    if "username" not in session:
        return json.dumps({"error": "Unauthorized"}), 401
    _proxy_forward(flow_id)
    return json.dumps({"ok": True})


@app.route("/proxy-drop/<int:flow_id>", methods=["POST"])
def proxy_drop(flow_id):
    if "username" not in session:
        return json.dumps({"error": "Unauthorized"}), 401
    _proxy_drop(flow_id)
    return json.dumps({"ok": True})


@app.route("/proxy-clear-history", methods=["POST"])
def proxy_clear_history():
    if "username" not in session:
        return json.dumps({"error": "Unauthorized"}), 401
    return json.dumps({"ok": True})

# ─── Intruder ─────────────────────────────────────────────────────────────────

@app.route("/intruder")
def intruder():
    if "username" not in session:
        return redirect(url_for("signin"))
    return render_template("intruder.html")


# ─── Shared HTTP proxy endpoint (used by Proxy, Repeater, and Intruder) ───────

@app.route("/intruder-proxy", methods=["POST"])
def intruder_proxy():
    if "username" not in session:
        return json.dumps({"error": "Unauthorized"}), 401

    data = request.get_json()
    url              = data.get("url", "").strip()
    method           = data.get("method", "GET").upper()
    raw_headers_in   = data.get("headers", [])
    body             = data.get("body", "")
    follow_redirects = data.get("follow_redirects", True)

    if not url:
        return json.dumps({"error": "No URL provided"}), 400

    # Headers may arrive as an ordered list of [name, value] pairs (preferred —
    # preserves duplicate header names) or, for backward compatibility, a dict.
    if isinstance(raw_headers_in, dict):
        header_pairs = list(raw_headers_in.items())
    else:
        header_pairs = [(p[0], p[1]) for p in raw_headers_in if len(p) >= 2]

    # Hop-by-hop headers urllib3 must set itself; drop anything the client sent.
    # NOTE: Host is intentionally NOT stripped — pentests may need a spoofed or
    # duplicate Host. If the client sends none, urllib3 derives one from the URL.
    skip = {"content-length", "connection", "transfer-encoding", "te"}
    clean_pairs = []
    for k, v in header_pairs:
        if k.lower() in skip:
            continue
        v = v.strip() if isinstance(v, str) else v
        # HTTP/2 cookie crumbs sometimes arrive comma-joined (invalid). The Cookie
        # header must use "; " between name=value pairs. Normalize defensively.
        if k.lower() == "cookie" and isinstance(v, str) and ", " in v:
            crumbs = [c.strip() for c in v.replace(", ", ";").split(";") if c.strip()]
            v = "; ".join(crumbs)
        clean_pairs.append((k, v))

    # HTTPHeaderDict preserves duplicate header names and order, so two Host /
    # X-Forwarded-For / etc. headers go out on the wire as distinct headers.
    from urllib3 import HTTPHeaderDict, PoolManager
    from urllib3.exceptions import HTTPError as _Urllib3Error
    send_headers = HTTPHeaderDict()
    for k, v in clean_pairs:
        send_headers.add(k, v)

    try:
        http = PoolManager(
            cert_reqs="CERT_NONE",  # allow self-signed certs
            retries=False,
            timeout=15.0,
        )
        resp = http.request(
            method,
            url,
            body=body.encode() if body else None,
            headers=send_headers,
            redirect=follow_redirects,
            preload_content=True,
            decode_content=True,  # auto-decompress gzip/deflate/br
        )
        status = resp.status
        reason = getattr(resp, "reason", "") or ""
        body_text = resp.data.decode("utf-8", errors="replace")

        # Build a printable raw response. Drop encoding/length headers since the
        # body is already decompressed; recompute Content-Length.
        skip_resp = {"content-encoding", "content-length", "transfer-encoding"}
        resp_header_lines = "\r\n".join(
            f"{k}: {v}" for k, v in resp.headers.items()
            if k.lower() not in skip_resp
        )
        raw = (f"HTTP/1.1 {status} {reason}\r\n"
               f"{resp_header_lines}\r\nContent-Length: {len(body_text.encode())}\r\n\r\n"
               f"{body_text}")

        # The headers we actually sent (list of pairs, duplicates intact).
        sent = [[k, v] for k, v in clean_pairs]
        final_url = getattr(resp, "geturl", lambda: url)() or url

        return json.dumps({
            "status":       status,
            "body":         body_text,
            "raw":          raw,
            "content_type": resp.headers.get("Content-Type", ""),
            "sent_headers": sent,
            "final_url":    final_url,
            "redirected":   final_url != url,
        })
    except (_Urllib3Error, Exception) as e:
        return json.dumps({
            "status": 0,
            "body":   f"[Error: {e}]",
            "raw":    f"[Error: {e}]",
        })


# ─── Entry point ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    if not os.path.exists(TASKS_FILE):
        with open(TASKS_FILE, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=FIELDNAMES)
            writer.writeheader()
    # debug=False in production; use threaded=True for concurrent requests
    app.run(debug=False, threaded=True, host="127.0.0.1", port=5000)