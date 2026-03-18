import httpx
import socket
import ssl
from rich.console import Console

console = Console()

def grab_http_headers(target, port, use_https=False):
    protocol = "https" if use_https or port == 443 else "http"
    url = f"{protocol}://{target}:{port}"
    try:
        with httpx.Client(verify=False, timeout=5.0) as client:
            response = client.get(url)
            return dict(response.headers)
    except Exception:
        return {}

def grab_socket_banner(target, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3.0)
        sock.connect((target, port))
        sock.send(b"HEAD / HTTP/1.1\r\nHost: " + target.encode() + b"\r\n\r\n")
        banner = sock.recv(1024).decode(errors='ignore').strip()
        sock.close()
        return banner
    except Exception:
        return ""

def get_tls_info(target, port=443):
    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        with socket.create_connection((target, port), timeout=5.0) as sock:
            with context.wrap_socket(sock, server_hostname=target) as ssock:
                cert = ssock.getpeercert()
                version = ssock.version()
                return {"tls_version": version, "cert": cert}
    except Exception:
        return None

def grab_banners(target, open_ports, verbose):
    results = {}
    for port in open_ports:
        port_info = {}
        
        # Try HTTP headers
        headers = grab_http_headers(target, port)
        if headers:
            port_info['headers'] = headers
            server = headers.get('server', '')
            if server:
                port_info['server'] = server
                
        # Try raw banner
        if not headers:
            banner = grab_socket_banner(target, port)
            if banner:
                port_info['raw_banner'] = banner[:200]
                
        # TLS Info
        if port == 443 or "https" in port_info.get("server", "").lower():
            tls_info = get_tls_info(target, port)
            if tls_info:
                port_info['tls'] = tls_info
                
        if port_info:
            results[port] = port_info
            
    return results
