import socket
import time
from rich.console import Console

console = Console()

def parse_port_range(port_str):
    try:
        if "-" in port_str:
            start, end = map(int, port_str.split("-"))
            return range(start, end + 1)
        return [int(port_str)]
    except ValueError:
        return range(1, 1001)

def fallback_nmap_scan(target, port_str, verbose):
    try:
        import nmap
        nm = nmap.PortScanner()
        if verbose:
            console.print(f"[*] Starting nmap scan on {target}:{port_str}")
        nm.scan(target, port_str)
        open_ports = []
        for host in nm.all_hosts():
            for proto in nm[host].all_protocols():
                lport = nm[host][proto].keys()
                for port in sorted(lport):
                    if nm[host][proto][port]['state'] == 'open':
                        open_ports.append(port)
        return open_ports
    except ImportError:
        console.print("[yellow][!] python-nmap not installed. Using raw sockets.[/yellow]")
        return []
    except Exception as e:
        console.print(f"[red][!] python-nmap scan failed: {e}[/red]")
        return []

def socket_scan(target, port_range, verbose):
    open_ports = []
    # Resolve target
    try:
        target_ip = socket.gethostbyname(target)
    except socket.gaierror:
        console.print(f"[red][!] Could not resolve hostname: {target}[/red]")
        return open_ports
        
    for port in port_range:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.5)
        try:
            result = sock.connect_ex((target_ip, port))
            if result == 0:
                open_ports.append(port)
        except Exception:
            pass
        finally:
            sock.close()
            
    return open_ports

def scan_ports(target, ports_str, verbose):
    port_range = parse_port_range(ports_str)
    open_ports = socket_scan(target, port_range, verbose)
    
    if not open_ports and verbose:
        console.print("[*] No ports found with raw sockets. Trying nmap fallback...")
        nmap_ports = fallback_nmap_scan(target, ports_str, verbose)
        if nmap_ports:
            open_ports = nmap_ports
            
    return open_ports
