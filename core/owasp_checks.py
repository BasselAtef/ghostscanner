import httpx
from rich.console import Console
from urllib.parse import urljoin

console = Console()

def check_directory_traversal(url):
    payloads = ["../../../etc/passwd", "..%2f..%2f..%2fetc%2fpasswd"]
    for payload in payloads:
        try:
            r = httpx.get(f"{url}/{payload}", verify=False, timeout=3.0)
            if "root:x:0:0" in r.text or "daemon:" in r.text:
                return True, f"Vulnerable to directory traversal: {payload}"
        except Exception:
            pass
    return False, ""

def check_sql_injection(url):
    # Basic check with single quote
    try:
        r = httpx.get(f"{url}/?id=1'", verify=False, timeout=3.0)
        errors = ["syntax error", "sql format", "mysql_fetch", "ora-", "postgresql"]
        for err in errors:
            if err in r.text.lower():
                return True, "Potential SQLi detected via '?id=1''"
    except Exception:
        pass
    return False, ""

def check_xss(url):
    payload = "<script>alert(1)</script>"
    try:
        r = httpx.get(f"{url}/?search={payload}", verify=False, timeout=3.0)
        if payload in r.text and "text/html" in r.headers.get("content-type", ""):
            return True, "Potential Reflected XSS detected via '?search='"
    except Exception:
        pass
    return False, ""

def check_exposed_endpoints(url):
    endpoints = ["/admin", "/.git/config", "/.env", "/phpinfo.php", "/server-status"]
    found = []
    for ep in endpoints:
        try:
            r = httpx.get(urljoin(url, ep), verify=False, timeout=3.0)
            if r.status_code == 200:
                # Basic false positive check (sometimes 200 is returned for custom 404)
                if len(r.text) > 0 and "404" not in r.text.lower() and "not found" not in r.text.lower():
                    found.append(ep)
        except Exception:
            pass
    if found:
        return True, f"Exposed endpoints found: {', '.join(found)}"
    return False, ""

def run_owasp_checks(target, verbose):
    url = f"http://{target}"
    https_url = f"https://{target}"
    
    findings = []
    
    # 1. HTTP vs HTTPS
    working_url = url
    try:
        r = httpx.get(https_url, verify=False, timeout=3.0)
        if r.status_code < 400:
            working_url = https_url
        else:
            findings.append({"vuln": "No HTTPS", "desc": "HTTPS available but responding with error."})
    except Exception:
        findings.append({"vuln": "No HTTPS", "desc": "Failed to connect via HTTPS."})

    target_url = working_url
    if verbose:
        console.print(f"[*] Running OWASP checks against {target_url}")

    # Run probes
    checks = {
        "Directory Traversal": lambda: check_directory_traversal(target_url),
        "SQL Injection": lambda: check_sql_injection(target_url),
        "Cross-Site Scripting (XSS)": lambda: check_xss(target_url),
        "Exposed Endpoints": lambda: check_exposed_endpoints(target_url)
    }

    for name, func in checks.items():
        try:
            is_vuln, desc = func()
            if is_vuln:
                findings.append({"vuln": name, "desc": desc})
        except Exception as e:
            if verbose:
                console.print(f"[yellow][!] Error running {name}: {e}[/yellow]")

    return findings
