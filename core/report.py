import json
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

console = Console()

def render_terminal(findings, target):
    console.print(f"\n[bold blue]GhostScanner Report for {target}[/bold blue]")
    
    # Ports
    pt = Table(title="Open Ports")
    pt.add_column("Port", style="cyan")
    pt.add_column("Service/Banner", style="magenta")
    for p in findings.get("ports", []):
        banner_info = findings.get("banners", {}).get(p, {})
        service = banner_info.get("server", banner_info.get("raw_banner", "Unknown")[:30])
        pt.add_row(str(p), service)
    console.print(pt)
    
    # OWASP
    ot = Table(title="OWASP Findings")
    ot.add_column("Vulnerability", style="red")
    ot.add_column("Description", style="yellow")
    for f in findings.get("owasp", []):
        ot.add_row(f["vuln"], f["desc"])
    console.print(ot)
    
    # CVEs
    cves = findings.get("cves", {})
    if cves:
        ct = Table(title="Known CVEs")
        ct.add_column("Port/Service", style="cyan")
        ct.add_column("CVE ID", style="red")
        ct.add_column("CVSS", style="yellow")
        for port, data in cves.items():
            software = data.get("software", "")
            for cve in data.get("cves", []):
                ct.add_row(f"{port} ({software})", cve.get("cve_id"), str(cve.get("score")))
        console.print(ct)
        
    # AI
    ai = findings.get("ai_analysis")
    if ai and not ai.startswith("Error"):
        console.print(Panel(ai, title="[bold green]Gemini AI Analysis[/bold green]"))

def save_json(findings, target):
    filename = f"report_{target.replace('.', '_')}.json"
    with open(filename, 'w') as f:
        json.dump(findings, f, indent=4, default=str)
    console.print(f"[green][+] JSON report saved to {filename}[/green]")

def save_html(findings, target):
    filename = f"report_{target.replace('.', '_')}.html"
    
    ai_md = findings.get("ai_analysis", "")
    try:
        import markdown
        ai_html = markdown.markdown(ai_md) if ai_md and not ai_md.startswith("Error") else f"<pre>{ai_md}</pre>"
    except ImportError:
        ai_html = f"<pre>{ai_md}</pre>"
    
    html = f"""
    <html>
    <head>
        <title>GhostScanner Report: {target}</title>
        <style>
            body {{ font-family: Arial, sans-serif; margin: 40px; background-color: #f4f4f9; color: #333; }}
            h1, h2 {{ color: #2c3e50; }}
            .section {{ background: white; padding: 20px; border-radius: 8px; margin-bottom: 20px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
            table {{ border-collapse: collapse; width: 100%; }}
            th, td {{ padding: 12px; border: 1px solid #ddd; text-align: left; }}
            th {{ background-color: #2c3e50; color: white; }}
        </style>
    </head>
    <body>
        <h1>GhostScanner Report: {target}</h1>
        
        <div class="section">
            <h2>Open Ports & Services</h2>
            <table>
                <tr><th>Port</th><th>Service / Banner</th></tr>
                {''.join([f"<tr><td>{p}</td><td>{findings.get('banners', {{}}).get(p, {{}}).get('server', 'Unknown')}</td></tr>" for p in findings.get("ports", [])])}
            </table>
        </div>
        
        <div class="section">
            <h2>OWASP Findings</h2>
            <table>
                <tr><th>Vulnerability</th><th>Description</th></tr>
                {''.join([f"<tr><td>{f['vuln']}</td><td>{f['desc']}</td></tr>" for f in findings.get("owasp", [])])}
            </table>
        </div>
        
        <div class="section">
            <h2>AI Analysis</h2>
            <div>{ai_html}</div>
        </div>
    </body>
    </html>
    """
    with open(filename, 'w') as f:
        f.write(html)
    console.print(f"[green][+] HTML report saved to {filename}[/green]")

def generate_report(findings, output_format, target):
    if output_format == "terminal":
        render_terminal(findings, target)
    elif output_format == "json":
        save_json(findings, target)
        render_terminal(findings, target)
    elif output_format == "html":
        save_html(findings, target)
        render_terminal(findings, target)
