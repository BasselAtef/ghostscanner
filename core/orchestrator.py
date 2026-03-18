import os
from rich.console import Console
from rich.progress import Progress
from core.port_scanner import scan_ports
from core.banner_grabber import grab_banners
from core.owasp_checks import run_owasp_checks
from core.cve_lookup import lookup_cves
from core.report import generate_report
from ai.gemini_analyst import analyze_findings

console = Console()

def run_scan(target, ports, output_format, skip_modules_str, verbose):
    skip_modules = [m.strip().lower() for m in skip_modules_str.split(",")] if skip_modules_str else []
    
    findings = {
        "target": target,
        "ports": [],
        "banners": {},
        "owasp": [],
        "cves": [],
        "ai_analysis": None
    }
    
    with Progress(console=console) as progress:
        # Ports
        if "ports" not in skip_modules:
            task_ports = progress.add_task("[cyan]Scanning ports...", total=100)
            findings["ports"] = scan_ports(target, ports, verbose)
            progress.update(task_ports, advance=100, description="[green]Port scan complete")
            if verbose:
                console.print(f"[*] Found open ports: {findings['ports']}")
        
        # Banners
        if "banners" not in skip_modules:
            task_banners = progress.add_task("[cyan]Grabbing banners...", total=100)
            findings["banners"] = grab_banners(target, findings["ports"], verbose)
            progress.update(task_banners, advance=100, description="[green]Banner grabbing complete")
        
        # OWASP
        if "owasp" not in skip_modules:
            task_owasp = progress.add_task("[cyan]Running OWASP checks...", total=100)
            findings["owasp"] = run_owasp_checks(target, verbose)
            progress.update(task_owasp, advance=100, description="[green]OWASP checks complete")
            
        # CVE Lookup
        if "cve" not in skip_modules:
            task_cve = progress.add_task("[cyan]Looking up CVEs...", total=100)
            findings["cves"] = lookup_cves(findings["banners"], verbose)
            progress.update(task_cve, advance=100, description="[green]CVE lookup complete")
            
        # AI Analysis
        if "ai" not in skip_modules:
            api_key = os.environ.get("GEMINI_API_KEY")
            if not api_key:
                progress.console.print("[yellow][!] GEMINI_API_KEY environment variable not set. Skipping AI analysis.[/yellow]")
            else:
                task_ai = progress.add_task("[cyan]Analyzing findings with Gemini AI...", total=100)
                findings["ai_analysis"] = analyze_findings(findings, verbose)
                progress.update(task_ai, advance=100, description="[green]AI Analysis complete")
                
    # Generate Report
    if verbose:
        console.print("[*] Generating report...")
    generate_report(findings, output_format, target)
