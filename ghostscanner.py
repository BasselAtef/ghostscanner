#!/usr/bin/env python3
"""
GhostScanner — AI-Powered Web Vulnerability Scanner

Usage example:
    python ghostscanner.py --target scanme.nmap.org --ports 1-100 --output html -v
"""

import argparse
import sys
from rich.console import Console
from core.orchestrator import run_scan

console = Console()

def print_disclaimer():
    console.print("[bold red]WARNING:[/bold red] For authorized testing only. Do not scan systems you do not own or have explicit permission to test.")
    console.print("-" * 60)

def parse_args():
    parser = argparse.ArgumentParser(description="GhostScanner — AI-Powered Web Vulnerability Scanner")
    parser.add_argument("--target", required=True, help="IP or domain to scan")
    parser.add_argument("--ports", default="1-1000", help="Port range to scan (default: 1-1000)")
    parser.add_argument("--output", choices=["terminal", "json", "html"], default="terminal", help="Report format")
    parser.add_argument("--skip", help="Comma-separated modules to skip: ports, banners, owasp, cve, ai", default="")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose mode")
    
    return parser.parse_args()

def main():
    print_disclaimer()
    args = parse_args()
    
    try:
        run_scan(args.target, args.ports, args.output, args.skip, args.verbose)
    except KeyboardInterrupt:
        console.print("\n[bold red][!] Scan aborted by user.[/bold red]")
        sys.exit(1)
    except Exception as e:
        console.print(f"\n[bold red][!] A fatal error occurred: {e}[/bold red]")
        if args.verbose:
            import traceback
            console.print(traceback.format_exc())
        sys.exit(1)

if __name__ == "__main__":
    main()
