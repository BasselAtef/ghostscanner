import os
import json
import google.generativeai as genai
from rich.console import Console

console = Console()

def analyze_findings(findings, verbose):
    api_key = os.environ.get("GEMINI_API_KEY")
    if not api_key:
        return "Error: GEMINI_API_KEY not set."
        
    genai.configure(api_key=api_key)
    
    # We use gemini-2.0-flash as requested
    model = genai.GenerativeModel("gemini-2.0-flash")
    
    prompt = f"""
    You are a senior penetration tester and cybersecurity expert.
    I have run a vulnerability scan on a target and here are the raw findings in JSON format:
    
    {json.dumps(findings, indent=2, default=str)}
    
    Please provide a structured markdown report that includes:
    1. An executive summary.
    2. Prioritized vulnerabilities by severity (Critical, High, Medium, Low).
    3. An explanation of each identified issue in plain English.
    4. Concrete, actionable remediation steps for each vulnerability.
    
    Ensure the report is professional and actionable.
    """
    
    try:
        response = model.generate_content(prompt)
        return response.text
    except Exception as e:
        if verbose:
            console.print(f"[red][!] Gemini API Error: {e}[/red]")
        return f"Error during AI analysis: {e}"
