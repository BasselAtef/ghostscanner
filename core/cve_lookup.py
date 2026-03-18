import httpx
from rich.console import Console

console = Console()

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

def query_nvd(keyword, verbose):
    url = f"{NVD_API_URL}?keywordSearch={keyword}&keywordExactMatch=false"
    try:
        r = httpx.get(url, timeout=10.0)
        if r.status_code == 200:
            data = r.json()
            vulnerabilities = data.get("vulnerabilities", [])
            results = []
            for item in vulnerabilities[:5]:  # Limit to top 5 to avoid enormous results
                cve = item.get("cve", {})
                cve_id = cve.get("id")
                
                # Try to extract CVSS score
                metrics = cve.get("metrics", {})
                cvss_score = "N/A"
                if "cvssMetricV31" in metrics:
                    cvss_score = metrics["cvssMetricV31"][0]["cvssData"]["baseScore"]
                elif "cvssMetricV30" in metrics:
                    cvss_score = metrics["cvssMetricV30"][0]["cvssData"]["baseScore"]
                elif "cvssMetricV2" in metrics:
                    cvss_score = metrics["cvssMetricV2"][0]["cvssData"]["baseScore"]
                
                description = ""
                for desc in cve.get("descriptions", []):
                    if desc.get("lang") == "en":
                        description = desc.get("value")
                        break
                        
                results.append({"cve_id": cve_id, "score": cvss_score, "description": description})
            return results
    except Exception as e:
        if verbose:
            console.print(f"[red][!] Error querying NVD for {keyword}: {e}[/red]")
    return []

def lookup_cves(banners, verbose):
    cve_results = {}
    for port, info in banners.items():
        server_str = info.get("server", "")
        if not server_str:
            continue
            
        # Clean up server string for better search
        keyword = server_str.split("(")[0].replace("/", " ").strip()
        if not keyword:
            continue
            
        if verbose:
            console.print(f"[*] Looking up CVEs for: {keyword}")
            
        cves = query_nvd(keyword, verbose)
        if cves:
            cve_results[port] = {"software": keyword, "cves": cves}
            
    return cve_results
