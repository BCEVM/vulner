import subprocess
import requests
import json
import joblib
import numpy as np
from urllib.parse import urljoin
from concurrent.futures import ThreadPoolExecutor
from termcolor import colored
from bs4 import BeautifulSoup

GITHUB_REPO = "https://github.com/BCEVM/vulner.git"

def print_banner():
    banner = """
    ===========================================
    |                                         |
    |   BCEVM Scanner - Hactivist Indonesia   |
    |                                         |
    ===========================================
    """
    print(colored(banner, 'red'))

# Load pre-trained ML model for vulnerability detection
try:
    model = joblib.load("vuln_model.pkl")
except:
    model = None

def run_subfinder(target):
    try:
        result = subprocess.run(["subfinder", "-d", target, "-silent"], capture_output=True, text=True)
        return result.stdout.splitlines()
    except Exception as e:
        print(f"Error running subfinder: {e}")
        return []

def run_httpx(subdomains):
    try:
        result = subprocess.run(["httpx", "-silent", "-json"], input="\n".join(subdomains), text=True, capture_output=True)
        active_subdomains = []
        for line in result.stdout.splitlines():
            data = json.loads(line)
            if data.get("url"):
                active_subdomains.append(data["url"])
        return active_subdomains
    except Exception as e:
        print(f"Error running httpx: {e}")
        return []

def run_waybackurls(subdomains):
    try:
        urls = []
        for subdomain in subdomains:
            result = subprocess.run(["waybackurls"], input=subdomain, capture_output=True, text=True)
            urls.extend(result.stdout.splitlines())
        return urls
    except Exception as e:
        print(f"Error running waybackurls: {e}")
        return []

def scan_vulnerability(url, payloads, vulnerability_name, severity):
    for payload in payloads:
        try:
            response = requests.get(url, params={"input": payload}, timeout=5)
            if payload in response.text:
                return True, payload, severity
        except requests.RequestException:
            pass
    return False, None, None

def scan_url(url):
    issues = []
    print(f"Scanning {url}...")
    
    vulnerabilities = {
        "Cross-Site Scripting (XSS)": (["<script>alert('XSS')</script>", "<img src=x onerror=alert('XSS')>", "<svg/onload=alert('XSS')>"], "Medium"),
        "SQL Injection": (["' OR '1'='1", "' UNION SELECT NULL, NULL, NULL--", "' AND 1=1--", "' OR 'a'='a"], "High"),
        "Open Redirect": (["//evil.com", "https://evil.com"], "High"),
        "Improper Authentication": (["admin", "password", "123456"], "High"),
        "Information Disclosure": (["/debug", "/info", "/phpinfo.php"], "Medium"),
        "Improper Access Control": (["/admin", "/secure", "/private"], "High"),
        "IDOR": (["?id=1", "?user=admin"], "High"),
        "Misconfiguration": (["/.env", "/config.php", "/backup.zip"], "Medium"),
        "Privilege Escalation": (["/root", "/superadmin"], "High"),
        "Business Logic Errors": (["/cart/add?item=999999"], "Medium"),
        "Improper Authorization": (["/restricted", "/admin-only"], "High"),
    }
    
    for vuln, (payloads, severity) in vulnerabilities.items():
        found, payload, sev = scan_vulnerability(url, payloads, vuln, severity)
        if found:
            issues.append((vuln, payload, sev))
    
    # Use ML model to refine results if available
    if model:
        predictions = model.predict(np.array([url]))
        if predictions[0] == 1:
            issues.append(("ML-Detected Potential Vulnerability", "N/A", "Critical"))
    
    return url, issues

def generate_report(vulnerabilities, output_file):
    with open(output_file, 'w', encoding='utf-8') as file:
        file.write("Vulnerability Scan Report\n")
        file.write("===========================================\n\n")
        for url, issues in vulnerabilities.items():
            file.write(f"URL: {url}\n")
            if issues:
                file.write("Vulnerabilities Found:\n")
                for issue, payload, severity in issues:
                    color = "yellow" if severity == "Low" else "blue" if severity == "Medium" else "red" if severity == "High" else "magenta"
                    file.write(f"  - {issue} (Severity: {severity})")
                    if payload:
                        file.write(f" (Payload: {payload})")
                    file.write("\n")
            file.write("\n")

def main():
    target = input("Enter target domain: ").strip()
    output_file = input("Enter output filename (e.g., results.txt): ").strip()
    
    print("Scanning proses 1...")
    subdomains = run_subfinder(target)

    print("Running proses 2...")
    active_subdomains = run_httpx(subdomains)
    
    print("Running proses 3...")
    urls = run_waybackurls(active_subdomains)

    print("Starting vulnerability scans...")
    vulnerabilities = {}
    with ThreadPoolExecutor(max_workers=1000) as executor:
        results = list(executor.map(scan_url, urls))
        for url, issues in results:
            if issues:
                vulnerabilities[url] = issues
    
    generate_report(vulnerabilities, output_file)
    print(f"Scan complete. Report saved to {output_file}")

if __name__ == "__main__":
    main()
