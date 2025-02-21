import subprocess
import requests
import json
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

def run_subfinder(domain):
    try:
        result = subprocess.run(["subfinder", "-d", domain, "-silent"], capture_output=True, text=True)
        return result.stdout.splitlines()
    except Exception as e:
        print(colored(f"Error running subfinder: {e}", 'red'))
        return []

def run_httpx(subdomains):
    try:
        result = subprocess.run(["httpx", "-silent", "-json"], input="\n".join(subdomains), text=True, capture_output=True)
        active_subdomains = [json.loads(line)["url"] for line in result.stdout.splitlines()]
        return active_subdomains
    except Exception as e:
        print(colored(f"Error running httpx: {e}", 'red'))
        return []

def run_waybackurls(subdomains):
    try:
        urls = []
        for subdomain in subdomains:
            result = subprocess.run(["waybackurls", subdomain], capture_output=True, text=True)
            urls.extend(result.stdout.splitlines())
        return urls
    except Exception as e:
        print(colored(f"Error running waybackurls: {e}", 'red'))
        return []

def filter_urls(urls):
    try:
        result = subprocess.run(["uro"], input="\n".join(urls), text=True, capture_output=True)
        return result.stdout.splitlines()
    except Exception as e:
        print(colored(f"Error running uro: {e}", 'red'))
        return []

def scan_logs(url):
    potential_paths = ["/logs", "/log.txt", "/error.log", "/access.log", "/admin", "/login"]
    for path in potential_paths:
        full_url = urljoin(url, path)
        try:
            response = requests.get(full_url, timeout=5)
            if response.status_code == 200 and len(response.text) > 0:
                return True, full_url
        except requests.RequestException:
            pass
    return False, None

def scan_with_owasp_zap(url):
    try:
        zap_api_key = 'tl2291dvtq639dv9fnaaovnfii'
        zap_base_url = 'http://localhost:8080'
        start_scan_url = f"{zap_base_url}/JSON/ascan/action/scan/?url={url}&apikey={zap_api_key}"
        response = requests.get(start_scan_url)
        if response.status_code == 200:
            return True
    except Exception as e:
        print(colored(f"Error running OWASP ZAP scan: {e}", 'red'))
    return False

def scan_url(url):
    issues = []
    print(colored(f"Scanning {url}...", 'yellow'))

    logs_found, log_url = scan_logs(url)
    if logs_found:
        issues.append(("Logs Found", log_url, "Medium"))

    zap_scan_started = scan_with_owasp_zap(url)
    if zap_scan_started:
        issues.append(("OWASP ZAP Scan Initiated", url, "High"))

    return url, issues

def generate_report(vulnerabilities, output_file):
    with open(output_file, 'w') as file:
        file.write("BCEVM - Vulnerability Scan Report\n")
        file.write("===========================================\n\n")
        for url, issues in vulnerabilities.items():
            file.write(f"URL: {url}\n")
            if issues:
                file.write("Vulnerabilities Found:\n")
                for issue, detail, severity in issues:
                    file.write(f"  - {issue} (Severity: {severity})")
                    if detail:
                        file.write(f" (Detail: {detail})")
                    file.write("\n")
            file.write("\n")

def display_vulnerabilities(vulnerabilities):
    for url, issues in vulnerabilities.items():
        if issues:
            print(colored(f"\nURL: {url}", "cyan"))
            for issue, detail, severity in issues:
                color = "yellow" if severity == "Low" else "blue" if severity == "Medium" else "red" if severity == "High" else "magenta"
                print(colored(f"  - {issue} (Severity: {severity})", color))
                if detail:
                    print(colored(f"    Detail: {detail}", color))

def main():
    print_banner()
    target = input("Enter target domain: ").strip()
    output_file = input("Enter output filename (e.g., results.txt): ").strip()

    print(colored("Running Subfinder...", 'green'))
    subdomains = run_subfinder(target)

    print(colored("Running Httpx...", 'green'))
    active_subdomains = run_httpx(subdomains)

    print(colored("Running Waybackurls...", 'green'))
    urls = run_waybackurls(active_subdomains)

    print(colored("Filtering URLs...", 'green'))
    filtered_urls = filter_urls(urls)

    print(colored("Starting vulnerability scans...", 'green'))
    vulnerabilities = {}
    with ThreadPoolExecutor(max_workers=100) as executor:
        results = list(executor.map(scan_url, filtered_urls))
        for url, issues in results:
            if issues:
                vulnerabilities[url] = issues

    display_vulnerabilities(vulnerabilities)
    generate_report(vulnerabilities, output_file)
    print(colored(f"\nScan complete. Report saved to {output_file}", 'green'))

if __name__ == "__main__":
    main()
