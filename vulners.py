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

def update_tool():
    print(colored("Checking for updates...", 'yellow'))
    subprocess.run(["git", "pull", GITHUB_REPO], capture_output=True, text=True)
    print(colored("Update completed!", 'green'))

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
            result = subprocess.run(["waybackurls", subdomain], capture_output=True, text=True)
            urls.extend(result.stdout.splitlines())
        return urls
    except Exception as e:
        print(f"Error running waybackurls: {e}")
        return []

def filter_urls(urls):
    try:
        result = subprocess.run(["uro"], input="\n".join(urls), text=True, capture_output=True)
        return result.stdout.splitlines()
    except Exception as e:
        print(f"Error running uro: {e}")
        return []

def scan_logs(url):
    potential_paths = ["/logs", "/log.txt", "/error.log", "/access.log", "/debug.log", "/system.log", "/database.log", "/backup.log", "/config/logs", "/var/logs", "/log/errors.log", "/server.log", "/admin.log", "/auth.log"]
    for path in potential_paths:
        try:
            full_url = urljoin(url, path)
            response = requests.get(full_url, timeout=5)
            if response.status_code == 200 and len(response.text) > 0:
                return True, path, "Medium"
        except requests.RequestException:
            pass
    return False, None, None

def generate_report(vulnerabilities, output_file):
    with open(output_file, 'w') as file:
        file.write("Klandestine by BCEVM - Vulnerability Scan Report\n")
        file.write("===========================================\n\n")
        for url, issues in vulnerabilities.items():
            file.write(f"URL: {url}\n")
            if issues:
                file.write("Vulnerabilities Found:\n")
                for issue, payload, severity in issues:
                    file.write(f"  - {issue} (Severity: {severity})")
                    if payload:
                        file.write(f" (Payload: {payload})")
                    file.write("\n")
            file.write("\n")

def display_vulnerabilities(vulnerabilities):
    for url, issues in vulnerabilities.items():
        if issues:
            print(colored(f"URL: {url}", "cyan"))
            for issue, payload, severity in issues:
                color = "yellow" if severity == "Low" else "blue" if severity == "Medium" else "red" if severity == "High" else "magenta"
                print(colored(f"  - {issue} (Severity: {severity})", color))
                if payload:
                    print(colored(f"    Payload: {payload}", color))

def scan_url(url):
    issues = []
    print(f"Scanning {url}...")
    logs_found, log_payload, log_severity = scan_logs(url)
    if logs_found:
        issues.append(("Logs Found", log_payload, log_severity))
    return url, issues

def main():
    print_banner()
    target = input("Enter target domain: ").strip()
    output_file = input("Enter output filename (e.g., results.txt): ").strip()
    
    print("Running Subfinder...")
    subdomains = run_subfinder(target)

    print("Running Httpx...")
    active_subdomains = run_httpx(subdomains)

    print("Running Waybackurls...")
    urls = run_waybackurls(active_subdomains)

    print("Filtering URLs...")
    filtered_urls = filter_urls(urls)

    print("Starting vulnerability scans...")
    vulnerabilities = {}
    with ThreadPoolExecutor(max_workers=10) as executor:
        results = list(executor.map(scan_url, filtered_urls))
        for url, issues in results:
            if issues:
                vulnerabilities[url] = issues

    display_vulnerabilities(vulnerabilities)
    generate_report(vulnerabilities, output_file)
    print(f"Scan complete. Report saved to {output_file}")

if __name__ == "__main__":
    main()
