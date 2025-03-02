import subprocess
import requests
import json
import joblib
import numpy as np
from urllib.parse import urljoin
from concurrent.futures import ThreadPoolExecutor
from termcolor import colored
from bs4 import BeautifulSoup
import logging
import schedule
import time
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import matplotlib.pyplot as plt

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

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
except Exception as e:
    logger.error(f"Error loading ML model: {e}")
    model = None

def run_subfinder(target):
    try:
        result = subprocess.run(["subfinder", "-d", target, "-silent"], capture_output=True, text=True)
        return result.stdout.splitlines()
    except Exception as e:
        logger.error(f"Error running subfinder: {e}")
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
        logger.error(f"Error running httpx: {e}")
        return []

def run_waybackurls(subdomains):
    try:
        urls = []
        for subdomain in subdomains:
            result = subprocess.run(["waybackurls"], input=subdomain, capture_output=True, text=True)
            urls.extend(result.stdout.splitlines())
        return urls
    except Exception as e:
        logger.error(f"Error running waybackurls: {e}")
        return []

def scan_vulnerability(url, payloads, vulnerability_name, severity):
    for payload in payloads:
        try:
            response = requests.get(url, params={"input": payload}, timeout=5)
            if payload in response.text:
                return True, payload, severity
        except requests.RequestException as e:
            logger.error(f"Request exception for {url} with payload {payload}: {e}")
    return False, None, None

def scan_url(url):
    issues = []
    logger.info(f"Scanning {url}...")
    
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
    
    if model:
        try:
            predictions = model.predict(np.array([url]))
            if predictions[0] == 1:
                issues.append(("ML-Detected Potential Vulnerability", "N/A", "Critical"))
        except Exception as e:
            logger.error(f"Error using ML model for {url}: {e}")
    
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
    generate_visual_report(vulnerabilities, output_file.replace(".txt", ".png"))

def generate_visual_report(vulnerabilities, output_image):
    labels = ["Low", "Medium", "High", "Critical"]
    counts = [0, 0, 0, 0]
    for issues in vulnerabilities.values():
        for _, _, severity in issues:
            if severity == "Low":
                counts[0] += 1
            elif severity == "Medium":
                counts[1] += 1
            elif severity == "High":
                counts[2] += 1
            elif severity == "Critical":
                counts[3] += 1
    plt.figure(figsize=(10, 6))
    plt.bar(labels, counts, color=["yellow", "blue", "red", "magenta"])
    plt.xlabel("Severity Levels")
    plt.ylabel("Number of Issues")
    plt.title("Vulnerability Severity Distribution")
    plt.savefig(output_image)

def send_notification(subject, body, attachment=None):
    msg = MIMEMultipart()
    msg['From'] = 'your_email@example.com'
    msg['To'] = 'receiver_email@example.com'
    msg['Subject'] = subject

    msg.attach(MIMEText(body, 'plain'))

    if attachment:
        with open(attachment, 'rb') as f:
            part = MIMEBase('application', 'octet-stream')
            part.set_payload(f.read())
            encoders.encode_base64(part)
            part.add_header(
                'Content-Disposition',
                f'attachment; filename= {attachment}',
            )
            msg.attach(part)

    server = smtplib.SMTP('smtp.example.com', 587)
    server.starttls()
    server.login('your_email@example.com', 'your_password')
    text = msg.as_string()
    server.sendmail('your_email@example.com', 'receiver_email@example.com', text)
    server.quit()

def perform_scan():
    target = 'example.com'
    output_file = 'scan_report.txt'
    
    logger.info("Scanning proses 1...")
    subdomains = run_subfinder(target)

    logger.info("Running proses 2...")
    active_subdomains = run_httpx(subdomains)
    
    logger.info("Running proses 3...")
    urls = run_waybackurls(active_subdomains)

    logger.info("Starting vulnerability scans...")
    vulnerabilities = {}
    with ThreadPoolExecutor(max_workers=1000) as executor:
        results = list(executor.map(scan_url, urls))
        for url, issues in results:
            if issues:
                vulnerabilities[url] = issues
    
    generate_report(vulnerabilities, output_file)
    send_notification("Vulnerability Scan Completed", f"Scan complete. Report saved to {output_file}", output_file)
    logger.info(f"Scan complete. Report saved to {output_file}")

def main():
    print_banner()
    schedule.every().day.at("00:00").do(perform_scan)
    while True:
        schedule.run_pending()
        time.sleep(1)

if __name__ == "__main__":
    main()
