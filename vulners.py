import subprocess
import requests
import json
import joblib
import numpy as np
import logging
import schedule
import time
import smtplib

from urllib.parse import urljoin
from concurrent.futures import ThreadPoolExecutor
from termcolor import colored
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders

# Logging configuration
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

def print_banner():
    """
    Print the banner for the tool.
    """
    banner = """
    ===========================================
    |                                         |
    |   BCEVM Scanner - Hactivist Indonesia   |
    |                                         |
    ===========================================
    """
    print(colored(banner, "green"))

# Load pre-trained ML model for vulnerability detection
try:
    model = joblib.load("vuln_model.pkl")
    logger.info("ML model loaded successfully.")
except Exception as e:
    logger.error(f"Error loading ML model: {e}")
    model = None

def run_subfinder(target):
    """
    Run Subfinder to enumerate subdomains.
    """
    try:
        result = subprocess.run(
            ["subfinder", "-d", target, "-silent"],
            capture_output=True,
            text=True
        )
        return result.stdout.splitlines()
    except Exception as e:
        logger.error(f"Error running Subfinder: {e}")
        return []

def run_httpx(subdomains):
    """
    Run HTTPX to check active subdomains.
    """
    try:
        result = subprocess.run(
            ["httpx", "-silent", "-json"],
            input="\n".join(subdomains),
            text=True,
            capture_output=True
        )
        active_subdomains = []
        for line in result.stdout.splitlines():
            try:
                data = json.loads(line)
                active_subdomains.append(data.get("url"))
            except json.JSONDecodeError:
                continue
        return active_subdomains
    except Exception as e:
        logger.error(f"Error running HTTPX: {e}")
        return []

def run_waybackurls(subdomains):
    """
    Fetch URLs from Wayback Machine.
    """
    try:
        urls = []
        for subdomain in subdomains:
            result = subprocess.run(
                ["waybackurls"],
                input=subdomain,
                capture_output=True,
                text=True
            )
            urls.extend(result.stdout.splitlines())
        return urls
    except Exception as e:
        logger.error(f"Error running Waybackurls: {e}")
        return []

def run_paramspider(domain):
    """
    Run ParamSpider to gather parameterized URLs.
    """
    try:
        result = subprocess.run(
            ["paramspider", "--domain", domain, "--quiet"],
            capture_output=True,
            text=True
        )
        return result.stdout.splitlines()
    except Exception as e:
        logger.error(f"Error running ParamSpider: {e}")
        return []

def scan_vulnerability(url, payloads, vulnerability_name, severity):
    """
    Scan a single URL for a specific vulnerability.
    """
    for payload in payloads:
        try:
            response = requests.get(url, params={"input": payload}, timeout=5)
            if payload in response.text:
                logger.warning(f"Vulnerability found: {vulnerability_name} on {url}")
                return True, payload, severity
        except requests.exceptions.RequestException as e:
            logger.error(f"Request error for {url}: {e}")
    return False, None, None

def scan_url(url):
    """
    Scan a URL for various vulnerabilities.
    """
    issues = []
    logger.info(f"Scanning {url}...")

    vulnerabilities = {
        "Cross-Site Scripting (XSS)": (["<script>alert('XSS')</script>", "<img src=x onerror=alert('XSS')>", "<svg/onload=alert('XSS')>"], "Medium"),
        "SQL Injection": (["' OR '1'='1", "' UNION SELECT NULL, NULL, NULL--", "' AND 1=1--", "' OR 'a'='a"], "High"),
        "Open Redirect": (["//evil.com", "https://evil.com"], "High"),
        # Add more vulnerabilities as needed
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
    """
    Generate a text report of the vulnerabilities found.
    """
    with open(output_file, 'w', encoding='utf-8') as file:
        file.write("Vulnerability Scan Report\n")
        file.write("=" * 40 + "\n")
        for url, issues in vulnerabilities.items():
            file.write(f"\nURL: {url}\n")
            for vuln, payload, severity in issues:
                file.write(f"- {vuln}: {severity} (Payload: {payload})\n")

def send_notification(subject, body, attachment=None):
    """
    Send an email notification with the report.
    """
    try:
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
            part.add_header('Content-Disposition', f'attachment; filename={attachment}')
            msg.attach(part)

        server = smtplib.SMTP('smtp.example.com', 587)
        server.starttls()
        server.login('your_email@example.com', 'your_password')
        server.sendmail('your_email@example.com', 'receiver_email@example.com', msg.as_string())
        server.quit()
    except Exception as e:
        logger.error(f"Error sending email: {e}")

def perform_scan():
    """
    Perform the vulnerability scanning process.
    """
    target = 'example.com'
    output_file = 'scan_report.txt'

    logger.info("Scanning process started...")
    subdomains = run_subfinder(target)
    active_subdomains = run_httpx(subdomains)
    wayback_urls = run_waybackurls(active_subdomains)

    param_urls = []
    for sub in active_subdomains:
        param_urls.extend(run_paramspider(sub))

    urls = list(set(wayback_urls + param_urls))
    vulnerabilities = {}

    with ThreadPoolExecutor(max_workers=100) as executor:
        results = list(executor.map(scan_url, urls))
        for url, issues in results:
            if issues:
                vulnerabilities[url] = issues

    generate_report(vulnerabilities, output_file)
    send_notification("Vulnerability Scan Completed", f"Scan complete. Report saved to {output_file}", output_file)
    logger.info("Scanning process completed.")

def main():
    """
    Main entry point for the script.
    """
    print_banner()
    schedule.every().day.at("00:00").do(perform_scan)
    while True:
        schedule.run_pending()
        time.sleep(1)

if __name__ == "__main__":
    main()
