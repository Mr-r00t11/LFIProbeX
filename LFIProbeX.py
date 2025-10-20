#!/usr/bin/python3
import requests
import argparse
import urllib.parse
from colorama import Fore, Style, Back, init
import sys
import time
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
import re
import base64
import urllib.request
import urllib.parse

# Initialize colorama for Windows
init(autoreset=True)

class LFIAuditor:
    def __init__(self, verbose=False, threads=5, timeout=10, encoding_type=None):
        self.verbose = verbose
        self.threads = threads
        self.timeout = timeout
        self.encoding_type = encoding_type
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        
        # Specific and reliable indicators for /etc/passwd
        self.success_indicators = [
            # Specific /etc/passwd structures - STRICTER
            "root:x:0:0:",
            "root:*:0:0:",
            "root::0:0:",
            "daemon:x:1:1:",
            "bin:x:2:2:",
            "sys:x:3:3:",
            "sync:x:4:65534:",
            "games:x:5:60:",
            "man:x:6:12:",
            "lp:x:7:7:",
            "mail:x:8:8:",
            "news:x:9:9:",
            "uucp:x:10:10:",
            "proxy:x:13:13:",
            "www-data:x:33:33:",
            "backup:x:34:34:",
            "list:x:38:38:",
            "irc:x:39:39:",
            "gnats:x:41:41:",
            "nobody:x:65534:65534:",
            "_apt:x:100:65534:",
            "systemd-timesync:x:100:103:",
            "systemd-network:x:101:104:",
            "systemd-resolve:x:102:105:",
            "messagebus:x:103:109:",
            "sshd:x:104:65534:",
            "mysql:x:105:111:",
            "postgres:x:106:112:",
            
            # Strict passwd format patterns
            r"^root:[x*]?:0:0:[^:]*:/[^:]*:/[^:]*$",
            r"^[a-zA-Z0-9_-]+:[x*]?:\d+:\d+:[^:]*:/[^:]*:/[^:]*$"
        ]

        # Compile regex patterns for better performance
        self.compiled_patterns = []
        for indicator in self.success_indicators:
            if indicator.startswith("^") or indicator.startswith(r"^"):
                try:
                    self.compiled_patterns.append(re.compile(indicator, re.MULTILINE | re.IGNORECASE))
                except:
                    self.compiled_patterns.append(None)
            else:
                self.compiled_patterns.append(None)

    def encode_payload(self, payload):
        """Apply encoding to payload according to specified type"""
        if not self.encoding_type:
            return payload
        
        encoding_type = self.encoding_type.lower()
        
        if encoding_type == "url":
            return urllib.parse.quote(payload)
        elif encoding_type == "double_url":
            return urllib.parse.quote(urllib.parse.quote(payload))
        elif encoding_type == "base64":
            return base64.b64encode(payload.encode()).decode()
        elif encoding_type == "base64_url":
            encoded = base64.b64encode(payload.encode()).decode()
            return urllib.parse.quote(encoded)
        elif encoding_type == "html":
            return payload.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;').replace('"', '&quot;').replace("'", '&#x27;')
        elif encoding_type == "unicode":
            return ''.join([f'%u{ord(c):04x}' for c in payload])
        elif encoding_type == "utf8":
            return payload.encode('utf-8').hex()
        elif encoding_type == "hex":
            return payload.encode().hex()
        else:
            self.print_warning(f"Unrecognized encoding type: {encoding_type}. Using unencoded payload.")
            return payload

    def print_banner(self, text, color=Fore.CYAN, style=Style.BRIGHT):
        """Print a colorful banner"""
        banner_width = 70
        padded_text = f" {text} ".center(banner_width, "=")
        print(f"{color}{style}{padded_text}{Style.RESET_ALL}")

    def print_success(self, text):
        """Print success message"""
        print(f"{Fore.GREEN}{Style.BRIGHT}[+] LFI_SUCCESS DETECTED! {text}{Style.RESET_ALL}")

    def print_warning(self, text):
        """Print warning message"""
        print(f"{Fore.YELLOW}{Style.BRIGHT}[!] {text}{Style.RESET_ALL}")

    def print_error(self, text):
        """Print error message"""
        print(f"{Fore.RED}{Style.BRIGHT}[✗] {text}{Style.RESET_ALL}")

    def print_info(self, text):
        """Print informational message"""
        if self.verbose:  # Only print if verbose is enabled
            print(f"{Fore.CYAN}{Style.BRIGHT}[*] {text}{Style.RESET_ALL}")

    def print_verbose(self, text):
        """Print message only in verbose mode"""
        if self.verbose:
            print(f"{Fore.BLUE}{Style.BRIGHT}[VERBOSE] {text}{Style.RESET_ALL}")

    def detect_success_indicator(self, text):
        """Detect success indicators in response text - STRICTER"""
        # First check with strict regex patterns
        for i, indicator in enumerate(self.success_indicators):
            if self.compiled_patterns[i] is not None:
                matches = self.compiled_patterns[i].findall(text)
                if matches:
                    # Additional verification: must have multiple lines matching passwd format
                    if len(matches) >= 2:
                        return f"passwd_structure_{i}", "strict_regex_pattern"
        
        # Then check with simple strings but with additional verification
        text_lower = text.lower()
        for i, indicator in enumerate(self.success_indicators):
            if self.compiled_patterns[i] is None and indicator.lower() in text_lower:
                # Additional verification for simple strings: must appear in full line context
                lines = text.split('\n')
                matching_lines = 0
                for line in lines:
                    if indicator in line:
                        # Verify that the line has passwd-like format
                        if ':' in line and len(line.split(':')) >= 6:
                            matching_lines += 1
                
                if matching_lines >= 2:
                    return indicator, "verified_string_match"
        
        # Advanced and strict detection of /etc/passwd
        if self.detect_etc_passwd_structure(text):
            return "etc_passwd_confirmed", "structure_analysis"
            
        return None, None

    def detect_etc_passwd_structure(self, text):
        """VERY STRICT detection of /etc/passwd structure"""
        lines = text.split('\n')
        passwd_like_lines = 0
        
        for line in lines:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
                
            # VERY strict /etc/passwd pattern
            parts = line.split(':')
            if len(parts) == 7:  # EXACTLY 7 parts
                # Verify strict format
                username, password, uid, gid, gecos, home, shell = parts
                
                # Strict verifications:
                # 1. UID and GID must be numeric
                if not uid.isdigit() or not gid.isdigit():
                    continue
                    
                # 2. Password field must be x, * or empty
                if password not in ['x', '*', '']:
                    continue
                    
                # 3. Home directory must start with /
                if not home.startswith('/'):
                    continue
                    
                # 4. Shell must be a valid path or /usr/sbin/nologin, /bin/false, etc.
                valid_shells = ['/bin/', '/usr/bin/', '/sbin/', '/usr/sbin/', '/bin/sh', '/bin/bash', 
                               '/bin/false', '/usr/sbin/nologin', '/sbin/nologin']
                if not any(shell.startswith(valid_shell) for valid_shell in valid_shells):
                    continue
                
                # 5. Username must be alphanumeric or with _ -
                if not re.match(r'^[a-zA-Z0-9_-]+$', username):
                    continue
                    
                passwd_like_lines += 1
        
        # Require at least 3 lines that meet the strict format
        return passwd_like_lines >= 3

    def parse_burp_request(self, file_path):
        """Parse a Burp Suite request file and automatically detect host and URL"""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            # Automatically extract information from request
            lines = content.strip().split('\n')
            if not lines:
                return None, None, None
            
            # Parse first line to get method and path
            first_line = lines[0].split()
            if len(first_line) < 3:
                self.print_error("Invalid request format - incomplete first line")
                return None, None, None
            
            method = first_line[0]
            path = first_line[1]
            
            # Find Host header
            host = None
            for line in lines[1:]:
                if line.lower().startswith('host:'):
                    host = line.split(':', 1)[1].strip()
                    break
            
            if not host:
                self.print_error("Could not detect Host in Burp request")
                return None, None, None
            
            # Build complete URL
            url = f"http://{host}{path}"  # Assume HTTP by default
            
            self.print_verbose(f"Detected from Burp request:")
            self.print_verbose(f"  Method: {method}")
            self.print_verbose(f"  Host: {host}")
            self.print_verbose(f"  Path: {path}")
            self.print_verbose(f"  Complete URL: {url}")
            
            return content, url, method
            
        except Exception as e:
            self.print_error(f"Error parsing Burp file {file_path}: {str(e)}")
            return None, None, None

    def extract_info_from_burp(self, burp_content):
        """Extract information from Burp request"""
        lines = burp_content.strip().split('\n')
        if not lines:
            return None, None, None, None
        
        # Parse first line (method, URL, protocol)
        first_line = lines[0].split()
        if len(first_line) < 3:
            self.print_error("Invalid request format")
            return None, None, None, None
        
        method = first_line[0]
        url_path = first_line[1]
        
        # Parse headers
        headers = {}
        body = ""
        body_started = False
        
        for line in lines[1:]:
            if not line.strip():
                body_started = True
                continue
            
            if not body_started:
                if ':' in line:
                    key, value = line.split(':', 1)
                    headers[key.strip()] = value.strip()
            else:
                body += line + '\n'
        
        return method, url_path, headers, body.strip()

    def extract_parameters(self, url, body=None, content_type=None):
        """Extract parameters from URL and body if POST"""
        parsed = urllib.parse.urlparse(url)
        params = {}
        
        # Extract parameters from query string
        if parsed.query:
            params.update(urllib.parse.parse_qs(parsed.query))
        
        # Also consider parameters in fragment (less common)
        if parsed.fragment and '=' in parsed.fragment:
            params.update(urllib.parse.parse_qs(parsed.fragment))
        
        # Extract parameters from body for POST requests
        if body and content_type and 'application/x-www-form-urlencoded' in content_type:
            body_params = urllib.parse.parse_qs(body)
            params.update(body_params)
        
        return params, parsed

    def build_test_requests(self, base_url, params, payload, target_params=None, method="GET", body=None, headers=None, burp_content=None):
        """Build test requests for specific parameters"""
        test_requests = []
        parsed_base = urllib.parse.urlparse(base_url)
        
        # Apply encoding to payload if specified
        encoded_payload = self.encode_payload(payload)
        
        # If target parameters specified, use only those
        if target_params:
            params_to_test = [p for p in target_params if p in params]
        else:
            # If not specified, test all parameters
            params_to_test = params.keys()
        
        for param in params_to_test:
            # Create new query string replacing parameter value
            new_params = params.copy()
            new_params[param] = encoded_payload
            
            if burp_content and method.upper() in ["POST", "PUT", "PATCH"]:
                # For Burp requests, modify complete content
                test_body = self.modify_burp_request_body(burp_content, param, encoded_payload)
                test_data = {
                    'url': base_url,
                    'method': method,
                    'headers': headers,
                    'body': test_body,
                    'burp_content': test_body
                }
            elif method.upper() == "GET":
                # Rebuild URL for GET
                new_query = urllib.parse.urlencode(new_params, doseq=True)
                test_url = urllib.parse.urlunparse((
                    parsed_base.scheme,
                    parsed_base.netloc,
                    parsed_base.path,
                    parsed_base.params,
                    new_query,
                    parsed_base.fragment
                ))
                test_data = {
                    'url': test_url,
                    'method': 'GET',
                    'headers': headers,
                    'body': None,
                    'burp_content': None
                }
            else:
                # For normal POST, keep original URL and modify body
                test_url = base_url
                if body and 'application/x-www-form-urlencoded' in headers.get('Content-Type', ''):
                    # Rebuild body for POST
                    new_body = urllib.parse.urlencode(new_params, doseq=True)
                    test_data = {
                        'url': test_url,
                        'method': method,
                        'headers': headers,
                        'body': new_body,
                        'burp_content': None
                    }
                else:
                    # For other POST types, use parameters in URL
                    new_query = urllib.parse.urlencode(new_params, doseq=True)
                    test_url = urllib.parse.urlunparse((
                        parsed_base.scheme,
                        parsed_base.netloc,
                        parsed_base.path,
                        parsed_base.params,
                        new_query,
                        parsed_base.fragment
                    ))
                    test_data = {
                        'url': test_url,
                        'method': 'GET',  # Change to GET if not form encoded
                        'headers': headers,
                        'body': None,
                        'burp_content': None
                    }
            
            test_requests.append((test_data, param))
            
        return test_requests

    def modify_burp_request_body(self, burp_content, param, payload):
        """Modify Burp request body with payload"""
        lines = burp_content.split('\n')
        body_started = False
        new_lines = []
        
        for line in lines:
            if not line.strip():
                body_started = True
                new_lines.append(line)
                continue
            
            if not body_started:
                new_lines.append(line)
            else:
                # In body, search and replace parameter
                if '=' in line:
                    parts = line.split('=')
                    if parts[0].strip() == param:
                        # Replace parameter value
                        new_lines.append(f"{param}={payload}")
                    else:
                        new_lines.append(line)
                else:
                    new_lines.append(line)
        
        return '\n'.join(new_lines)

    def test_payload(self, test_data):
        """Test a specific payload"""
        request_data, param, payload = test_data
        
        # Show current test if verbose is enabled
        if self.verbose:
            self.print_verbose(f"Testing: {param}={payload}")
        
        try:
            if request_data.get('burp_content'):
                # Use modified complete Burp content
                burp_lines = request_data['burp_content'].split('\n')
                method = request_data['method']
                url = request_data['url']
                headers = request_data['headers']
                
                # Rebuild complete request
                first_line = f"{method} {urllib.parse.urlparse(url).path} HTTP/1.1"
                header_lines = []
                body_lines = []
                in_body = False
                
                for line in burp_lines[1:]:
                    if not line.strip() and not in_body:
                        in_body = True
                        continue
                    if not in_body:
                        header_lines.append(line)
                    else:
                        body_lines.append(line)
                
                # Combine headers
                full_headers = {}
                for line in header_lines:
                    if ':' in line:
                        key, value = line.split(':', 1)
                        full_headers[key.strip()] = value.strip()
                
                # Update host header if necessary
                if 'Host' not in full_headers:
                    full_headers['Host'] = urllib.parse.urlparse(url).netloc
                
                body_content = '\n'.join(body_lines) if body_lines else None
                
                if method.upper() == 'GET':
                    response = self.session.get(
                        url,
                        headers=full_headers,
                        timeout=self.timeout,
                        verify=False
                    )
                else:
                    response = self.session.request(
                        method=method,
                        url=url,
                        headers=full_headers,
                        data=body_content,
                        timeout=self.timeout,
                        verify=False
                    )
            else:
                # Normal request
                if request_data['method'] == 'GET':
                    response = self.session.get(
                        request_data['url'], 
                        headers=request_data['headers'],
                        timeout=self.timeout, 
                        verify=False
                    )
                else:
                    response = self.session.post(
                        request_data['url'],
                        data=request_data['body'],
                        headers=request_data['headers'],
                        timeout=self.timeout,
                        verify=False
                    )
            
            # STRICT success verification
            indicator, indicator_type = self.detect_success_indicator(response.text)
            
            if indicator:
                return {
                    'vulnerable': True,
                    'url': request_data['url'],
                    'method': request_data['method'],
                    'parameter': param,
                    'payload': payload,
                    'encoded_payload': request_data['url'].split(param + '=')[1].split('&')[0] if '?' in request_data['url'] else payload,
                    'indicator': indicator,
                    'indicator_type': indicator_type,
                    'response_length': len(response.text),
                    'status_code': response.status_code,
                    'body_used': request_data['body'] is not None,
                    'burp_used': request_data.get('burp_content') is not None
                }
            
            return {
                'vulnerable': False,
                'url': request_data['url'],
                'method': request_data['method'],
                'parameter': param,
                'payload': payload,
                'status_code': response.status_code,
                'body_used': request_data['body'] is not None,
                'burp_used': request_data.get('burp_content') is not None
            }
            
        except requests.exceptions.RequestException as e:
            if self.verbose:
                self.print_error(f"Error with {param}={payload}: {str(e)}")
            return {
                'vulnerable': False,
                'url': request_data['url'],
                'method': request_data['method'],
                'parameter': param,
                'payload': payload,
                'error': str(e)
            }

    def audit_request(self, request_file, wordlist_path, target_params=None):
        """Audit a Burp Suite request with automatic host and URL detection"""
        self.print_banner(f"AUDITING REQUEST: {request_file}")
        
        # Parse Burp request with automatic detection
        burp_content, detected_url, detected_method = self.parse_burp_request(request_file)
        
        if not burp_content or not detected_url:
            self.print_error(f"Could not parse request from {request_file}")
            return []
        
        # Extract additional request information
        method, url_path, headers, body = self.extract_info_from_burp(burp_content)
        
        if not method or not url_path:
            self.print_error(f"Invalid request in {request_file}")
            return []
        
        # Use automatically detected URL
        url = detected_url
        method = detected_method

        self.print_info(f"Method: {method}")
        self.print_info(f"Detected URL: {url}")
        if self.encoding_type:
            self.print_info(f"Encoding applied: {self.encoding_type}")
        self.print_success("Burp request loaded successfully")
        
        # Show important headers
        if self.verbose:
            self.print_info("Request headers:")
            for key, value in headers.items():
                if key.lower() in ['host', 'content-type', 'cookie', 'user-agent']:
                    print(f"   {Fore.CYAN}{key}: {value}{Style.RESET_ALL}")
        
        # Extract parameters
        content_type = headers.get('Content-Type', '') if headers else ''
        params, parsed = self.extract_parameters(url, body, content_type)
        
        if not params:
            self.print_warning("No parameters found in request")
            return []
        
        # Show parameter information
        all_params = list(params.keys())
        if target_params:
            # Filter target parameters that exist in request
            target_params = [p for p in target_params if p in params]
            self.print_info(f"All parameters: {', '.join(all_params)}")
            self.print_info(f"Target parameters: {', '.join(target_params)}")
            
            # Show warning if some target parameters don't exist
            missing_params = set(target_params) - set(all_params)
            if missing_params:
                self.print_warning(f"Parameters not found: {', '.join(missing_params)}")
        else:
            self.print_info(f"Testing all parameters: {', '.join(all_params)}")
        
        # Show request type
        if body and method.upper() == "POST":
            self.print_success("Body parameters will be tested")
        
        vulnerable_findings = []
        tested_count = 0
        
        with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
            payloads = [line.strip() for line in f if line.strip()]
        
        self.print_info(f"Payloads loaded: {len(payloads)}")
        
        # Prepare data for testing
        test_data = []
        for payload in payloads:
            test_requests = self.build_test_requests(url, params, payload, target_params, method, body, headers, burp_content)
            for test_request, param in test_requests:
                test_data.append((test_request, param, payload))
        
        if not test_data:
            self.print_warning("No parameters to test")
            return []
        
        self.print_info(f"Total tests to perform: {len(test_data)}")
        
        # Execute tests with threads
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            future_to_test = {
                executor.submit(self.test_payload, data): data 
                for data in test_data
            }
            
            for future in as_completed(future_to_test):
                result = future.result()
                tested_count += 1
                
                if result['vulnerable']:
                    # Show the specific message you requested
                    self.print_success(f"Vulnerability found!")
                    print(f"   {Fore.CYAN}URL:{Style.RESET_ALL} {result['url']}")
                    print(f"   {Fore.CYAN}Parameter:{Style.RESET_ALL} {result['parameter']}")
                    print(f"   {Fore.CYAN}Original payload:{Style.RESET_ALL} {result['payload']}")
                    if self.encoding_type:
                        print(f"   {Fore.CYAN}Encoded payload:{Style.RESET_ALL} {result.get('encoded_payload', result['payload'])}")
                    print(f"   {Fore.CYAN}Detected indicator:{Style.RESET_ALL} {result['indicator']}")
                    print(f"   {Fore.CYAN}Type:{Style.RESET_ALL} {result['indicator_type']}")
                    print(f"   {Fore.CYAN}Status Code:{Style.RESET_ALL} {result['status_code']}")
                    
                    vulnerable_findings.append(result)
                        
                else:
                    if 'error' in result:
                        if self.verbose:
                            self.print_error(f"Error with {result['parameter']}={result['payload']}: {result['error']}")
                    else:
                        if tested_count % 50 == 0 and self.verbose:  # Show progress only in verbose
                            self.print_info(f"Tested {tested_count}/{len(test_data)} payloads...")
        
        return vulnerable_findings

    def audit_url(self, url, wordlist_path, target_params=None):
        """Audit a specific URL with the wordlist"""
        self.print_banner(f"AUDITING URL: {url}")
        
        if self.encoding_type:
            self.print_info(f"Encoding applied: {self.encoding_type}")
        
        # Extract parameters
        params, parsed = self.extract_parameters(url)
        
        if not params:
            self.print_warning(f"No parameters found in URL: {url}")
            return []
        
        # Show parameter information
        all_params = list(params.keys())
        if target_params:
            # Filter target parameters that exist in URL
            target_params = [p for p in target_params if p in params]
            self.print_info(f"All parameters: {', '.join(all_params)}")
            self.print_info(f"Target parameters: {', '.join(target_params)}")
            
            # Show warning if some target parameters don't exist
            missing_params = set(target_params) - set(all_params)
            if missing_params:
                self.print_warning(f"Parameters not found: {', '.join(missing_params)}")
        else:
            self.print_info(f"Testing all parameters: {', '.join(all_params)}")
        
        vulnerable_findings = []
        tested_count = 0
        
        with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
            payloads = [line.strip() for line in f if line.strip()]
        
        self.print_info(f"Payloads loaded: {len(payloads)}")
        
        # Prepare data for testing
        test_data = []
        for payload in payloads:
            test_requests = self.build_test_requests(url, params, payload, target_params)
            for test_request, param in test_requests:
                test_data.append((test_request, param, payload))
        
        if not test_data:
            self.print_warning("No parameters to test")
            return []
        
        self.print_info(f"Total tests to perform: {len(test_data)}")
        
        # Execute tests with threads
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            future_to_test = {
                executor.submit(self.test_payload, data): data 
                for data in test_data
            }
            
            for future in as_completed(future_to_test):
                result = future.result()
                tested_count += 1
                
                if result['vulnerable']:
                    # Show the specific message you requested
                    self.print_success(f"Vulnerability found!")
                    print(f"   {Fore.CYAN}URL:{Style.RESET_ALL} {result['url']}")
                    print(f"   {Fore.CYAN}Parameter:{Style.RESET_ALL} {result['parameter']}")
                    print(f"   {Fore.CYAN}Original payload:{Style.RESET_ALL} {result['payload']}")
                    if self.encoding_type:
                        print(f"   {Fore.CYAN}Encoded payload:{Style.RESET_ALL} {result.get('encoded_payload', result['payload'])}")
                    print(f"   {Fore.CYAN}Detected indicator:{Style.RESET_ALL} {result['indicator']}")
                    print(f"   {Fore.CYAN}Type:{Style.RESET_ALL} {result['indicator_type']}")
                    print(f"   {Fore.CYAN}Status Code:{Style.RESET_ALL} {result['status_code']}")
                    
                    vulnerable_findings.append(result)
                        
                else:
                    if 'error' in result:
                        if self.verbose:
                            self.print_error(f"Error with {result['parameter']}={result['payload']}: {result['error']}")
                    else:
                        if tested_count % 50 == 0 and self.verbose:  # Show progress only in verbose
                            self.print_info(f"Tested {tested_count}/{len(test_data)} payloads...")
        
        return vulnerable_findings

class LFIScanner:
    def __init__(self, target_url, wordlist_file, verbose=False):
        self.target_url = target_url
        self.wordlist_file = wordlist_file
        self.verbose = verbose
        self.auditor = LFIAuditor(verbose=verbose)
        self.passwd_patterns = ["root:x:0:0:", "daemon:x:1:1:", "bin:x:2:2:"]

    def print_banner(self, text, color=Fore.CYAN, style=Style.BRIGHT):
        """Print a colorful banner"""
        banner_width = 70
        padded_text = f" {text} ".center(banner_width, "=")
        print(f"{color}{style}{padded_text}{Style.RESET_ALL}")

    def print_success(self, text):
        """Print success message"""
        print(f"{Fore.GREEN}{Style.BRIGHT}[+] LFI_SUCCESS DETECTED! {text}{Style.RESET_ALL}")

    def print_warning(self, text):
        """Print warning message"""
        print(f"{Fore.YELLOW}{Style.BRIGHT}[!] {text}{Style.RESET_ALL}")

    def print_error(self, text):
        """Print error message"""
        print(f"{Fore.RED}{Style.BRIGHT}[✗] {text}{Style.RESET_ALL}")

    def print_info(self, text):
        """Print informational message"""
        if self.verbose:
            print(f"{Fore.CYAN}{Style.BRIGHT}[*] {text}{Style.RESET_ALL}")

    def check_lfi_vulnerability(self, content):
        for pattern in self.passwd_patterns:
            if pattern in content:
                return True
        return False

    def load_wordlist(self):
        with open(self.wordlist_file, 'r', encoding='utf-8', errors='ignore') as f:
            return [line.strip() for line in f if line.strip() and not line.startswith('#')]

    def test_payload(self, payload):
        try:
            safe_payload = urllib.parse.quote(payload, safe="/%")
            full_url = self.target_url.replace("PAYLOAD", safe_payload)
            
            if self.verbose:
                self.print_info(f"Testing: {payload}")
            
            request = urllib.request.Request(full_url)
            response = urllib.request.urlopen(request, timeout=10)
            res = response.read().decode("utf-8")
            
            if self.check_lfi_vulnerability(res):
                self.print_success(f"Vulnerability found!")
                print(f"   {Fore.CYAN}URL:{Style.RESET_ALL} {full_url}")
                print(f"   {Fore.CYAN}Payload:{Style.RESET_ALL} {payload}")
                print(f"   {Fore.CYAN}Encoded payload:{Style.RESET_ALL} {safe_payload}")
                print(f"   {Fore.CYAN}Status Code:{Style.RESET_ALL} {response.getcode()}")
                print(f"   {Fore.CYAN}Detected indicator:{Style.RESET_ALL} /etc/passwd structure")
                return {
                    'vulnerable': True,
                    'url': full_url,
                    'payload': payload,
                    'encoded_payload': safe_payload,
                    'status_code': response.getcode(),
                    'indicator': 'etc_passwd_structure',
                    'indicator_type': 'basic_pattern'
                }
            return {
                'vulnerable': False,
                'url': full_url,
                'payload': payload
            }
        except Exception as e:
            if self.verbose:
                self.print_error(f"Error with payload {payload}: {str(e)}")
            return {
                'vulnerable': False,
                'url': self.target_url.replace("PAYLOAD", urllib.parse.quote(payload, safe="/%")),
                'payload': payload,
                'error': str(e)
            }

    def scan(self):
        self.print_banner(f"SIMPLE LFI SCAN: {self.target_url}")
        self.print_info(f"Wordlist: {self.wordlist_file}")
        self.print_info("Starting scan...")
        
        payloads = self.load_wordlist()
        self.print_info(f"Payloads loaded: {len(payloads)}")
        
        vulnerable_findings = []
        tested_count = 0
        
        for payload in payloads:
            result = self.test_payload(payload)
            tested_count += 1
            
            if result['vulnerable']:
                vulnerable_findings.append(result)
                # In simple mode, stop at first vulnerability found
                # as in original script, but show improved format
                break
            else:
                if tested_count % 50 == 0 and self.verbose:
                    self.print_info(f"Tested {tested_count}/{len(payloads)} payloads...")
        
        if not vulnerable_findings:
            self.print_warning("No LFI vulnerabilities found")
        else:
            self.print_success(f"Found {len(vulnerable_findings)} vulnerabilities")
        
        return vulnerable_findings

def main():
    banner = f"""
{Fore.CYAN}{Style.BRIGHT}
╔══════════════════════════════════════════════════════════════════════════╗
║                                                                          ║
║  ██      ███████ ██ ██████  ██████   ██████  ██████  ███████ ██   ██     ║
║  ██      ██      ██ ██   ██ ██   ██ ██    ██ ██   ██ ██       ██ ██      ║
║  ██      █████   ██ ██████  ██████  ██    ██ ██████  █████     ███       ║
║  ██      ██      ██ ██      ██   ██ ██    ██ ██   ██ ██       ██ ██      ║
║  ███████ ██      ██ ██      ██   ██  ██████  ██████  ███████ ██   ██     ║
║                                                                          ║
║                    [NO FALSE POSITIVES - /etc/passwd ONLY]               ║
║                                [By Mrr00t]                               ║
║                                                                          ║
╚══════════════════════════════════════════════════════════════════════════╝
{Style.RESET_ALL}
"""
    print(banner)
    parser = argparse.ArgumentParser(
        description="Strict LFI Auditor - /etc/passwd Detection Only (No False Positives)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
{Fore.YELLOW}{Style.BRIGHT}📚 USAGE EXAMPLES - FROM BASIC TO ADVANCED:{Style.RESET_ALL}

{Fore.GREEN}🎯 BASIC LEVEL - Simple scans:{Style.RESET_ALL}
{Fore.CYAN}
  # Simple scan (improved original mode)
  python LFIProbeX.py --path --url "http://localhost/PAYLOAD" -w wordlist.txt

  # Basic single URL scan
  python LFIProbeX.py --url "http://example.com/page.php?file=test" -w payloads.txt

  # Scan with verbose output
  python LFIProbeX.py --url "http://test.com/view?page=index" -w wordlist.txt -v
{Style.RESET_ALL}

{Fore.GREEN}🚀 INTERMEDIATE LEVEL - Specific scans:{Style.RESET_ALL}
{Fore.CYAN}
  # Test specific parameters
  python LFIProbeX.py --url "http://site.com/search?q=test&file=data" -w payloads.txt -p file document page

  # Multiple URLs from file
  python LFIProbeX.py -l urls.txt -w wordlist.txt

  # With threads for higher speed
  python LFIProbeX.py --url "http://target.com/gallery?img=1" -w payloads.txt -t 10
{Style.RESET_ALL}

{Fore.GREEN}🔥 ADVANCED LEVEL - Evasion techniques:{Style.RESET_ALL}
{Fore.CYAN}
  # Standard URL encoding
  python LFIProbeX.py --url "http://target.com/include?page=home" -w wordlist.txt --encoding url

  # Double URL encoding
  python LFIProbeX.py --url "http://target.com/load?template=main" -w payloads.txt --encoding double_url

  # Base64 encoding
  python LFIProbeX.py --url "http://target.com/render?view=default" -w wordlist.txt --encoding base64

  # Base64 + URL encoding
  python LFIProbeX.py --url "http://target.com/display?content=welcome" -w payloads.txt --encoding base64_url

  # HTML encoding
  python LFIProbeX.py --url "http://target.com/show?src=banner" -w wordlist.txt --encoding html
{Style.RESET_ALL}

{Fore.GREEN}🛠️ PROFESSIONAL LEVEL - Burp Suite integration:{Style.RESET_ALL}
{Fore.CYAN}
  # Basic Burp Suite request
  python LFIProbeX.py -r request.txt -w wordlist.txt

  # Burp Suite with advanced encoding
  python LFIProbeX.py -r request.txt -w payloads.txt --encoding double_url -v

  # Burp Suite with specific parameters
  python LFIProbeX.py -r burp_request.txt -w wordlist.txt -p file page template -t 15
{Style.RESET_ALL}

{Fore.GREEN}📊 PRODUCTION LEVEL - Complete scans:{Style.RESET_ALL}
{Fore.CYAN}
  # Complete scan with results saving
  python LFIProbeX.py -l targets.txt -w big_wordlist.txt -t 20 -v -o results.txt

  # Massive scan with encoding and specific parameters
  python LFIProbeX.py -l massive_urls.txt -w payloads.txt -p file include page template --encoding url -t 25 -o complete_scan.txt

  # Combination of professional techniques
  python LFIProbeX.py -r burp_export.txt -w advanced_payloads.txt --encoding base64_url -p filename document src -t 20 -v -o burp_scan_results.txt
{Style.RESET_ALL}

{Fore.YELLOW}⚡ QUICK TIP: For maximum effectiveness, combine multiple techniques:{Style.RESET_ALL}
{Fore.CYAN}
  python LFIProbeX.py -l targets.txt -w wordlist.txt --encoding double_url -p file page include -t 20 -v -o detailed_results.txt
{Style.RESET_ALL}

{Fore.GREEN}🎨 Available encoding types:{Style.RESET_ALL}
{Fore.YELLOW}
  url           - Standard URL encoding (%20, %2F, etc.)
  double_url    - Double URL encoding (%2520, %252F, etc.)
  base64        - Base64 encoding (Li4vLi4vLi4vZXRjL3Bhc3N3ZA==)
  base64_url    - Base64 + URL encoding (Li4vLi4vLi4vZXRjL3Bhc3N3ZA%3D%3D)
  html          - HTML entities encoding (../../../etc/passwd)
  unicode       - Unicode encoding (%u002e%u002e%u002f)
  utf8          - UTF-8 hexadecimal encoding (2e2e2f2e2e2f2e2e2f6574632f706173737764)
  hex           - Simple hexadecimal encoding (2e2e2f2e2e2f2e2e2f6574632f706173737764)
{Style.RESET_ALL}
        """
    )
    
    group = parser.add_mutually_exclusive_group(required=False)
    group.add_argument("--url", help="Single URL to audit")
    group.add_argument("-l", "--list", help="File with list of URLs to audit")
    group.add_argument("-r", "--request", help="Burp Suite request file")
    
    parser.add_argument("--path", action='store_true', help="Run simple LFI scan (improved original mode)")
    parser.add_argument("-w", "--wordlist", required=True, help="Wordlist file")
    parser.add_argument("-p", "--parameters", nargs="+", help="Specific parameters to test (space separated)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output (shows all tests)")
    parser.add_argument("-t", "--threads", type=int, default=5, help="Number of threads (default: 5)")
    parser.add_argument("-o", "--output", help="File to save results")
    parser.add_argument("--timeout", type=int, default=10, help="Request timeout in seconds (default: 10)")
    parser.add_argument("--encoding", choices=['url', 'double_url', 'base64', 'base64_url', 'html', 'unicode', 'utf8', 'hex'], 
                       help="Type of encoding to apply to payloads")
    
    args = parser.parse_args()

    # Validate --path mode (improved original script)
    if args.path:
        if not args.url:
            print(f"{Fore.RED}[✗] Error: You must use --url with --path to run simple scan{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}Example: python3 LFIProbeX.py --path --url \"http://localhost/PAYLOAD\" -w wordlist.txt{Style.RESET_ALL}")
            sys.exit(1)
        
        if "PAYLOAD" not in args.url:
            print(f"{Fore.RED}[✗] URL must contain 'PAYLOAD'{Style.RESET_ALL}")
            sys.exit(1)

        if not os.path.exists(args.wordlist):
            print(f"{Fore.RED}[✗] Wordlist file not found: {args.wordlist}{Style.RESET_ALL}")
            sys.exit(1)
        
        # Run improved simple scan
        scanner = LFIScanner(args.url, args.wordlist, verbose=args.verbose)
        start_time = time.time()
        vulnerabilities = scanner.scan()
        end_time = time.time()
        
        # Show summary
        scanner.print_banner("SCAN SUMMARY", Fore.MAGENTA)
        print(f"   {Fore.CYAN}URL:{Style.RESET_ALL} {args.url}")
        print(f"   {Fore.CYAN}Wordlist:{Style.RESET_ALL} {args.wordlist}")
        print(f"   {Fore.CYAN}Vulnerabilities found:{Style.RESET_ALL} {len(vulnerabilities)}")
        print(f"   {Fore.CYAN}Total time:{Style.RESET_ALL} {end_time - start_time:.2f} seconds")
        
        # Save results if specified
        if args.output and vulnerabilities:
            with open(args.output, 'w', encoding='utf-8') as f:
                f.write("SIMPLE LFI SCAN RESULTS\n")
                f.write("=" * 50 + "\n\n")
                f.write(f"URL: {args.url}\n")
                f.write(f"Wordlist: {args.wordlist}\n\n")
                for i, vuln in enumerate(vulnerabilities, 1):
                    f.write(f"VULNERABILITY {i}:\n")
                    f.write(f"URL: {vuln['url']}\n")
                    f.write(f"Original payload: {vuln['payload']}\n")
                    f.write(f"Encoded payload: {vuln['encoded_payload']}\n")
                    f.write(f"Status Code: {vuln['status_code']}\n")
                    f.write(f"Indicator: {vuln['indicator']}\n")
                    f.write(f"Type: {vuln['indicator_type']}\n")
                    f.write("-" * 50 + "\n\n")
            scanner.print_success(f"Results saved in: {args.output}")
        
        return

    # Validations for advanced mode
    if not any([args.url, args.list, args.request]):
        print(f"{Fore.RED}[✗] You must specify a URL, URL list or Burp request file{Style.RESET_ALL}")
        parser.print_help()
        sys.exit(1)

    if not os.path.exists(args.wordlist):
        print(f"{Fore.RED}[✗] Wordlist file not found: {args.wordlist}{Style.RESET_ALL}")
        sys.exit(1)
        
    if args.list and not os.path.exists(args.list):
        print(f"{Fore.RED}[✗] URL list file not found: {args.list}{Style.RESET_ALL}")
        sys.exit(1)
        
    if args.request and not os.path.exists(args.request):
        print(f"{Fore.RED}[✗] Request file not found: {args.request}{Style.RESET_ALL}")
        sys.exit(1)

    # Initialize auditor (advanced mode)
    auditor = LFIAuditor(verbose=args.verbose, threads=args.threads, timeout=args.timeout, encoding_type=args.encoding)
    
    all_vulnerabilities = []
    start_time = time.time()
    
    try:
        if args.request:
            # Audit Burp Suite request
            vulnerabilities = auditor.audit_request(args.request, args.wordlist, args.parameters)
            all_vulnerabilities.extend(vulnerabilities)
            
            if not vulnerabilities:
                auditor.print_warning(f"No vulnerabilities found in {args.request}")
                
        else:
            # Load URLs for normal audit
            urls = []
            if args.url:
                urls = [args.url]
            elif args.list:
                with open(args.list, 'r') as f:
                    urls = [line.strip() for line in f if line.strip()]

            for url in urls:
                vulnerabilities = auditor.audit_url(url, args.wordlist, args.parameters)
                all_vulnerabilities.extend(vulnerabilities)
                
                if not vulnerabilities:
                    auditor.print_warning(f"No vulnerabilities found in {url}")
                
    except KeyboardInterrupt:
        auditor.print_warning("Scan interrupted by user")
    
    end_time = time.time()
    
    # Show summary
    auditor.print_banner("SCAN SUMMARY", Fore.MAGENTA)
    if args.request:
        print(f"   {Fore.CYAN}Request file:{Style.RESET_ALL} {args.request}")
    else:
        print(f"   {Fore.CYAN}URLs tested:{Style.RESET_ALL} {len(urls) if 'urls' in locals() else 1}")
    
    print(f"   {Fore.CYAN}Encoding used:{Style.RESET_ALL} {args.encoding if args.encoding else 'None'}")
    print(f"   {Fore.CYAN}Vulnerabilities found:{Style.RESET_ALL} {len(all_vulnerabilities)}")
    print(f"   {Fore.CYAN}Total time:{Style.RESET_ALL} {end_time - start_time:.2f} seconds")
    
    # Show target parameters if specified
    if args.parameters:
        print(f"   {Fore.CYAN}Target parameters:{Style.RESET_ALL} {', '.join(args.parameters)}")
    
    # Save results if specified
    if args.output and all_vulnerabilities:
        with open(args.output, 'w', encoding='utf-8') as f:
            f.write("LFI AUDIT RESULTS\n")
            f.write("=" * 50 + "\n\n")
            f.write(f"Encoding used: {args.encoding if args.encoding else 'None'}\n\n")
            for i, vuln in enumerate(all_vulnerabilities, 1):
                f.write(f"VULNERABILITY {i}:\n")
                f.write(f"URL: {vuln['url']}\n")
                f.write(f"Method: {vuln.get('method', 'GET')}\n")
                f.write(f"Parameter: {vuln['parameter']}\n")
                f.write(f"Original payload: {vuln['payload']}\n")
                if args.encoding:
                    f.write(f"Encoded payload: {vuln.get('encoded_payload', vuln['payload'])}\n")
                f.write(f"Indicator: {vuln['indicator']}\n")
                f.write(f"Type: {vuln['indicator_type']}\n")
                f.write("-" * 50 + "\n\n")
        auditor.print_success(f"Results saved in: {args.output}")

if __name__ == "__main__":
    # Disable SSL warnings for development
    import warnings
    warnings.filterwarnings('ignore', message='Unverified HTTPS request')
    
    main()