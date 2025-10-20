**Strict LFI Auditor - /etc/passwd Detection Only (No False Positives)**
![[ChatGPT Image 19 oct 2025, 07_29_36 p.m..png]]
## 📖 Description

LFIProbeX is an advanced Local File Inclusion (LFI) vulnerability scanner designed with a strict focus on detecting **real vulnerabilities** while eliminating false positives. Unlike traditional scanners, it specifically targets `/etc/passwd` file inclusion with multiple verification layers to ensure accurate results.

### 🎯 Key Features

- **🚫 Zero False Positives** - Strict verification using multiple `/etc/passwd` structure patterns
- **🔧 Multiple Encoding Techniques** - Support for various encoding methods to bypass filters
- **🛠️ Burp Suite Integration** - Direct import of Burp Suite requests
- **⚡ Multi-threaded Scanning** - High-performance concurrent testing
- **🎨 Colorful Output** - Clear and informative terminal interface
- **📊 Advanced Detection** - Regex patterns and structural analysis

## 🚀 Installation

### Prerequisites
- Python 3.x
- Required packages: `requests`, `colorama`

### Quick Setup
```bash
# Clone the repository
git clone https://github.com/yourusername/LFIProbeX.git
cd LFIProbeX

# Install dependencies
pip install requests colorama

# Make executable (Linux/Mac)
chmod +x LFIProbeX.py
```

## 💡 Usage Examples

### 🎯 Basic Level - Simple Scans
```bash
# Simple scan (improved original mode)
python LFIProbeX.py --path --url "http://localhost/PAYLOAD" -w wordlist.txt

# Basic single URL scan
python LFIProbeX.py --url "http://example.com/page.php?file=test" -w payloads.txt

# Scan with verbose output
python LFIProbeX.py --url "http://test.com/view?page=index" -w wordlist.txt -v
```

### 🚀 Intermediate Level - Specific Scans
```bash
# Test specific parameters
python LFIProbeX.py --url "http://site.com/search?q=test&file=data" -w payloads.txt -p file document page

# Multiple URLs from file
python LFIProbeX.py -l urls.txt -w wordlist.txt

# With threads for higher speed
python LFIProbeX.py --url "http://target.com/gallery?img=1" -w payloads.txt -t 10
```

### 🔥 Advanced Level - Evasion Techniques
```bash
# Standard URL encoding
python LFIProbeX.py --url "http://target.com/include?page=home" -w wordlist.txt --encoding url

# Double URL encoding
python LFIProbeX.py --url "http://target.com/load?template=main" -w payloads.txt --encoding double_url

# Base64 encoding
python LFIProbeX.py --url "http://target.com/render?view=default" -w wordlist.txt --encoding base64

# Base64 + URL encoding
python LFIProbeX.py --url "http://target.com/display?content=welcome" -w payloads.txt --encoding base64_url
```

### 🛠️ Professional Level - Burp Suite Integration
```bash
# Basic Burp Suite request
python LFIProbeX.py -r request.txt -w wordlist.txt

# Burp Suite with advanced encoding
python LFIProbeX.py -r request.txt -w payloads.txt --encoding double_url -v

# Burp Suite with specific parameters
python LFIProbeX.py -r burp_request.txt -w wordlist.txt -p file page template -t 15
```

# Burp Suite Scan
![[Request_Scan.png]]

# URL Scan
![[URL_Scan.png]]

# Path Scan
![[Path_Scan.png]]

# List Scan
![[List_Scan.png]]

## 🎨 Available Encoding Types
|Encoding Type|Description|Example|
|---|---|---|
|`url`|Standard URL encoding|`%2e%2e%2f%65%74%63%2f%70%61%73%73%77%64`|
|`double_url`|Double URL encoding|`%252e%252e%252f%2565%2574%2563%252f%2570%2561%2573%2573%2577%2564`|
|`base64`|Base64 encoding|`Li4vLi4vLi4vZXRjL3Bhc3N3ZA==`|
|`base64_url`|Base64 + URL encoding|`Li4vLi4vLi4vZXRjL3Bhc3N3ZA%3D%3D`|
|`html`|HTML entities encoding|`../../../etc/passwd`|
|`unicode`|Unicode encoding|`%u002e%u002e%u002f`|
|`utf8`|UTF-8 hexadecimal|`2e2e2f2e2e2f2e2e2f6574632f706173737764`|
|`hex`|Simple hexadecimal|`2e2e2f2e2e2f2e2e2f6574632f706173737764`|


