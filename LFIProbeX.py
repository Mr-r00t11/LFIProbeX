import requests
import argparse
from colorama import Fore, Style, Back

def audit_lfi(urls, wordlist, verbose):
    for url in urls:
        print(f"{Style.BRIGHT}{Back.CYAN}Auditing URL: {url}{Style.RESET_ALL}")
        with open(wordlist, 'r') as f:
            for payload in f:
                payload = payload.strip()
                full_url = f"{url}{payload}"
                try:
                    response = requests.get(full_url)
                    if "root:" in response.text:
                        print(f"{Fore.GREEN}[+] Vulnerable! Payload: {payload}{Style.RESET_ALL}")
                        if verbose:
                            print(f"Response:\n{response.text}")
                        break
                    else:
                        print(f"{Fore.RED}[-] Payload {payload} did not detect 'root:'{Style.RESET_ALL}")
                except requests.exceptions.RequestException as e:
                    print(f"An error occurred with payload {payload}: {e}")

if __name__ == "__main__":
    print("""

██      ███████ ██ ██████  ██████   ██████  ██████  ███████ ██   ██ 
██      ██      ██ ██   ██ ██   ██ ██    ██ ██   ██ ██       ██ ██  
██      █████   ██ ██████  ██████  ██    ██ ██████  █████     ███   
██      ██      ██ ██      ██   ██ ██    ██ ██   ██ ██       ██ ██  
███████ ██      ██ ██      ██   ██  ██████  ██████  ███████ ██   ██ 
________________________ by Mr r00t11 ___________________________
""")
    parser = argparse.ArgumentParser(description="LFI Auditor Script with Multiple URLs and Verbosity Control")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--url", help="Single URL to audit (e.g., 'https://example.com/vuln.php?param=')")
    group.add_argument("-l", "--list", help="Path to file containing a list of URLs to audit")
    parser.add_argument("-w", "--wordlist", required=True, help="Path to the wordlist file")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output (prints the response if vulnerable)")

    args = parser.parse_args()

    urls = []
    if args.url:
        urls = [args.url]
    elif args.list:
        with open(args.list, 'r') as f:
            urls = [line.strip() for line in f]

    audit_lfi(urls, args.wordlist, args.verbose)
