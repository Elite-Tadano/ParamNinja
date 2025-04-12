import argparse
import os
import logging
import colorama
from colorama import Fore, Style
from urllib.parse import urlparse, parse_qs, urlencode
import requests
import re
import threading
import time

colorama.init(autoreset=True)

log_format = '%(message)s'
logging.basicConfig(format=log_format, level=logging.INFO)
logging.getLogger('').handlers[0].setFormatter(logging.Formatter(log_format))

HARDCODED_EXTENSIONS = [
    ".jpg", ".jpeg", ".png", ".gif", ".pdf", ".svg", ".json",
    ".css", ".js", ".webp", ".woff", ".woff2", ".eot", ".ttf", ".otf", ".mp4", ".txt"
]

def has_extension(url, extensions):
    parsed_url = urlparse(url)
    path = parsed_url.path
    extension = os.path.splitext(path)[1].lower()
    return extension in extensions

def clean_url(url):
    parsed_url = urlparse(url)
    if (parsed_url.port == 80 and parsed_url.scheme == "http") or (parsed_url.port == 443 and parsed_url.scheme == "https"):
        parsed_url = parsed_url._replace(netloc=parsed_url.netloc.rsplit(":", 1)[0])
    return parsed_url.geturl()

def clean_urls(urls, extensions, placeholder="FUZZ"):
    cleaned_urls = set()
    for url in urls:
        cleaned_url = clean_url(url)
        if not has_extension(cleaned_url, extensions):
            parsed_url = urlparse(cleaned_url)
            query_params = parse_qs(parsed_url.query)
            cleaned_params = {key: placeholder for key in query_params}
            cleaned_query = urlencode(cleaned_params, doseq=True)
            cleaned_url = parsed_url._replace(query=cleaned_query).geturl()
            cleaned_urls.add(cleaned_url)
    return list(cleaned_urls)

def fetch_urls_from_wayback(domain):
    logging.info(f"{Fore.YELLOW}[INFO]{Style.RESET_ALL} Fetching URLs from Wayback for {Fore.CYAN + domain + Style.RESET_ALL}")
    wayback_uri = f"https://web.archive.org/cdx/search/cdx?url={domain}/*&output=txt&collapse=urlkey&fl=original"
    try:
        response = requests.get(wayback_uri, timeout=30)
        response.raise_for_status()
        urls = response.text.split()
        logging.info(f"{Fore.YELLOW}[INFO]{Style.RESET_ALL} Found {Fore.GREEN + str(len(urls)) + Style.RESET_ALL} URLs")
        return urls
    except requests.RequestException as e:
        logging.error(f"{Fore.RED}[ERROR]{Style.RESET_ALL} Wayback fetch failed: {str(e)}")
        return []

def fetch_urls_from_commoncrawl(domain):
    logging.info(f"{Fore.YELLOW}[INFO]{Style.RESET_ALL} Fetching URLs from CommonCrawl for {Fore.CYAN + domain + Style.RESET_ALL}")
    index_url = "https://index.commoncrawl.org/collinfo.json"
    try:
        response = requests.get(index_url, timeout=15)
        response.raise_for_status()
        indexes = response.json()
        all_urls = set()
        for idx in indexes:
            cc_api = idx["cdx-api"] + f"?url={domain}/*&output=json"
            cc_resp = requests.get(cc_api, timeout=30)
            if cc_resp.status_code == 200:
                for line in cc_resp.text.strip().splitlines():
                    try:
                        url = eval(line).get("url")
                        if url:
                            all_urls.add(url)
                    except:
                        continue
        logging.info(f"{Fore.YELLOW}[INFO]{Style.RESET_ALL} Found {Fore.GREEN + str(len(all_urls)) + Style.RESET_ALL} URLs from CommonCrawl")
        return list(all_urls)
    except Exception as e:
        logging.error(f"{Fore.RED}[ERROR]{Style.RESET_ALL} CommonCrawl fetch failed: {str(e)}")
        return []

def sanitize_filename(name):
    base_name = os.path.basename(name)
    return re.sub(r'[^a-zA-Z0-9._-]', '_', base_name)

def save_cleaned_urls(urls, extensions, output_file, placeholder="FUZZ"):
    logging.info(f"{Fore.YELLOW}[INFO]{Style.RESET_ALL} Cleaning URLs")
    cleaned_urls = clean_urls(urls, extensions, placeholder)
    logging.info(f"{Fore.YELLOW}[INFO]{Style.RESET_ALL} Found {Fore.GREEN + str(len(cleaned_urls)) + Style.RESET_ALL} URLs after cleaning")
    logging.info(f"{Fore.YELLOW}[INFO]{Style.RESET_ALL} Extracting URLs with parameters")

    output_dir = os.path.dirname(output_file) if os.path.dirname(output_file) else "."
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    sanitized_filename = os.path.join(output_dir, sanitize_filename(output_file))
    try:
        with open(sanitized_filename, "w") as f:
            for url in cleaned_urls:
                if "?" in url:
                    f.write(url + "\n")
        logging.info(f"{Fore.YELLOW}[INFO]{Style.RESET_ALL} Saved cleaned URLs to {Fore.CYAN + sanitized_filename + Style.RESET_ALL}")
    except PermissionError:
        logging.error(f"{Fore.RED}[ERROR]{Style.RESET_ALL} Permission denied: Cannot write to file {sanitized_filename}")

def banner():
    log_text = r"""
 ________   ________   ________   ________   _____ ______    ________    ___   ________          ___   ________     
|\   __  \ |\   __  \ |\   __  \ |\   __  \ |\   _ \  _   \ |\   ___  \ |\  \ |\   ___  \       |\  \ |\   __  \    
\ \  \|\  \\ \  \|\  \\ \  \|\  \\ \  \|\  \\ \  \\\__\ \  \\ \  \\ \  \\ \  \\ \  \\ \  \      \ \  \\ \  \|\  \   
 \ \   ____\\ \   __  \\ \   _  _\\ \   __  \\ \  \\|__| \  \\ \  \\ \  \\ \  \\ \  \\ \  \   __ \ \  \\ \   __  \  
  \ \  \___| \ \  \ \  \\ \  \\  \|\ \  \ \  \\ \  \    \ \  \\ \  \\ \  \\ \  \\ \  \\ \  \ |\  \\_\  \\ \  \ \  \ 
   \ \__\     \ \__\ \__\\ \__\\ _\ \ \__\ \__\\ \__\    \ \__\\ \__\\ \__\\ \__\\ \__\\ \__\\ \________\\ \__\ \__\
    \|__|      \|__|\|__| \|__|\|__| \|__|\|__| \|__|     \|__| \|__| \|__| \|__| \|__| \|__| \|________| \|__|\|__|
                                                                                                    by @Elite-Tadano                                                                                                                                                                                                                               
    """
    print(f"{Fore.LIGHTGREEN_EX}{log_text}{Style.RESET_ALL}")

def main():
    banner()
    parser = argparse.ArgumentParser(description="ParamNinja - Mining & Cleaning Parameters from Web Archives")
    parser.add_argument("-d", "--domain", required=True, help="Domain name to fetch URLs for")
    parser.add_argument("-o", "--output", help="Output file name", default="result.txt")
    parser.add_argument("-p", "--placeholder", help="Placeholder for parameter values", default="FUZZ")
    parser.add_argument("--commoncrawl", action="store_true", help="Include CommonCrawl data")
    args = parser.parse_args()

    domain = args.domain.lower().replace('https://', '').replace('http://', '').strip('/')
    extensions = HARDCODED_EXTENSIONS

    wayback_urls = fetch_urls_from_wayback(domain)
    cc_urls = fetch_urls_from_commoncrawl(domain) if args.commoncrawl else []
    all_urls = list(set(wayback_urls + cc_urls))

    if not all_urls:
        logging.error(f"{Fore.RED}[ERROR]{Style.RESET_ALL} No URLs found for {domain}. Exiting.")
        return

    save_cleaned_urls(all_urls, extensions, args.output, args.placeholder)

if __name__ == "__main__":
    main()
