import argparse
import os
import logging
import colorama
from colorama import Fore, Style
from urllib.parse import urlparse, parse_qs, urlencode
import requests
from concurrent.futures import ThreadPoolExecutor

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
            if query_params:
                cleaned_params = {key: placeholder for key in query_params}
                cleaned_query = urlencode(cleaned_params, doseq=True)
                cleaned_url = parsed_url._replace(query=cleaned_query).geturl()
                cleaned_urls.add(cleaned_url)
    return list(cleaned_urls)

def fetch_urls_from_wayback(domain):
    logging.info(f"{Fore.YELLOW}[INFO]{Style.RESET_ALL} Fetching URLs from Wayback for {Fore.CYAN + domain + Style.RESET_ALL}")
    wayback_uri = f"https://web.archive.org/cdx/search/cdx?url={domain}/*&output=txt&collapse=urlkey&fl=original"
    try:
        response = requests.get(wayback_uri, timeout=10)
        response.raise_for_status()
        urls = response.text.split()
        logging.info(f"{Fore.YELLOW}[INFO]{Style.RESET_ALL} Found {Fore.GREEN + str(len(urls)) + Style.RESET_ALL} Wayback URLs")
        return urls
    except requests.RequestException as e:
        logging.error(f"{Fore.RED}[ERROR]{Style.RESET_ALL} Wayback fetch failed: {str(e)}")
        return []

def fetch_urls_from_commoncrawl(domain):
    logging.info(f"{Fore.YELLOW}[INFO]{Style.RESET_ALL} Fetching URLs from CommonCrawl for {Fore.CYAN + domain + Style.RESET_ALL}")
    index_url = "https://index.commoncrawl.org/collinfo.json"
    urls = []
    try:
        index_response = requests.get(index_url)
        index_response.raise_for_status()
        indices = index_response.json()
        for index in indices[-3:]:  # last 3 indices only for performance
            cc_url = index['cdx-api'] + f"?url={domain}/*&output=json"
            r = requests.get(cc_url)
            if r.status_code == 200:
                for line in r.text.strip().split('\n'):
                    try:
                        entry = eval(line)
                        if 'url' in entry:
                            urls.append(entry['url'])
                    except:
                        continue
    except Exception as e:
        logging.error(f"{Fore.RED}[ERROR]{Style.RESET_ALL} CommonCrawl fetch failed: {str(e)}")
    logging.info(f"{Fore.YELLOW}[INFO]{Style.RESET_ALL} Found {Fore.GREEN + str(len(urls)) + Style.RESET_ALL} CommonCrawl URLs")
    return urls

def fetch_all_sources(domain, source):
    urls = []
    if source in ('wayback', 'all'):
        urls += fetch_urls_from_wayback(domain)
    if source in ('commoncrawl', 'all'):
        urls += fetch_urls_from_commoncrawl(domain)
    return list(set(urls))

def process_domain(domain, extensions, placeholder, output_dir, source):
    urls = fetch_all_sources(domain, source)
    if not urls:
        return
    cleaned_urls = clean_urls(urls, extensions, placeholder)
    if not cleaned_urls:
        return
    output_file = os.path.join(output_dir, f"{domain.replace('.', '_')}_cleaned.txt")
    with open(output_file, "w") as f:
        for url in cleaned_urls:
            f.write(url + "\n")
    logging.info(f"{Fore.YELLOW}[INFO]{Style.RESET_ALL} Saved cleaned URLs to {Fore.CYAN + output_file + Style.RESET_ALL}")

def main():
    banner = r"""
                                      _    __       
   ___  ___ ________ ___ _  ___ ___  (_)__/ /__ ____
  / _ \/ _ `/ __/ _ `/  ' \(_-</ _ \/ / _  / -_) __/
 / .__/\_,_/_/  \_,_/_/_/_/___/ .__/_/\_,_/\__/_/   
/_/                          /_/                    
                                                                      
    """
    print(Fore.YELLOW + banner + Style.RESET_ALL)

    parser = argparse.ArgumentParser(description="Param Monkey - Mining URLs from Web Archives")
    parser.add_argument("-d", "--domain", required=True, help="Single domain or path to file with domains.")
    parser.add_argument("-p", "--placeholder", help="Placeholder for parameter values", default="FUZZ")
    parser.add_argument("-o", "--output", help="Directory to save results", default="results")
    parser.add_argument("-s", "--source", help="Source: wayback, commoncrawl, all", default="wayback")
    args = parser.parse_args()

    if not os.path.exists(args.output):
        os.makedirs(args.output)

    extensions = HARDCODED_EXTENSIONS

    if os.path.isfile(args.domain):
        with open(args.domain, 'r') as f:
            domains = [line.strip() for line in f if line.strip()]
    else:
        domains = [args.domain.strip()]

    with ThreadPoolExecutor(max_workers=5) as executor:
        for domain in domains:
            domain = domain.lower().replace('https://', '').replace('http://', '')
            executor.submit(process_domain, domain, extensions, args.placeholder, args.output, args.source)

if __name__ == "__main__":
    main()
