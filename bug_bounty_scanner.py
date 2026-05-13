#!/usr/bin/env python3
import os
import sys
import json
import csv
import asyncio
import socket
import aiohttp
import argparse
from urllib.parse import urlparse

# --- [PHASE 1: MULTI-SOURCE PASSIVE OSINT SCRAPER] ---
async def fetch_passive_subdomains(session, domain):
    """
    Queries both crt.sh and AlienVault OTX APIs concurrently 
    to maximize public subdomain mapping coverage.
    """
    print(f"[*] [Subdominator] Extracting passive subdomain map for '{domain}'...")
    discovered = {domain, f"www.{domain}"}
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0"}
    
    # Task A: Query crt.sh
    async def query_crt_sh():
        url = f"crt.sh.{domain}&output=json"
        try:
            async with session.get(url, headers=headers, timeout=20) as r:
                if r.status == 200:
                    for entry in await r.json():
                        for name in entry.get("name_value", "").split("\n"):
                            clean = name.replace("*.", "").strip().lower()
                            if clean and clean.endswith(domain):
                                discovered.add(clean)
        except Exception:
            pass

    # Task B: Query AlienVault OTX
    async def query_alienvault():
        url = f"alienvault.com{domain}/passive_dns"
        try:
            async with session.get(url, headers=headers, timeout=20) as r:
                if r.status == 200:
                    data = await r.json()
                    for entry in data.get("passive_dns", []):
                        hostname = entry.get("hostname", "").strip().lower()
                        if hostname and hostname.endswith(domain):
                            discovered.add(hostname)
        except Exception:
            pass

    await asyncio.gather(query_crt_sh(), query_alienvault())
    return sorted(list(discovered))


# --- [PHASE 2: ASYNCHRONOUS DNS RESOLVER PRE-FILTER] ---
async def resolve_dns(subdomain, semaphore):
    """
    Uses non-blocking system sockets to verify if a subdomain points 
    to a live IP address, preventing wasting HTTP requests on dead records.
    """
    async with semaphore:
        loop = asyncio.get_running_loop()
        try:
            # Performs standard non-blocking system DNS A-record resolution
            await loop.getaddrinfo(subdomain, None, family=socket.AF_INET)
            return subdomain
        except Exception:
            return None


# --- [PHASE 3: SOFT-404 FINGERPRINT CALIBRATION] ---
async def calibrate_soft_404(session, base_url):
    """
    Requests a non-existent randomized path on a domain to determine its 
    unique error page byte length, preventing false-positive loops.
    """
    test_url = f"{base_url}/soft404_calibration_token_path_signature"
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
    try:
        async with session.get(test_url, headers=headers, timeout=6, allow_redirects=True) as r:
            body = await r.text()
            return len(body)  # Returns content-length signature of a bad page
    except Exception:
        return None


# --- [PHASE 4: PRECISION ENDPOINT EVALUATOR] ---
async def evaluate_endpoint(session, url, timeout, semaphore, soft_404_map):
    """
    Fuzzes structural targets. Normalizes redirects, screens multi-tenant 
    auth takeovers, and suppresses matched content-length soft-404 errors.
    """
    login_fingerprints = ["google.com", "microsoftonline.com", "okta.com", "auth0.com"]
    parsed_url = urlparse(url)
    base_host_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
    
    async with semaphore:
        try:
            headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
            async with session.get(url, timeout=timeout, headers=headers, allow_redirects=True) as response:
                final_url = str(response.url)
                status_code = response.status
                body_content = await response.text()
                content_length = len(body_content)
                
                # Filter A: Drop generic corporate portal takeovers
                if any(fp in final_url for fp in login_fingerprints):
                    return None
                
                # Filter B: Smart Content-Length matching (Soft-404 Suppression)
                # If path isn't a root directory, but mirrors the system error page size, drop it
                if parsed_url.path not in ["", "/"]:
                    expected_bad_size = soft_404_map.get(base_host_url)
                    if expected_bad_size is not None and abs(content_length - expected_bad_size) < 20: 
                        return None

                if status_code in [200, 301, 302, 401, 403, 405] or response.history:
                    sys.stdout.write("\033[K")  # Wipe ticker row
                    
                    if status_code == 200:
                        print(f"[\033[92m{status_code}\033[0m] Live Endpoint: {url} (Size: {content_length})")
                    elif status_code in [401, 403]:
                        print(f"[\033[93m{status_code}\033[0m] Protected Panel: {url}")
                    else:
                        print(f"[\033[94mINFO\033[0m] Active Route: {url} -> {final_url}")
                        
                    return {
                        "requested_url": url,
                        "resolved_status": status_code,
                        "content_length": content_length,
                        "final_destination": final_url
                    }
                else:
                    sys.stdout.write(f"[\033[90mFUZZ\033[0m] Analyzing: {url} ({status_code})\033[K\r")
                    sys.stdout.flush()
                    return None
        except Exception:
            return None


def load_brute_paths(config_path="scanner_config.ini"):
    default_paths = ["/api", "/admin", "/login", "/dashboard", "/.env", "/.git/config"]
    if not os.path.exists(config_path):
        return default_paths
    try:
        with open(config_path, "r", encoding="utf-8") as cfg:
            return [line.strip() for line in cfg if line.strip() and line.strip().startswith("/")]
    except Exception:
        return default_paths


# --- [CORE PIPELINE ENGINE] ---
async def main_pipeline(targets, paths_wordlist, args):
    dns_semaphore = asyncio.BoundedSemaphore(100)  # Safe high speed for asynchronous DNS queries
    http_semaphore = asyncio.BoundedSemaphore(args.concurrent)
    timeout = aiohttp.ClientTimeout(total=args.timeout)
    
    async with aiohttp.ClientSession() as session:
        all_discovered_endpoints = []
        
        for target in targets:
            # 1. Gather all unique OSINT subdomains
            raw_subdomains = await fetch_passive_subdomains(session, target)
            print(f"[*] Total Raw OSINT Records Discovered: {len(raw_subdomains)}")
            
            # 2. Run Asynchronous DNS Resolution Pre-Filter
            print("[*] Filtering out dead entries using Async DNS Resolvers...")
            dns_tasks = [resolve_dns(sub, dns_semaphore) for sub in raw_subdomains]
            resolved_results = await asyncio.gather(*dns_tasks)
            live_subdomains = [sub for sub in resolved_results if sub is not None]
            print(f"[*] [\033[92mDNS SUCCESS\033[0m] Mapped {len(live_subdomains)}/{len(raw_subdomains)} live domains.")
            
            # 3. Dynamic Soft-404 / Fingerprinting Calibration
            print("[*] Calibrating server response fingerprints...")
            soft_404_map = {}
            for sub in live_subdomains:
                for schema in ["http", "https"]:
                    base = f"{schema}://{sub}"
                    size = await calibrate_soft_404(session, base)
                    if size:
                        soft_404_map[base] = size
            
            # 4. Generate Optimized Scan Queue Matrix
            scan_queue = []
            for sub in live_subdomains:
                scan_queue.append(f"http://{sub}")
                scan_queue.append(f"https://{sub}")
                for path in paths_wordlist:
                    scan_queue.append(f"http://{sub}{path}")
                    scan_queue.append(f"https://{sub}{path}")
            
            print(f"[*] [ffuf Module] Matrix compiled: {len(scan_queue)} optimized paths queued.")
            print("[*] Launching async verification workers... \n")
            
            # 5. Execute Fuzzing Matrix Pass
            tasks = [evaluate_endpoint(session, url, timeout, http_semaphore, soft_404_map) for url in scan_queue]
            results = await asyncio.gather(*tasks)
            
            all_discovered_endpoints.extend([res for res in results if res is not None])
            
        sys.stdout.write("\033[K")
        print("\n" + "="*75)
        print(f"[*] Scan finalized. Consolidated {len(all_discovered_endpoints)} unique findings.")
        
        # Save output records
        if args.format == "json":
            with open(args.output, "w", encoding="utf-8") as f:
                json.dump(all_discovered_endpoints, f, indent=4)
        elif args.format == "csv":
            with open(args.output, "w", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=["requested_url", "resolved_status", "content_length", "final_destination"])
                writer.writeheader()
                writer.writerows(all_discovered_endpoints)
        elif args.format == "txt":
            with open(args.output, "w", encoding="utf-8") as f:
                for item in all_discovered_endpoints:
                    f.write(f"[{item['resolved_status']}] {item['requested_url']} (Len: {item['content_length']})\n")
                    
        print(f"[+] Clean output matrix written to: '{args.output}'")


def run():
    print("="*75)
    print("      Subdominator x ffuf Framework v6.0 - Advanced Recon Core")
    print("="*75)

    parser = argparse.ArgumentParser(description="Advanced Subdomain Fuzzer")
    parser.add_argument("-i", "--input", required=True, help="Root domain string or list path")
    parser.add_argument("-o", "--output", required=True, help="Output tracking path location")
    parser.add_argument("-f", "--format", choices=["json", "csv", "txt"], default="json")
    parser.add_argument("-c", "--concurrent", type=int, default=50, help="Parallel HTTP request worker count")
    parser.add_argument("-t", "--timeout", type=int, default=10, help="Max network connection timeout window")
    
    args = parser.parse_args()
    paths_list = load_brute_paths("scanner_config.ini")
    
    target_source = args.input.strip()
    targets = [target_source] if not os.path.isfile(target_source) else [line.strip() for line in open(target_source, "r", encoding="utf-8") if line.strip()]
    
    if not targets:
        print("[!] Error: Target scope parsed empty.")
        sys.exit(1)
        
    asyncio.run(main_pipeline(targets, paths_list, args))
    print("="*75)
    print("                    Execution Pipeline Complete! 🎯")
    print("="*75)

if __name__ == "__main__":
    run()
