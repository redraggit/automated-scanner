#!/usr/bin/env python3
import os
import sys
import json
import csv
import asyncio
import aiohttp
import argparse
from urllib.parse import urlparse

# --- [1. DYNAMIC OSINT SUBDOMAIN DISCOVERY] ---
async def fetch_passive_subdomains(session, domain):
    """
    Queries public Certificate Transparency logs via crt.sh API.
    Extracts every publicly registered subdomain dynamically.
    """
    print(f"[*] [Subdominator Phase] Extracting full subdomain map for '{domain}'...")
    
    # FIXED: Absolute canonical URL format for the crt.sh JSON endpoint
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    
    discovered = set()
    discovered.add(domain)       # Seed root target
    discovered.add(f"www.{domain}")
    
    # Custom headers protect against programmatic dropping rules on crt.sh
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0"}
    
    try:
        async with session.get(url, headers=headers, timeout=30) as response:
            if response.status == 200:
                try:
                    data = await response.json()
                    for entry in data:
                        name_value = entry.get("name_value", "")
                        for name in name_value.split("\n"):
                            clean_name = name.replace("*.", "").strip().lower()
                            if clean_name and clean_name.endswith(domain):
                                discovered.add(clean_name)
                except Exception:
                    pass
            else:
                print(f"[!] Target API gave unexpected status: {response.status}. Using local arrays.")
    except Exception as e:
        print(f"[!] Warning: Passive OSINT lookup timed out ({e}). Utilizing preset defaults.")
        
    return sorted(list(discovered))


# --- [2. DIRECTORY PAYLOAD WORDLIST INJECTOR] ---
def load_brute_paths(config_path="scanner_config.ini"):
    """Loads fuzzing tracks from text configuration lists."""
    default_paths = ["/api", "/admin", "/login", "/dashboard", "/.env", "/.git/config"]
    if not os.path.exists(config_path):
        return default_paths
    try:
        with open(config_path, "r", encoding="utf-8") as cfg:
            paths = [line.strip() for line in cfg if line.strip() and line.strip().startswith("/")]
        return paths if paths else default_paths
    except Exception:
        return default_paths


# --- [3. HIGH-SPEED ENDPOINT FUZZER CORE] ---
async def evaluate_endpoint(session, url, timeout, semaphore):
    """
    Evaluates subdomains and paths. Returns and tracks responses 
    (200, 301, 302, 403) to ensure total visibility of the attack surface.
    """
    # Exclude external generic multi-tenant single sign-on loops
    login_fingerprints = [
        "google.com", "microsoftonline.com", "okta.com", "auth0.com"
    ]
    
    async with semaphore:
        try:
            headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
            # allow_redirects=True maps out where hidden endpoints ultimately lead
            async with session.get(url, timeout=timeout, headers=headers, allow_redirects=True) as response:
                final_url = str(response.url)
                status_code = response.status
                
                if any(fingerprint in final_url for fingerprint in login_fingerprints):
                    return None
                
                # RECON STRATEGY: Capture 200 OK, 403 Forbidden, and 401 Unauthorized codes
                if status_code in [200, 401, 403] or response.history:
                    # Clear inline terminal buffering remnants
                    sys.stdout.write("\033[K")
                    
                    # Highlight operational status values visually
                    if status_code == 200:
                        print(f"[\033[92m{status_code}\033[0m] Live Endpoint: {url}")
                    elif status_code in [401, 403]:
                        print(f"[\033[93m{status_code}\033[0m] Restricted Access: {url}")
                    else:
                        print(f"[\033[94mINFO\033[0m] Path Active: {url} -> Leads to: {final_url}")
                        
                    return {
                        "requested_url": url,
                        "resolved_status": status_code,
                        "final_destination": final_url
                    }
                else:
                    # Dynamic console logging update tracker
                    sys.stdout.write(f"[\033[90mFUZZ\033[0m] Analyzing: {url} ({status_code})\033[K\r")
                    sys.stdout.flush()
                    return None
        except Exception:
            return None


# --- [4. AGGREGATED PIPELINE ENGINE] ---
async def main_pipeline(targets, paths_wordlist, args):
    semaphore = asyncio.BoundedSemaphore(args.concurrent)
    timeout = aiohttp.ClientTimeout(total=args.timeout)
    
    async with aiohttp.ClientSession() as session:
        all_discovered_endpoints = []
        
        for target in targets:
            # Step A: Enumerate full subdomain layout via OSINT
            subdomains = await fetch_passive_subdomains(session, target)
            print(f"[*] [Subdominator Phase] Discovered {len(subdomains)} unique public subdomains for: {target}")
            
            # Step B: Compile comprehensive mapping arrays (Checks both HTTP and HTTPS variations)
            scan_queue = []
            for sub in subdomains:
                # Add base subdomains directly into the check queue
                scan_queue.append(f"http://{sub}")
                scan_queue.append(f"https://{sub}")
                
                # Append targeted fuzz paths against every discovered subdomain
                for path in paths_wordlist:
                    scan_queue.append(f"http://{sub}{path}")
                    scan_queue.append(f"https://{sub}{path}")
            
            print(f"[*] [ffuf Phase] Scanning Matrix: {len(scan_queue)} endpoints queued for validation.")
            print("[*] Launching async verification workers... \n")
            
            # Step C: Parallel batch request execution
            tasks = [evaluate_endpoint(session, url, timeout, semaphore) for url in scan_queue]
            results = await asyncio.gather(*tasks)
            
            target_findings = [res for res in results if res is not None]
            all_discovered_endpoints.extend(target_findings)
            
        sys.stdout.write("\033[K") # Flush trailing terminal text strings
        print("\n" + "="*75)
        print(f"[*] Recon complete. Pipeline mapped {len(all_discovered_endpoints)} valid targets.")
        
        # Save complete finding matrix
        if args.format == "json":
            with open(args.output, "w", encoding="utf-8") as f:
                json.dump(all_discovered_endpoints, f, indent=4)
        elif args.format == "csv":
            with open(args.output, "w", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=["requested_url", "resolved_status", "final_destination"])
                writer.writeheader()
                writer.writerows(all_discovered_endpoints)
        elif args.format == "txt":
            with open(args.output, "w", encoding="utf-8") as f:
                for item in all_discovered_endpoints:
                    f.write(f"[{item['resolved_status']}] {item['requested_url']} -> {item['final_destination']}\n")
                    
        print(f"[+] Output logs saved completely to: '{args.output}'")


# --- [5. ENTRY POINT EXECUTION CONTROLLER] ---
def run():
    print("="*75)
    print("          Subdominator x ffuf Unified Recon Engine v5.0")
    print("="*75)

    parser = argparse.ArgumentParser(description="Subdominator + ffuf Full-Scale Target Recon Pipeline")
    parser.add_argument("-i", "--input", required=True, help="Target domain context or line list path")
    parser.add_argument("-o", "--output", required=True, help="Target storage track output location")
    parser.add_argument("-f", "--format", choices=["json", "csv", "txt"], default="json")
    parser.add_argument("-c", "--concurrent", type=int, default=50, help="Parallel processing threshold (Default: 50)")
    parser.add_argument("-t", "--timeout", type=int, default=10, help="Network request connection timeout barrier")
    
    args = parser.parse_args()
    
    paths_list = load_brute_paths("scanner_config.ini")
    target_source = args.input.strip()
    targets = []
    
    if os.path.isfile(target_source):
        with open(target_source, "r", encoding="utf-8") as f:
            targets = [line.strip() for line in f if line.strip()]
    else:
        targets = [target_source]
        
    if not targets:
        print("[!] Operational Error: No targets parsed.")
        sys.exit(1)
        
    asyncio.run(main_pipeline(targets, paths_list, args))
    
    print("="*75)
    print("                    Execution Pipeline Complete! 🎯")
    print("="*75)

if __name__ == "__main__":
    run()
