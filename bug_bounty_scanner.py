#!/usr/bin/env python3
import os
import sys
import json
import csv
import asyncio
import aiohttp
import argparse
from urllib.parse import urlparse

# --- [1. FIXED OSINT DNS CLIENT - THE SUBDOMINATOR PHASE] ---
async def fetch_passive_subdomains(session, domain):
    """
    Queries public Certificate Transparency logs via the correct crt.sh API url format.
    Extracts every publicly registered subdomain dynamically.
    """
    print(f"[*] [Subdominator Phase] Querying crt.sh API for '{domain}'...")
    
    # CORRECT SPECIFICATION: Appends the proper web schema, query parameters, and wildcard selectors
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    
    discovered = set()
    discovered.add(domain)       # Track the main domain asset
    discovered.add(f"www.{domain}")
    
    # Spoof a standard web browser header as crt.sh drops blank programmatic scripts
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/119.0"}
    
    try:
        async with session.get(url, headers=headers, timeout=25) as response:
            if response.status == 200:
                try:
                    data = await response.json()
                    for entry in data:
                        name_value = entry.get("name_value", "")
                        # Split entries containing newline characters
                        names = name_value.split("\n")
                        for name in names:
                            # Clean up wildcards (*.domain.com) and convert to standard format
                            clean_name = name.replace("*.", "").strip().lower()
                            if clean_name and clean_name.endswith(domain):
                                discovered.add(clean_name)
                except Exception as json_err:
                    print(f"[!] Warning: Failed parsing payload stream ({json_err}).")
            else:
                print(f"[!] Warning: crt.sh API returned response status code {response.status}.")
    except Exception as e:
        print(f"[!] Warning: Passive OSINT lookup failed ({e}). Reverting to standard configurations.")
        
    return sorted(list(discovered))


# --- [2. FLAT-TEXT WORDLIST INJECTOR - THE FFUF WORDLIST PHASE] ---
def load_brute_paths(config_path="scanner_config.ini"):
    """Loads explicit fuzzing paths from your text config file."""
    default_paths = ["/api", "/admin", "/login", "/dashboard", "/.env", "/.git/config"]
    if not os.path.exists(config_path):
        return default_paths
    try:
        with open(config_path, "r", encoding="utf-8") as cfg:
            paths = [line.strip() for line in cfg if line.strip() and line.strip().startswith("/")]
        return paths if paths else default_paths
    except Exception:
        return default_paths


# --- [3. HIGH-SPEED ENDPOINT EVALUATOR ENGINE] ---
async def evaluate_endpoint(session, url, timeout, semaphore):
    """
    Fuzzes target URL paths. Follows redirects to verify destinations,
    detects proxy authentication traps, and logs live paths.
    """
    # Filter out corporate third-party portal redirections
    login_fingerprints = [
        "google.com", "microsoftonline.com", "okta.com", 
        "pingidentity.com", "auth0.com", "cloudflare.com"
    ]
    
    async with semaphore:
        try:
            headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
            async with session.get(url, timeout=timeout, headers=headers, allow_redirects=True) as response:
                final_url = str(response.url)
                
                # Check for single sign-on overrides
                if any(fingerprint in final_url for fingerprint in login_fingerprints):
                    return None
                
                # Report active 200 matches (matching the precise behavior of ffuf)
                if response.status == 200:
                    parsed_final = urlparse(final_url)
                    parsed_original = urlparse(url)
                    
                    # Ignore paths that simply redirect users back to the homepage
                    if parsed_final.path in ["", "/"] and parsed_original.path not in ["", "/"]:
                        return None
                        
                    print(f"[\033[92mMATCH\033[0m] Found: {url} -> Status: 200")
                    return {"url": url, "status": 200, "final_destination": final_url}
                else:
                    print(f"[\033[90mFUZZ\033[0m] Checking: {url} ({response.status})", end="\r")
                    return None
        except Exception:
            return None


# --- [4. DISTRIBUTED EXECUTION PIPELINE ORCHESTRATOR] ---
async def main_pipeline(targets, paths_wordlist, args):
    semaphore = asyncio.BoundedSemaphore(args.concurrent)
    timeout = aiohttp.ClientTimeout(total=args.timeout)
    
    async with aiohttp.ClientSession() as session:
        all_discovered_endpoints = []
        
        for target in targets:
            # Step A: Execute Subdominator Phase with correct API strings
            subdomains = await fetch_passive_subdomains(session, target)
            print(f"[*] [Subdominator Phase] Successfully mapped {len(subdomains)} unique subdomains for: {target}")
            
            # Step B: Build Global Scan Matrix (Combines HTTP and HTTPS variations)
            scan_queue = []
            for sub in subdomains:
                scan_queue.append(f"http://{sub}")
                scan_queue.append(f"https://{sub}")
                for path in paths_wordlist:
                    scan_queue.append(f"http://{sub}{path}")
                    scan_queue.append(f"https://{sub}{path}")
            
            print(f"[*] [ffuf Phase] Scanning Fuzz Matrix: {len(scan_queue)} endpoints to evaluate.")
            print("[*] Launching async verification workers... \n")
            
            # Step C: Run concurrent network tasks
            tasks = [evaluate_endpoint(session, url, timeout, semaphore) for url in scan_queue]
            results = await asyncio.gather(*tasks)
            
            target_findings = [res for res in results if res is not None]
            all_discovered_endpoints.extend(target_findings)
            
        print("\n" + "="*75)
        print(f"[*] Evaluation complete. Pipeline captured {len(all_discovered_endpoints)} live endpoints.")
        
        # Save structured results
        if args.format == "json":
            with open(args.output, "w", encoding="utf-8") as f:
                json.dump(all_discovered_endpoints, f, indent=4)
        elif args.format == "csv":
            with open(args.output, "w", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=["url", "status", "final_destination"])
                writer.writeheader()
                writer.writerows(all_discovered_endpoints)
        elif args.format == "txt":
            with open(args.output, "w", encoding="utf-8") as f:
                for item in all_discovered_endpoints:
                    f.write(f"[{item['status']}] {item['url']} -> {item['final_destination']}\n")
                    
        print(f"[+] Operational log exported to: '{args.output}'")


# --- [5. ENTRY SYSTEM MANAGER] ---
def run():
    print("="*75)
    print("          Subdominator x ffuf Unified Scanner v3.1 - Bug Fixed Core")
    print("="*75)

    parser = argparse.ArgumentParser(description="Subdominator + ffuf Combined Enterprise Web Asset Pipeline")
    parser.add_argument("-i", "--input", required=True, help="Domain target or asset list path")
    parser.add_argument("-o", "--output", required=True, help="Target storage output file path")
    parser.add_argument("-f", "--format", choices=["json", "csv", "txt"], default="json")
    parser.add_argument("-c", "--concurrent", type=int, default=40, help="Parallel connection limit")
    parser.add_argument("-t", "--timeout", type=int, default=8, help="Timeout maximum boundary limit")
    
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
        print("[!] Operational Error: No targets found.")
        sys.exit(1)
        
    asyncio.run(main_pipeline(targets, paths_list, args))
    
    print("="*75)
    print("                    Execution Pipeline Complete! 🎯")
    print("="*75)

if __name__ == "__main__":
    run()
