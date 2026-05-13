#!/usr/bin/env python3
import os
import sys
import json
import csv
import asyncio
import aiohttp
import argparse
from urllib.parse import urlparse

# --- [1. PASSIVE DNS SCRAPER - THE SUBDOMINATOR PHASE] ---
async def fetch_passive_subdomains(session, domain):
    """
    Queries public Certificate Transparency logs via crt.sh to find
    all real, historically valid subdomains dynamically.
    """
    print(f"[*] [Subdominator Phase] Querying crt.sh API for '{domain}'...")
    url = f"crt.sh%.{domain}&output=json"
    discovered = set()
    discovered.add(domain) # Include root domain
    discovered.add(f"www.{domain}")
    
    try:
        async with session.get(url, timeout=15) as response:
            if response.status == 200:
                try:
                    data = await response.json()
                    for entry in data:
                        name_value = entry.get("name_value", "")
                        # Handle wildcard notations and clean string noise
                        names = name_value.split("\n")
                        for name in names:
                            clean_name = name.replace("*.", "").strip().lower()
                            if clean_name and clean_name.endswith(domain):
                                discovered.add(clean_name)
                except Exception:
                    pass
    except Exception as e:
        print(f"[!] Warning: OSINT API connection timed out ({e}). Using core presets.")
        
    return list(discovered)


# --- [2. FLAT-TEXT WORDLIST INJECTOR - THE FFUF WORDLIST PHASE] ---
def load_brute_paths(config_path="scanner_config.ini"):
    """Loads explicit fuzzing paths from local wordlist config file."""
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
    Fuzzes target URL paths. Follows redirects to intercept final destinations,
    detects multi-tenant login takeovers, and suppresses noise.
    """
    # Block lists to strip out third-party enterprise login pages (False Positive Killers)
    login_fingerprints = [
        "google.com", "google.com", "microsoftonline.com",
        "okta.com", "pingidentity.com", "auth0.com", "cloudflare.com"
    ]
    
    async with semaphore:
        try:
            headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko)"}
            # allow_redirects=True ensures we verify where the path lands
            async with session.get(url, timeout=timeout, headers=headers, allow_redirects=True) as response:
                final_url = str(response.url)
                
                # Check if target hijacked our scanner path and redirected us to an authentication portal
                if any(fingerprint in final_url for fingerprint in login_fingerprints):
                    return None
                
                # We only match clean 200 OK responses to mimic ffuf precision matching
                if response.status == 200:
                    parsed_final = urlparse(final_url)
                    parsed_original = urlparse(url)
                    
                    # If it redirected from an important path back to a generic landing homepage, skip it
                    if parsed_final.path in ["", "/"] and parsed_original.path not in ["", "/"]:
                        return None
                        
                    print(f"[\033[92mMATCH\033[0m] Found: {url} -> Status: 200")
                    return {"url": url, "status": 200, "final_destination": final_url}
                    
                else:
                    # Non-200 responses are compressed into an inline terminal status ticker
                    print(f"[\033[90mFUZZ\033[0m] {url} ({response.status})", end="\r")
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
            # Step A: Execute Subdominator Phase
            subdomains = await fetch_passive_subdomains(session, target)
            print(f"[*] [Subdominator Phase] Successfully mapped {len(subdomains)} live subdomains for target: {target}")
            
            # Step B: Build Global Scan Matrix
            scan_queue = []
            for sub in subdomains:
                # Seed base target addresses
                scan_queue.append(f"http://{sub}")
                scan_queue.append(f"https://{sub}")
                # Seed directory fuzz targets
                for path in paths_wordlist:
                    scan_queue.append(f"http://{sub}{path}")
                    scan_queue.append(f"https://{sub}{path}")
            
            print(f"[*] [ffuf Phase] Combined Target Fuzz Matrix Compiled: {len(scan_queue)} endpoints.")
            print("[*] Launching async verification workers... \n")
            
            # Step C: Execute Concurrent Path Vulnerability Scan Execution
            tasks = [evaluate_endpoint(session, url, timeout, semaphore) for url in scan_queue]
            results = await asyncio.gather(*tasks)
            
            # Compress verified output tracking records
            target_findings = [res for res in results if res is not None]
            all_discovered_endpoints.extend(target_findings)
            
        print("\n" + "="*75)
        print(f"[*] Target evaluation complete. Pipeline captured {len(all_discovered_endpoints)} unique verified live endpoints.")
        
        # Save output structured configurations
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
                    
        print(f"[+] Operational log exported completely to: '{args.output}'")


# --- [5. ENTRY SYSTEM MANAGER] ---
def run():
    print("="*75)
    print("          Subdominator x ffuf Unified Scanner v3.0 - Production Core")
    print("="*75)

    parser = argparse.ArgumentParser(description="Subdominator + ffuf Combined Enterprise Web Asset Pipeline")
    parser.add_argument("-i", "--input", required=True, help="Domain context string or asset list path")
    parser.add_argument("-o", "--output", required=True, help="Target storage track output data location")
    parser.add_argument("-f", "--format", choices=["json", "csv", "txt"], default="json")
    parser.add_argument("-c", "--concurrent", type=int, default=30, help="Parallel session limit. Default: 30")
    parser.add_argument("-t", "--timeout", type=int, default=6, help="Timeout maximum boundary edge limit")
    
    args = parser.parse_args()
    
    # Load dictionary assets safely
    paths_list = load_brute_paths("scanner_config.ini")
    
    target_source = args.input.strip()
    targets = []
    
    if os.path.isfile(target_source):
        with open(target_source, "r", encoding="utf-8") as f:
            targets = [line.strip() for line in f if line.strip()]
    else:
        targets = [target_source]
        
    if not targets:
        print("[!] Operational Error: No targets selected.")
        sys.exit(1)
        
    # Launch structural orchestration sequence loops
    asyncio.run(main_pipeline(targets, paths_list, args))
    
    print("="*75)
    print("                    Execution Pipeline Complete! 🎯")
    print("="*75)

if __name__ == "__main__":
    run()
