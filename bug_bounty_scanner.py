#!/usr/bin/env python3
import os
import sys
import json
import csv
import asyncio
import aiohttp
import argparse

# --- [1. SAFE FLAT-TEXT CONFIGURATION PARSER] ---
def load_scan_configurations(config_path="scanner_config.ini"):
    """
    Safely reads raw lines from the config file without crashing on missing sections.
    Separates subdomains from directory paths based on structural prefixes.
    """
    default_subs = ["www", "mail", "api", "admin", "dev", "staging", "beta", "test", "app"]
    default_paths = ["/api", "/admin", "/login", "/dashboard", "/.env", "/.git/config"]
    
    if not os.path.exists(config_path):
        print(f"[!] Warning: '{config_path}' not found on disk. Reverting to basic internal defaults.")
        return default_subs, default_paths

    try:
        with open(config_path, "r", encoding="utf-8") as cfg:
            lines = [line.strip() for line in cfg if line.strip() and not line.strip().startswith("#")]
        
        # Route entries based on URL formatting conventions
        subdomains = [item for item in lines if not item.startswith("/")]
        paths = [item for item in lines if item.startswith("/")]
        
        subdomains = subdomains if subdomains else default_subs
        paths = paths if paths else default_paths
        
        print(f"[*] Configurations Merged: {len(subdomains)} subdomains & {len(paths)} paths.")
        return subdomains, paths
    except Exception as e:
        print(f"[!] Failed to parse configuration file ({e}). Utilizing fallback lists.")
        return default_subs, default_paths


# --- [2. ASYNCHRONOUS SCAN WORKER ENGINE] ---
async def check_endpoint(session, url, timeout, semaphore):
    """
    Performs a network request against a targeted target endpoint.
    Leverages a semaphore constraint to prevent overwhelming your connection pipeline.
    """
    async with semaphore:
        try:
            # Custom browser agent used to bypass primary string firewall filters
            headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
            async with session.get(url, timeout=timeout, headers=headers, allow_redirects=False) as response:
                # Print real-time diagnostics straight onto the active command-line interface
                if response.status == 200:
                    print(f"[\033[92mLIVE\033[0m] Found: {url} (Status: {response.status})")
                elif response.status in [301, 302]:
                    print(f"[\033[94mMOVE\033[0m] Redirect: {url} -> {response.headers.get('Location')}")
                else:
                    # Optional diagnostic visibility for non-200 responses
                    print(f"[\033[90mFAIL\033[0m] Checked: {url} (Status: {response.status})", end="\r")
                
                return {"url": url, "status": response.status}
        except asyncio.TimeoutError:
            return None
        except Exception:
            return None


# --- [3. CORE COORDINATOR RUN LOOP] ---
async def start_scanner_loop(targets, subdomains, paths, args):
    """
    Maps subdomains and asset endpoints into the worker queue.
    Collects execution metrics asynchronously.
    """
    semaphore = asyncio.BoundedSemaphore(args.concurrent)
    timeout = aiohttp.ClientTimeout(total=args.timeout)
    
    # Build complete network targeting matrices
    scan_queue = []
    for target in targets:
        for sub in subdomains:
            base_url = f"http://{sub}.{target}"
            scan_queue.append(base_url) # Check the raw subdomain
            for path in paths:
                scan_queue.append(f"{base_url}{path}") # Check subdirectory variations

    print(f"[*] Network Scan Queue Constructed: {len(scan_queue)} total target endpoints mapped.")
    print("[*] Launching async worker engine... (Displaying findings in real-time below)\n")

    findings = []
    async with aiohttp.ClientSession() as session:
        tasks = [check_endpoint(session, url, timeout, semaphore) for url in scan_queue]
        results = await asyncio.gather(*tasks)
        findings = [res for res in results if res is not None]
        
    print("\n" + "="*75)
    print(f"[*] Async execution sequence completed. Discovered {len(findings)} responsive configurations.")
    
    # --- [4. PERSISTENT STORAGE SERIALIZER] ---
    if args.format == "json":
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(findings, f, indent=4)
    elif args.format == "csv":
        with open(args.output, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=["url", "status"])
            writer.writeheader()
            writer.writerows(findings)
    elif args.format == "txt":
        with open(args.output, "w", encoding="utf-8") as f:
            for item in findings:
                f.write(f"[{item['status']}] {item['url']}\n")
                
    print(f"[+] Output record successfully compiled: '{args.output}'")


# --- [5. INITIALIZATION ENTRY POINT] ---
def run():
    print("="*75)
    print("          Bug Bounty Automated Scanner v2.0 - Stabilized Edition")
    print("="*75)

    parser = argparse.ArgumentParser(description="Automated Async Bug Bounty Scanner Engine")
    parser.add_argument("-i", "--input", required=True, help="Domain context (doximity.com) OR list path")
    parser.add_argument("-o", "--output", required=True, help="Output storage file target route")
    parser.add_argument("-f", "--format", choices=["json", "csv", "txt"], default="json", help="Serialization schema format")
    parser.add_argument("-c", "--concurrent", type=int, default=5, help="Async concurrent semaphore threshold")
    parser.add_argument("-t", "--timeout", type=int, default=5, help="Network timeout barrier")
    
    args = parser.parse_args()
    
    # Extract line configurations using our flat array tracker fix
    subdomains_list, paths_list = load_scan_configurations("scanner_config.ini")
    
    # Validate raw CLI inputs vs file mapping frameworks
    target_source = args.input.strip()
    targets = []
    
    if os.path.isfile(target_source):
        print(f"[*] Importing target array from local registry path: {target_source}")
        with open(target_source, "r", encoding="utf-8") as f:
            targets = [line.strip() for line in f if line.strip()]
    else:
        print(f"[*] Target parsed natively from raw command-line string parameter.")
        targets = [target_source]
        
    if not targets:
        print("[!] Execution Failure: Empty target resolution queue map layout.")
        sys.exit(1)
        
    print(f"[*] Targeting Scope: {targets}")
    
    # Bridge variables straight into the underlying asyncio processing environment
    asyncio.run(start_scanner_loop(targets, subdomains_list, paths_list, args))
    
    print("="*75)
    print("                    Scan Complete! 🎯")
    print("="*75)

if __name__ == "__main__":
    run()
