#!/usr/bin/env python3
import os
import sys
import json
import csv
import asyncio
import aiohttp
import argparse

# --- [PHASE 1: MULTI-SOURCE PASSIVE OSINT ENGINE] ---
async def fetch_passive_subdomains(session, domain):
    """
    Queries public production API integrations concurrently.
    Extracts the complete public subdomain infrastructure from crt.sh and AlienVault.
    """
    print(f"[*] [Subdominator] Extracting comprehensive passive subdomain map for '{domain}'...")
    discovered = {domain, f"www.{domain}"}
    
    # Custom headers to bypass programmatic dropping rules on OSINT platforms
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0"}
    
    # Source A: crt.sh API Query
    async def query_crt_sh():
        url = f"crt.sh.{domain}&output=json"
        try:
            async with session.get(url, headers=headers, timeout=30) as r:
                if r.status == 200:
                    data = await r.json()
                    for entry in data:
                        for name in entry.get("name_value", "").split("\n"):
                            clean = name.replace("*.", "").strip().lower()
                            if clean and clean.endswith(domain):
                                discovered.add(clean)
        except Exception:
            pass

    # Source B: AlienVault OTX Passive DNS Query
    async def query_alienvault():
        url = f"alienvault.com{domain}/passive_dns"
        try:
            async with session.get(url, headers=headers, timeout=30) as r:
                if r.status == 200:
                    data = await r.json()
                    for entry in data.get("passive_dns", []):
                        hostname = entry.get("hostname", "").strip().lower()
                        if hostname and hostname.endswith(domain):
                            discovered.add(hostname)
        except Exception:
            pass

    # Process both intelligence databases concurrently
    await asyncio.gather(query_crt_sh(), query_alienvault())
    return sorted(list(discovered))


# --- [PHASE 2: HIGH-SPEED ENDPOINT RECON MODULE] ---
async def evaluate_endpoint(session, url, timeout, semaphore):
    """
    Evaluates subdomains and paths directly. Tracks status codes 
    (200, 301, 302, 401, 403, 405) to ensure total attack surface visibility.
    """
    # Exclude external generic multi-tenant single sign-on loops
    login_fingerprints = ["google.com", "microsoftonline.com", "okta.com", "auth0.com"]
    target_statuses = [200, 301, 302, 401, 403, 405]
    
    async with semaphore:
        try:
            headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
            # allow_redirects=True maps out where hidden endpoints ultimately lead
            async with session.get(url, timeout=timeout, headers=headers, allow_redirects=True) as response:
                final_url = str(response.url)
                status_code = response.status
                
                try:
                    content_length = len(await response.read())
                except Exception:
                    content_length = 0
                
                if any(fingerprint in final_url for fingerprint in login_fingerprints):
                    return None
                
                # Capture specified target response behaviors or active redirect tracks
                if status_code in target_statuses or response.history:
                    # Clear trailing inline terminal characters
                    sys.stdout.write("\033[K")
                    
                    if status_code == 200:
                        print(f"[\033[92m{status_code}\033[0m] Live Endpoint: {url} (Size: {content_length})")
                    elif status_code in [401, 403]:
                        print(f"[\033[93m{status_code}\033[0m] Restricted Access: {url}")
                    else:
                        print(f"[\033[94mINFO\033[0m] Path Active: {url} -> Leads to: {final_url}")
                        
                    return {
                        "requested_url": url,
                        "resolved_status": status_code,
                        "content_length": content_length,
                        "final_destination": final_url
                    }
                else:
                    # Dynamic console logging string update engine
                    sys.stdout.write(f"[\033[90mFUZZ\033[0m] Checking: {url} ({status_code})\033[K\r")
                    sys.stdout.flush()
                    return None
        except Exception:
            return None


def load_brute_paths(config_path="scanner_config.ini"):
    """Loads directory target variants from your local text configuration wordlist."""
    default_paths = ["/api", "/admin", "/login", "/dashboard", "/.env", "/.git/config"]
    if not os.path.exists(config_path):
        return default_paths
    try:
        with open(config_path, "r", encoding="utf-8") as cfg:
            paths = [line.strip() for line in cfg if line.strip() and line.strip().startswith("/")]
        return paths if paths else default_paths
    except Exception:
        return default_paths


# --- [PHASE 3: PIPELINE EXECUTION ENGINE] ---
async def main_pipeline(targets, paths_wordlist, args):
    semaphore = asyncio.BoundedSemaphore(args.concurrent)
    timeout = aiohttp.ClientTimeout(total=args.timeout)
    
    async with aiohttp.ClientSession() as session:
        all_discovered_endpoints = []
        
        for target in targets:
            # Step A: Enumerate full subdomain layout via combined OSINT sources
            subdomains = await fetch_passive_subdomains(session, target)
            print(f"[*] [Subdominator Phase] Discovered {len(subdomains)} unique public subdomains for: {target}")
            
            # Step B: Compile comprehensive target execution grid matrix
            scan_queue = []
            for sub in subdomains:
                # Add base subdomains directly into the mapping loop
                scan_queue.append(f"http://{sub}")
                scan_queue.append(f"https://{sub}")
                
                # Append directory paths against every found subdomain
                for path in paths_wordlist:
                    scan_queue.append(f"http://{sub}{path}")
                    scan_queue.append(f"https://{sub}{path}")
            
            print(f"[*] [ffuf Phase] Scanning Matrix: {len(scan_queue)} endpoints queued for validation.")
            print("[*] Launching async verification workers... \n")
            
            # Step C: Run concurrent fuzzer tasks directly against the target matrix
            tasks = [evaluate_endpoint(session, url, timeout, semaphore) for url in scan_queue]
            results = await asyncio.gather(*tasks)
            
            target_findings = [res for res in results if res is not None]
            all_discovered_endpoints.extend(target_findings)
            
        sys.stdout.write("\033[K") # Clear leftover line buffers from the fuzzer tracking loop
        print("\n" + "="*75)
        print(f"[*] Recon complete. Pipeline mapped {len(all_discovered_endpoints)} valid target configurations.")
        
        # Write output files to disk
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
                    f.write(f"[{item['resolved_status']}] {item['requested_url']} -> {item['final_destination']}\n")
                    
        print(f"[+] Output data tracking logs saved completely to: '{args.output}'")


def run():
    print("="*75)
    print("          Subdominator x ffuf Framework v7.1 - Final Fixed Core")
    print("="*75)

    parser = argparse.ArgumentParser(description="Subdominator + ffuf Unified Enterprise Web Asset Pipeline")
    parser.add_argument("-i", "--input", required=True, help="Target domain context string or list path")
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
