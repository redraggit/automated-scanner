#!/usr/bin/env python3
import os
import sys
import json
import csv
import asyncio
import aiohttp
import argparse

# --- [STAGE 1: DEEP OSINT HISTORICAL SUBDOMAIN DISCOVERY] ---
async def fetch_passive_subdomains(session, domain):
    """
    Queries production public API integrations concurrently.
    All integration channels utilize absolute HTTP schemas to prevent exceptions.
    """
    print(f"[*] [Stage 1: Subdominator] Pulling complete historical subdomain map for '{domain}'...")
    discovered = {domain, f"www.{domain}"}
    
    # Custom headers protect against programmatic edge-dropping rules
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0"}
    
    # Source A: Canonical Certificate Transparency Log API
    async def query_crt_sh():
        url = f"crt.sh.{domain}&output=json"
        try:
            async with session.get(url, headers=headers, timeout=35) as r:
                if r.status == 200:
                    data = await r.json()
                    for entry in data:
                        name_value = entry.get("name_value", "")
                        for name in name_value.replace(" ", "\n").split("\n"):
                            clean = name.replace("*.", "").strip().lower()
                            if clean and clean.endswith(domain):
                                discovered.add(clean)
        except Exception:
            pass

    # Source B: AlienVault Open Threat Exchange Route
    async def query_alienvault():
        url = f"alienvault.com{domain}/passive_dns"
        try:
            async with session.get(url, headers=headers, timeout=35) as r:
                if r.status == 200:
                    data = await r.json()
                    for entry in data.get("passive_dns", []):
                        hostname = entry.get("hostname", "").strip().lower()
                        if hostname and hostname.endswith(domain):
                            discovered.add(hostname)
        except Exception:
            pass

    # Source C: Anubis Open-Source Asset Database Target Index
    async def query_anubis():
        url = f"jldc.me{domain}"
        try:
            async with session.get(url, headers=headers, timeout=35) as r:
                if r.status == 200:
                    data = await r.json()
                    for sub in data:
                        clean = sub.strip().lower()
                        if clean and clean.endswith(domain):
                            discovered.add(clean)
        except Exception:
            pass

    # Fire all three discovery routines concurrently in separate workers
    await asyncio.gather(query_crt_sh(), query_alienvault(), query_anubis())
    return sorted(list(discovered))


# --- [STAGE 2: RAW UNRESTRICTED ENDPOINT RECON MODULE] ---
async def evaluate_endpoint(session, url, timeout, semaphore):
    """
    Evaluates subdomains and paths directly. Tracks status codes 
    (200, 301, 302, 401, 403, 405) to ensure total visibility of the attack surface.
    """
    # Exclude external generic multi-tenant single sign-on redirect tracks
    login_fingerprints = ["google.com", "microsoftonline.com", "okta.com", "auth0.com"]
    target_statuses = [200, 301, 302, 401, 403, 405]
    
    async with semaphore:
        try:
            headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
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
                    sys.stdout.write("\033[K")  # Wipe line ticker overlap artifacts
                    
                    if status_code == 200:
                        print(f"[\033[92m{status_code}\033[0m] LIVE ENDPOINT -> {url} (Bytes: {content_length})")
                    elif status_code in [401, 403]:
                        print(f"[\033[93m{status_code}\033[0m] PROTECTED ASSET -> {url}")
                    else:
                        print(f"[\033[94mINFO\033[0m] REDIRECTION MAP -> {url} ==> {final_url} ({status_code})")
                        
                    return {
                        "requested_url": url,
                        "resolved_status": status_code,
                        "content_length": content_length,
                        "final_destination": final_url
                    }
                else:
                    # Compressed line tracker keeps terminal interface updates clean
                    sys.stdout.write(f"[\033[90mFUZZ\033[0m] Evaluating: {url} ({status_code})\033[K\r")
                    sys.stdout.flush()
                    return None
        except Exception:
            return None


# --- [DYNAMIC WORDLIST LOADER ENGINE] ---
def parse_custom_wordlist(wordlist_path):
    """
    Parses custom external wordlists. Normalizes paths ensuring they begin 
    with a single forward slash to guarantee correct programmatic concatenation.
    """
    if not wordlist_path or not os.path.exists(wordlist_path):
        print(f"[!] Target Wordlist '{wordlist_path}' missing. Exiting initialization pipeline.")
        sys.exit(1)
        
    cleaned_paths = []
    print(f"[*] Parsing custom fuzzing wordlist payload: {wordlist_path}")
    
    with open(wordlist_path, "r", encoding="utf-8", errors="ignore") as wfile:
        for line in wfile:
            entry = line.strip()
            # Skip comments or empty lines inside the dictionary payload
            if not entry or entry.startswith("#"):
                continue
            
            # Normalize structure ensuring it is safely prefixed with a slash
            if not entry.startswith("/"):
                entry = f"/{entry}"
                
            cleaned_paths.append(entry)
            
    # Deduplicate payloads while maintaining total pipeline integrity
    return sorted(list(set(cleaned_paths)))


# --- [PIPELINE ORCHESTRATION BRIDGE] ---
async def main_pipeline(targets, paths_wordlist, args):
    semaphore = asyncio.BoundedSemaphore(args.concurrent)
    timeout = aiohttp.ClientTimeout(total=args.timeout)
    
    async with aiohttp.ClientSession() as session:
        all_discovered_endpoints = []
        
        for target in targets:
            # Step A: Enumerate full history lists
            subdomains = await fetch_passive_subdomains(session, target)
            print(f"[*] [Stage 1 Complete] Retrieved {len(subdomains)} unique public subdomains for target: {target}")
            
            if not subdomains:
                continue

            # Step B: Compile comprehensive target execution grid matrix using your wordlist entries
            scan_queue = []
            for sub in subdomains:
                scan_queue.append(f"http://{sub}")
                scan_queue.append(f"https://{sub}")
                for path in paths_wordlist:
                    scan_queue.append(f"http://{sub}{path}")
                    scan_queue.append(f"https://{sub}{path}")
            
            print(f"[*] [Stage 2: ffuf Module] Fuzz Matrix Compiled: {len(scan_queue)} endpoints queued using wordlist payloads.")
            print("[*] Launching async verification workers... \n")
            
            # Step C: Run concurrent fuzzer tasks directly against the target matrix
            tasks = [evaluate_endpoint(session, url, timeout, semaphore) for url in scan_queue]
            results = await asyncio.gather(*tasks)
            
            target_findings = [res for res in results if res is not None]
            all_discovered_endpoints.extend(target_findings)
            
        sys.stdout.write("\033[K")  # Clear leftover line buffers from the fuzzer tracking loop
        print("\n" + "="*75)
        print(f"[*] Recon complete. Pipeline mapped {len(all_discovered_endpoints)} valid target configurations.")
        
        # Write final outputs to file
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
                    
        print(f"[+] Output record successfully written to: '{args.output}'")


def run():
    print("="*75)
    print("       Subdominator x ffuf Framework v10.5 - Absolute Master Release")
    print("="*75)

    parser = argparse.ArgumentParser(description="Subdominator + ffuf Unified Enterprise Web Asset Pipeline")
    parser.add_argument("-i", "--input", required=True, help="Target domain context string or list path")
    parser.add_argument("-w", "--wordlist", required=True, help="Custom wordlist file containing endpoints to fuzz")
    parser.add_argument("-o", "--output", required=True, help="Target storage track output location")
    parser.add_argument("-f", "--format", choices=["json", "csv", "txt"], default="json")
    parser.add_argument("-c", "--concurrent", type=int, default=60, help="Parallel processing threshold (Default: 60)")
    parser.add_argument("-t", "--timeout", type=int, default=10, help="Network request connection timeout barrier")
    
    args = parser.parse_args()
    
    # Load dynamic wordlist using the -w flag parameter instead of internal hardcoded defaults
    paths_list = parse_custom_wordlist(args.wordlist)
    
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
