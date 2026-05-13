#!/usr/bin/env python3
import os
import sys
import json
import csv
import asyncio
import aiohttp
import argparse

# --- [STAGE 1: PRODUCTION HISTORICAL SUBDOMAIN DISCOVERY] ---
async def fetch_passive_subdomains(session, domain):
    """
    Queries three separate public datasets concurrently.
    Extracts historical records using completely qualified network schemas.
    """
    print(f"[*] [Stage 1] Mining complete historical subdomain map for '{domain}'...")
    discovered = {domain, f"www.{domain}"}
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0"}
    
    # Source A: Certificate Transparency Logs API
    async def query_crt_sh():
        url = f"crt.sh.{domain}&output=json"
        try:
            async with session.get(url, headers=headers, timeout=45) as r:
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

    # Source B: AlienVault Open Threat Exchange Passive DNS History
    async def query_alienvault():
        url = f"alienvault.com{domain}/passive_dns"
        try:
            async with session.get(url, headers=headers, timeout=45) as r:
                if r.status == 200:
                    data = await r.json()
                    for entry in data.get("passive_dns", []):
                        hostname = entry.get("hostname", "").strip().lower()
                        if hostname and hostname.endswith(domain):
                            discovered.add(hostname)
        except Exception:
            pass

    # Source C: Centralized AnubisDB Archive Tracker
    async def query_anubis():
        url = f"https://jldc.me/anubis/subdomains/{domain}"
        try:
            async with session.get(url, headers=headers, timeout=45) as r:
                if r.status == 200:
                    data = await r.json()
                    for sub in data:
                        clean = sub.strip().lower()
                        if clean and clean.endswith(domain):
                            discovered.add(clean)
        except Exception:
            pass

    # Run execution channels concurrently inside isolated containment layers
    await asyncio.gather(query_crt_sh(), query_alienvault(), query_anubis())
    return sorted(list(discovered))


# --- [STAGE 2: RAW UNRESTRICTED ENDPOINT INTERCEPTOR] ---
async def evaluate_endpoint(session, url, timeout, semaphore):
    """
    Directly hits mapped network channels without internal silencing filters.
    Forces output to print raw status configurations straight onto the terminal frame.
    """
    # Exclude external multi-tenant authorization loops to focus output tracking
    login_fingerprints = ["google.com", "microsoftonline.com", "okta.com", "auth0.com"]
    target_statuses = [200, 301, 302, 401, 403, 405]
    
    async with semaphore:
        try:
            headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
            # allow_redirects=True ensures we discover where assets redirect
            async with session.get(url, timeout=timeout, headers=headers, allow_redirects=True) as response:
                final_url = str(response.url)
                status_code = response.status
                
                try:
                    content_length = len(await response.read())
                except Exception:
                    content_length = 0
                
                if any(fingerprint in final_url for fingerprint in login_fingerprints):
                    return None
                
                # RECON POLICY: Capture and echo all actionable tracking flags instantly
                if status_code in target_statuses or response.history:
                    sys.stdout.write("\033[K")  # Completely clear the buffer ticker row
                    
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
                    # Clear carriage line feedback ticker loop updates cleanly
                    sys.stdout.write(f"[\033[90mFUZZ\033[0m] Evaluating: {url} ({status_code})\033[K\r")
                    sys.stdout.flush()
                    return None
        except Exception:
            return None


# --- [STAGE 3: PIPELINE EXECUTION CONTEXT BRIDGE] ---
async def main_pipeline(targets, paths_wordlist, args):
    semaphore = asyncio.BoundedSemaphore(args.concurrent)
    timeout = aiohttp.ClientTimeout(total=args.timeout)
    
    async with aiohttp.ClientSession() as session:
        all_discovered_endpoints = []
        
        for target in targets:
            # Step A: Enumerate full history lists
            subdomains = await fetch_passive_subdomains(session, target)
            print(f"[*] [Stage 1 Complete] Retrieved {len(subdomains)} unique subdomains from historical archives.")
            
            if not subdomains:
                continue

            # Step B: Build massive path expansion grid mapping matrix
            scan_queue = []
            for sub in subdomains:
                # Add base entry points
                scan_queue.append(f"http://{sub}")
                scan_queue.append(f"https://{sub}")
                
                # Loop out directories across protocols
                for path in paths_wordlist:
                    scan_queue.append(f"http://{sub}{path}")
                    scan_queue.append(f"https://{sub}{path}")
            
            print(f"[*] [Stage 2] Compiled Matrix: {len(scan_queue)} total structural targets queued.")
            print("[*] Launching async verification workers... \n")
            
            # Step C: Parallel worker tracking dispatch execution loop
            tasks = [evaluate_endpoint(session, url, timeout, semaphore) for url in scan_queue]
            results = await asyncio.gather(*tasks)
            
            target_findings = [res for res in results if res is not None]
            all_discovered_endpoints.extend(target_findings)
            
        sys.stdout.write("\033[K")  # Finalize clean stdout tracking print boundaries
        print("\n" + "="*75)
        print(f"[*] Pipeline Execution Complete. Mapped {len(all_discovered_endpoints)} valid responsive attack points.")
        
        # Serialize database entries
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
                    
        print(f"[+] Operational data log cleanly exported to: '{args.output}'")


def run():
    print("="*75)
    print("       Subdominator x ffuf Framework v10.0 - Production Core Engine")
    print("="*75)

    parser = argparse.ArgumentParser(description="Subdominator + ffuf Unified Asset Pipeline")
    parser.add_argument("-i", "--input", required=True, help="Target domain context or asset file path")
    parser.add_argument("-o", "--output", required=True, help="Output tracking path location")
    parser.add_argument("-f", "--format", choices=["json", "csv", "txt"], default="json")
    parser.add_argument("-c", "--concurrent", type=int, default=60, help="Parallel request limit. Default: 60")
    parser.add_argument("-t", "--timeout", type=int, default=10, help="Network timeout barrier ceiling")
    
    args = parser.parse_args()
    paths_list = load_brute_paths("scanner_config.ini")
    
    target_source = args.input.strip()
    targets = [target_source] if not os.path.isfile(target_source) else [line.strip() for line in open(target_source, "r", encoding="utf-8") if line.strip()]
    
    if not targets:
        print("[!] Error: Targets parameter parsing failed.")
        sys.exit(1)
        
    asyncio.run(main_pipeline(targets, paths_list, args))
    print("="*75)
    print("                     Framework Run Finalized! 🎯")
    print("="*75)

if __name__ == "__main__":
    run()
