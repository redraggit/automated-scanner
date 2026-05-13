import os
import argparse
import sys

# --- [FIXED CONFIGURATION PARSER CODESPACE] ---
def load_scan_configurations(config_path="scanner_config.ini"):
    """
    Safely reads raw lines from the config file without crashing on missing keys.
    Automatically segregates subdomains from file paths based on string patterns.
    """
    # Bulletproof fallback defaults in case your config gets corrupted again
    default_subs = ["www", "mail", "api", "admin", "dev", "staging", "beta", "test"]
    default_paths = ["/api", "/admin", "/login", "/dashboard", "/.env", "/.git/config"]
    
    if not os.path.exists(config_path):
        print(f"[!] Warning: '{config_path}' missing. Utilizing internal defaults.")
        return default_subs, default_paths

    try:
        with open(config_path, "r", encoding="utf-8") as cfg:
            # Drop clean whitespace, extract real payloads, skip comment annotations (#)
            lines = [line.strip() for line in cfg if line.strip() and not line.strip().startswith("#")]
        
        # Smart router: paths begin with structural slash separators, subdomains do not
        subdomains = [item for item in lines if not item.startswith("/")]
        paths = [item for item in lines if item.startswith("/")]
        
        # Safeguard logic: Ensure lists are never parsed back empty
        subdomains = subdomains if subdomains else default_subs
        paths = paths if paths else default_paths
        
        print(f"[*] Configuration Loaded: {len(subdomains)} subdomains & {len(paths)} paths.")
        return subdomains, paths
        
    except Exception as e:
        print(f"[!] Target config parsing failed ({e}). Reverting to core defaults.")
        return default_subs, default_paths


# --- [FIXED INPUT REGISTRATION & EXECUTION ENGINE] ---
def run():
    parser = argparse.ArgumentParser(description="Automated Scanner v2.0")
    parser.add_argument("-i", "--input", required=True, help="Target domain (e.g. doximity.com) OR text file track")
    parser.add_argument("-o", "--output", required=True, help="Output destination trace path")
    parser.add_argument("-f", "--format", choices=["json", "csv", "txt"], default="json")
    parser.add_argument("-c", "--concurrent", type=int, default=5)
    parser.add_argument("-t", "--timeout", type=int, default=5)
    
    args = parser.parse_args()
    
    # Run the fixed configuration line reader
    subdomains_list, paths_list = load_scan_configurations("scanner_config.ini")
    
    # --- DYNAMIC RANGE INPUT CHECKER ---
    # This prevents the specific [Errno 2] error when passing a string directly
    target_source = args.input.strip()
    targets = []
    
    if os.path.isfile(target_source):
        # The user provided a real text file list path on disk
        print(f"[*] Loading targets from system map file: {target_source}")
        with open(target_source, "r", encoding="utf-8") as f:
            targets = [line.strip() for line in f if line.strip()]
    else:
        # The user typed a raw domain literal directly into the terminal string
        print(f"[*] Input string registered directly as target context domain.")
        targets = [target_source]
        
    if not targets:
        print("[!] Fatal Error: Execution stopped. No valid target assets detected.")
        sys.exit(1)
        
    print(f"[*] Active Queue Targets: {targets}")
    
    # Continue into your pre-existing async event loop orchestration engine...
    # (e.g., asyncio.run(start_scanner_loop(targets, subdomains_list, paths_list, args)))

if __name__ == "__main__":
    run()
