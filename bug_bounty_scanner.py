#!/usr/bin/env python3
"""
Bug Bounty Automated Scanner 
"""

import asyncio
import aiohttp
import argparse
import json
import csv
import configparser
from urllib.parse import urljoin, urlparse
from typing import Set, List, Dict
from datetime import datetime
import re
from collections import defaultdict
import sys

# Colors for better output
class Colors:
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BLUE = '\033[94m'
    RESET = '\033[0m'

class BugBountyScanner:
    def __init__(self, max_concurrent=10, timeout=10, user_agent=None):
        self.max_concurrent = max_concurrent
        self.timeout = timeout
        self.user_agent = user_agent or "Mozilla/5.0 (compatible; BugBountyScanner/2.0)"
        
        self.subdomains = set()
        self.discovered_endpoints = defaultdict(set)
        self.semaphore = asyncio.Semaphore(max_concurrent)
        self.session = None

    async def init_session(self):
        """Initialize persistent aiohttp session"""
        if not self.session:
            timeout = aiohttp.ClientTimeout(total=self.timeout)
            self.session = aiohttp.ClientSession(
                timeout=timeout,
                headers={'User-Agent': self.user_agent}
            )

    async def close(self):
        if self.session:
            await self.session.close()

    async def load_config(self):
        """Load configuration from scanner_config.ini"""
        config = configparser.ConfigParser()
        try:
            config.read('scanner_config.ini')
            
            # Load subdomains from config
            if 'subdomains' in config:
                self.common_subdomains = [k.strip() for k in config['subdomains'] if k.strip()]
            else:
                self.common_subdomains = [...]  # fallback list (kept short)

            # Load common paths from config
            if 'endpoints' in config:
                self.common_paths = [k.strip() for k in config['endpoints'] if k.strip()]
            else:
                self.common_paths = ['/api', '/admin', ...]  # fallback

            print(f"{Colors.BLUE}[*]{Colors.RESET} Configuration loaded successfully")
        except Exception:
            print(f"{Colors.YELLOW}[!]{Colors.RESET} Could not load config, using defaults")

    async def check_subdomain(self, subdomain: str) -> str:
        """Check if subdomain is alive (HTTP + HTTPS)"""
        async with self.semaphore:
            for protocol in ['https', 'http']:
                try:
                    async with self.session.get(
                        f"{protocol}://{subdomain}",
                        allow_redirects=True
                    ) as resp:
                        if resp.status < 500:
                            print(f"{Colors.GREEN}[✓]{Colors.RESET} {subdomain} ({protocol}) - {resp.status}")
                            return subdomain
                except asyncio.TimeoutError:
                    continue
                except Exception:
                    continue
        return None

    async def enumerate_subdomains(self, wildcard_domain: str) -> Set[str]:
        print(f"{Colors.BLUE}[*]{Colors.RESET} Enumerating subdomains for: {wildcard_domain}")
        base_domain = wildcard_domain.replace('*.', '')

        tasks = [self.check_subdomain(f"{sub}.{base_domain}") for sub in self.common_subdomains]
        results = await asyncio.gather(*tasks)
        
        active = {sd for sd in results if sd}
        self.subdomains.update(active)
        
        print(f"{Colors.GREEN}[+]{Colors.RESET} Found {len(active)} active subdomains for {base_domain}")
        return active

    async def check_endpoint(self, endpoint: str) -> str:
        """Check single endpoint"""
        async with self.semaphore:
            try:
                async with self.session.get(endpoint, allow_redirects=False) as resp:
                    if resp.status in (200, 201, 202, 301, 302, 401, 403):
                        print(f"{Colors.GREEN}[✓]{Colors.RESET} {endpoint} - {resp.status}")
                        return endpoint
            except Exception:
                pass
        return None

    async def crawl_page(self, url: str) -> Set[str]:
        """Improved basic crawler"""
        endpoints = set()
        try:
            async with self.session.get(url) as resp:
                if resp.status != 200:
                    return endpoints
                
                html = await resp.text()
                base_domain = urlparse(url).netloc

                # Better regex for links
                patterns = [
                    r'href=["\']([^"\']+)["\']',
                    r'src=["\']([^"\']+)["\']'
                ]
                
                for pattern in patterns:
                    matches = re.findall(pattern, html)
                    for match in matches:
                        absolute = urljoin(url, match)
                        parsed = urlparse(absolute)
                        
                        if parsed.netloc == base_domain or not parsed.netloc:
                            clean = f"{parsed.scheme or 'https'}://{parsed.netloc}{parsed.path}"
                            if parsed.query:
                                clean += f"?{parsed.query}"
                            endpoints.add(clean)
        except Exception:
            pass
        return endpoints

    async def discover_endpoints(self, url: str):
        print(f"\n{Colors.BLUE}[*]{Colors.RESET} Discovering endpoints for: {url}")
        endpoints = {url}

        # Test common paths
        tasks = [self.check_endpoint(urljoin(url, path)) for path in self.common_paths]
        results = await asyncio.gather(*tasks)
        endpoints.update(ep for ep in results if ep)

        # Crawl
        crawled = await self.crawl_page(url)
        endpoints.update(crawled)

        self.discovered_endpoints[url].update(endpoints)
        print(f"{Colors.GREEN}[+]{Colors.RESET} Found {len(endpoints)} endpoints for {url}")

    async def scan_from_file(self, filepath: str):
        await self.init_session()
        await self.load_config()

        print(f"{Colors.BLUE}[*]{Colors.RESET} Loading targets from: {filepath}")
        with open(filepath, 'r') as f:
            targets = [line.strip() for line in f if line.strip() and not line.startswith('#')]

        all_urls = set()

        for target in targets:
            if target.startswith('*.'):
                subdomains = await self.enumerate_subdomains(target)
                for sd in subdomains:
                    all_urls.add(f"https://{sd}")
            else:
                if not target.startswith('http'):
                    target = f"https://{target}"
                all_urls.add(target)

        print(f"{Colors.BLUE}[*]{Colors.RESET} Starting endpoint discovery on {len(all_urls)} URLs...")

        tasks = [self.discover_endpoints(url) for url in all_urls]
        await asyncio.gather(*tasks)

    def export_results(self, output_file: str, format='json'):
        print(f"\n{Colors.BLUE}[*]{Colors.RESET} Exporting results to {output_file}")

        if format == 'json':
            results = {
                'scan_time': datetime.now().isoformat(),
                'total_urls': len(self.discovered_endpoints),
                'total_endpoints': sum(len(eps) for eps in self.discovered_endpoints.values()),
                'subdomains': sorted(self.subdomains),
                'endpoints': {url: sorted(list(eps)) for url, eps in self.discovered_endpoints.items()}
            }
            with open(output_file, 'w') as f:
                json.dump(results, f, indent=2)

        elif format == 'csv':
            with open(output_file, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(['Base_URL', 'Endpoint'])
                for base, eps in self.discovered_endpoints.items():
                    for ep in eps:
                        writer.writerow([base, ep])

        elif format == 'txt':
            with open(output_file, 'w') as f:
                f.write(f"Bug Bounty Scan Results - {datetime.now().isoformat()}\n\n")
                for base, eps in sorted(self.discovered_endpoints.items()):
                    f.write(f"\n=== {base} ===\n")
                    for ep in sorted(eps):
                        f.write(f"{ep}\n")

        print(f"{Colors.GREEN}[+] {Colors.RESET} Export completed! Total endpoints: {sum(len(eps) for eps in self.discovered_endpoints.values())}")


async def main():
    parser = argparse.ArgumentParser(description='Bug Bounty Automated Scanner v2.0')
    parser.add_argument('-i', '--input', required=True, help='Input targets file')
    parser.add_argument('-o', '--output', required=True, help='Output file')
    parser.add_argument('-f', '--format', choices=['json', 'csv', 'txt'], default='json')
    parser.add_argument('-c', '--concurrent', type=int, default=15)
    parser.add_argument('-t', '--timeout', type=int, default=10)
    parser.add_argument('-u', '--user-agent')

    args = parser.parse_args()

    print(f"{Colors.GREEN}{'='*70}")
    print("          Bug Bounty Automated Scanner v2.0")
    print(f"{'='*70}{Colors.RESET}")

    scanner = BugBountyScanner(
        max_concurrent=args.concurrent,
        timeout=args.timeout,
        user_agent=args.user_agent
    )

    try:
        await scanner.scan_from_file(args.input)
        scanner.export_results(args.output, args.format)
    except KeyboardInterrupt:
        print(f"\n{Colors.RED}[!]{Colors.RESET} Scan interrupted by user")
        scanner.export_results(args.output, args.format)
    except Exception as e:
        print(f"{Colors.RED}[!] Error: {e}{Colors.RESET}")
    finally:
        await scanner.close()

    print(f"\n{Colors.GREEN}{'='*70}")
    print("                    Scan Complete!")
    print(f"{'='*70}{Colors.RESET}")


if __name__ == '__main__':
    asyncio.run(main())
