#!/usr/bin/env python3
"""
Bug Bounty Automated Scanner
Scans wildcard domains for subdomains and endpoints
"""

import asyncio
import aiohttp
import argparse
import json
import csv
from urllib.parse import urljoin, urlparse
from typing import Set, List, Dict
from datetime import datetime
import re
from collections import defaultdict

class BugBountyScanner:
    def __init__(self, max_concurrent=10, timeout=10, user_agent=None):
        self.max_concurrent = max_concurrent
        self.timeout = timeout
        self.user_agent = user_agent or "BugBountyScanner/1.0"
        self.discovered_endpoints = defaultdict(set)
        self.subdomains = set()
        self.semaphore = asyncio.Semaphore(max_concurrent)
        
    async def enumerate_subdomains(self, wildcard_domain: str) -> Set[str]:
        """
        Enumerate subdomains for a wildcard domain
        Uses common subdomain wordlist
        """
        print(f"[*] Enumerating subdomains for: {wildcard_domain}")
        
        # Remove wildcard prefix
        base_domain = wildcard_domain.replace('*.', '')
        
        # Common subdomain wordlist
        common_subdomains = [
            'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 'webdisk',
            'ns2', 'cpanel', 'whm', 'autodiscover', 'autoconfig', 'ns', 'm', 'imap', 'test',
            'dev', 'staging', 'beta', 'api', 'admin', 'portal', 'dashboard', 'login', 'app',
            'blog', 'shop', 'store', 'cdn', 'static', 'media', 'assets', 'img', 'images',
            'upload', 'downloads', 'docs', 'support', 'help', 'status', 'monitor', 'vpn',
            'git', 'mysql', 'db', 'redis', 'jenkins', 'gitlab', 'github', 'jira', 'confluence'
        ]
        
        tasks = []
        for subdomain in common_subdomains:
            full_domain = f"{subdomain}.{base_domain}"
            tasks.append(self.check_subdomain(full_domain))
        
        results = await asyncio.gather(*tasks)
        active_subdomains = {sd for sd in results if sd}
        
        print(f"[+] Found {len(active_subdomains)} active subdomains for {base_domain}")
        self.subdomains.update(active_subdomains)
        return active_subdomains
    
    async def check_subdomain(self, subdomain: str) -> str:
        """Check if subdomain is active"""
        async with self.semaphore:
            try:
                async with aiohttp.ClientSession() as session:
                    async with session.get(
                        f"http://{subdomain}",
                        timeout=aiohttp.ClientTimeout(total=self.timeout),
                        allow_redirects=True,
                        headers={'User-Agent': self.user_agent}
                    ) as response:
                        if response.status < 500:  # Accept anything not server error
                            print(f"  [✓] {subdomain} - Status: {response.status}")
                            return subdomain
            except:
                pass
            return None
    
    async def discover_endpoints(self, url: str) -> Set[str]:
        """
        Discover endpoints for a given URL
        Methods: crawling, common paths, wayback machine simulation
        """
        print(f"\n[*] Discovering endpoints for: {url}")
        endpoints = set()
        
        # Add base URL
        endpoints.add(url)
        
        # Common endpoint patterns
        common_paths = [
            '/api', '/api/v1', '/api/v2', '/v1', '/v2',
            '/admin', '/login', '/signin', '/signup', '/register',
            '/dashboard', '/panel', '/control', '/manage',
            '/user', '/users', '/account', '/profile', '/settings',
            '/upload', '/download', '/files', '/documents',
            '/search', '/query', '/find',
            '/auth', '/oauth', '/token', '/authorize',
            '/docs', '/documentation', '/swagger', '/api-docs',
            '/status', '/health', '/ping', '/version',
            '/config', '/configuration', '/env', '/.env',
            '/backup', '/backups', '/dump', '/export',
            '/test', '/debug', '/dev', '/development',
            '/.git', '/.git/config', '/robots.txt', '/sitemap.xml',
            '/wp-admin', '/wp-login.php', '/phpmyadmin',
            '/graphql', '/graphiql', '/playground',
        ]
        
        # Test common paths
        path_tasks = []
        for path in common_paths:
            endpoint = urljoin(url, path)
            path_tasks.append(self.check_endpoint(endpoint))
        
        # Check all paths concurrently
        results = await asyncio.gather(*path_tasks)
        valid_endpoints = {ep for ep in results if ep}
        endpoints.update(valid_endpoints)
        
        # Crawl the main page for links
        crawled = await self.crawl_page(url)
        endpoints.update(crawled)
        
        # Store discovered endpoints
        self.discovered_endpoints[url].update(endpoints)
        
        print(f"[+] Discovered {len(endpoints)} endpoints for {url}")
        return endpoints
    
    async def check_endpoint(self, endpoint: str) -> str:
        """Check if endpoint exists and return it if valid"""
        async with self.semaphore:
            try:
                async with aiohttp.ClientSession() as session:
                    async with session.get(
                        endpoint,
                        timeout=aiohttp.ClientTimeout(total=self.timeout),
                        allow_redirects=False,
                        headers={'User-Agent': self.user_agent}
                    ) as response:
                        # Accept 200s, 300s, 401, 403 (authentication/authorization required)
                        if response.status in range(200, 400) or response.status in [401, 403]:
                            print(f"  [✓] {endpoint} - Status: {response.status}")
                            return endpoint
            except Exception as e:
                pass
            return None
    
    async def crawl_page(self, url: str, max_depth=1) -> Set[str]:
        """Crawl a page to find links"""
        endpoints = set()
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    url,
                    timeout=aiohttp.ClientTimeout(total=self.timeout),
                    headers={'User-Agent': self.user_agent}
                ) as response:
                    if response.status == 200:
                        html = await response.text()
                        
                        # Simple regex to find URLs (basic crawling)
                        # In production, use BeautifulSoup or similar
                        href_pattern = r'href=["\']([^"\']+)["\']'
                        src_pattern = r'src=["\']([^"\']+)["\']'
                        
                        matches = re.findall(href_pattern, html) + re.findall(src_pattern, html)
                        
                        base_domain = urlparse(url).netloc
                        
                        for match in matches:
                            # Convert relative URLs to absolute
                            absolute_url = urljoin(url, match)
                            parsed = urlparse(absolute_url)
                            
                            # Only include same domain
                            if parsed.netloc == base_domain:
                                # Clean URL (remove fragments, normalize)
                                clean_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                                if parsed.query:
                                    clean_url += f"?{parsed.query}"
                                endpoints.add(clean_url)
        
        except Exception as e:
            pass
        
        return endpoints
    
    async def scan_from_file(self, filepath: str):
        """Scan all wildcards/URLs from a file"""
        print(f"[*] Loading targets from: {filepath}")
        
        with open(filepath, 'r') as f:
            targets = [line.strip() for line in f if line.strip() and not line.startswith('#')]
        
        print(f"[*] Loaded {len(targets)} targets")
        
        all_urls = set()
        
        # Process each target
        for target in targets:
            if target.startswith('*.'):
                # It's a wildcard - enumerate subdomains
                subdomains = await self.enumerate_subdomains(target)
                for subdomain in subdomains:
                    all_urls.add(f"http://{subdomain}")
                    all_urls.add(f"https://{subdomain}")
            else:
                # It's a direct URL
                if not target.startswith('http'):
                    target = f"https://{target}"
                all_urls.add(target)
        
        print(f"\n[*] Total URLs to scan: {len(all_urls)}")
        
        # Discover endpoints for all URLs
        tasks = []
        for url in all_urls:
            tasks.append(self.discover_endpoints(url))
        
        await asyncio.gather(*tasks)
        
    def export_results(self, output_file: str, format='json'):
        """Export discovered endpoints to file"""
        print(f"\n[*] Exporting results to: {output_file}")
        
        if format == 'json':
            # Convert sets to lists for JSON serialization
            results = {
                'scan_time': datetime.now().isoformat(),
                'total_endpoints': sum(len(eps) for eps in self.discovered_endpoints.values()),
                'total_urls': len(self.discovered_endpoints),
                'subdomains': list(self.subdomains),
                'endpoints': {url: list(eps) for url, eps in self.discovered_endpoints.items()}
            }
            
            with open(output_file, 'w') as f:
                json.dump(results, f, indent=2)
        
        elif format == 'csv':
            with open(output_file, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(['Base URL', 'Endpoint', 'Discovered At'])
                
                timestamp = datetime.now().isoformat()
                for base_url, endpoints in self.discovered_endpoints.items():
                    for endpoint in endpoints:
                        writer.writerow([base_url, endpoint, timestamp])
        
        elif format == 'txt':
            with open(output_file, 'w') as f:
                f.write(f"# Bug Bounty Scan Results\n")
                f.write(f"# Scan Time: {datetime.now().isoformat()}\n")
                f.write(f"# Total Endpoints: {sum(len(eps) for eps in self.discovered_endpoints.values())}\n\n")
                
                for base_url, endpoints in sorted(self.discovered_endpoints.items()):
                    f.write(f"\n## {base_url}\n")
                    for endpoint in sorted(endpoints):
                        f.write(f"{endpoint}\n")
        
        print(f"[+] Results exported successfully!")
        print(f"[+] Total endpoints found: {sum(len(eps) for eps in self.discovered_endpoints.values())}")


async def main():
    parser = argparse.ArgumentParser(
        description='Bug Bounty Automated Scanner - Discover subdomains and endpoints',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Scan from a file containing wildcards and URLs
  python bug_bounty_scanner.py -i targets.txt -o results.json
  
  # Custom concurrency and timeout
  python bug_bounty_scanner.py -i targets.txt -o results.csv -f csv -c 20 -t 15
  
  # Export to multiple formats
  python bug_bounty_scanner.py -i targets.txt -o results.txt -f txt
        """
    )
    
    parser.add_argument('-i', '--input', required=True, help='Input file with wildcard domains/URLs (one per line)')
    parser.add_argument('-o', '--output', required=True, help='Output file for results')
    parser.add_argument('-f', '--format', choices=['json', 'csv', 'txt'], default='json', help='Output format (default: json)')
    parser.add_argument('-c', '--concurrent', type=int, default=10, help='Max concurrent requests (default: 10)')
    parser.add_argument('-t', '--timeout', type=int, default=10, help='Request timeout in seconds (default: 10)')
    parser.add_argument('-u', '--user-agent', help='Custom User-Agent string')
    
    args = parser.parse_args()
    
    print("=" * 60)
    print("    Bug Bounty Automated Scanner")
    print("=" * 60)
    
    scanner = BugBountyScanner(
        max_concurrent=args.concurrent,
        timeout=args.timeout,
        user_agent=args.user_agent
    )
    
    try:
        await scanner.scan_from_file(args.input)
        scanner.export_results(args.output, args.format)
        
        print("\n" + "=" * 60)
        print("    Scan Complete!")
        print("=" * 60)
        
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user")
        print("[*] Saving partial results...")
        scanner.export_results(args.output, args.format)
    except Exception as e:
        print(f"[!] Error: {e}")
        import traceback
        traceback.print_exc()


if __name__ == '__main__':
    asyncio.run(main())
