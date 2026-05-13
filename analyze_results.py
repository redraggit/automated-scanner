#!/usr/bin/env python3
"""
Results Analyzer - Analyze bug bounty scan results
Helps identify interesting endpoints and potential vulnerabilities
"""

import json
import argparse
from collections import defaultdict
from urllib.parse import urlparse

class ResultsAnalyzer:
    def __init__(self, results_file):
        with open(results_file, 'r') as f:
            self.data = json.load(f)
        
        self.endpoints = self.data.get('endpoints', {})
        self.all_endpoints = []
        
        for base_url, eps in self.endpoints.items():
            self.all_endpoints.extend(eps)
    
    def analyze(self):
        """Run all analysis functions"""
        print("=" * 70)
        print("  BUG BOUNTY SCAN RESULTS ANALYSIS")
        print("=" * 70)
        print()
        
        self.show_summary()
        print()
        self.find_interesting_endpoints()
        print()
        self.categorize_endpoints()
        print()
        self.find_potential_issues()
    
    def show_summary(self):
        """Show scan summary"""
        print("📊 SCAN SUMMARY")
        print("-" * 70)
        print(f"Scan Time: {self.data.get('scan_time', 'Unknown')}")
        print(f"Total URLs Scanned: {self.data.get('total_urls', 0)}")
        print(f"Total Endpoints Found: {self.data.get('total_endpoints', 0)}")
        print(f"Subdomains Discovered: {len(self.data.get('subdomains', []))}")
        
        if self.data.get('subdomains'):
            print(f"\nDiscovered Subdomains:")
            for sd in sorted(self.data['subdomains'])[:10]:
                print(f"  • {sd}")
            if len(self.data['subdomains']) > 10:
                print(f"  ... and {len(self.data['subdomains']) - 10} more")
    
    def find_interesting_endpoints(self):
        """Find potentially interesting endpoints"""
        print("🔍 INTERESTING ENDPOINTS")
        print("-" * 70)
        
        patterns = {
            '🔐 Authentication/Admin': ['admin', 'login', 'auth', 'signin', 'dashboard', 'panel', 'control'],
            '🛠️ API Endpoints': ['/api', '/v1', '/v2', '/graphql', '/rest'],
            '📝 Documentation': ['docs', 'swagger', 'api-docs', 'documentation', 'graphiql'],
            '⚙️ Configuration': ['config', '.env', 'settings', 'environment'],
            '🔧 Development/Debug': ['debug', 'test', 'dev', 'staging', 'beta', 'qa'],
            '📦 File Operations': ['upload', 'download', 'files', 'backup', 'export', 'dump'],
            '🔓 Potential Leaks': ['.git', '.svn', 'backup', '.env', 'config.json', 'database'],
        }
        
        findings = defaultdict(list)
        
        for endpoint in self.all_endpoints:
            endpoint_lower = endpoint.lower()
            for category, keywords in patterns.items():
                if any(keyword in endpoint_lower for keyword in keywords):
                    findings[category].append(endpoint)
        
        for category, eps in findings.items():
            if eps:
                print(f"\n{category}:")
                for ep in sorted(set(eps))[:5]:
                    print(f"  • {ep}")
                if len(set(eps)) > 5:
                    print(f"  ... and {len(set(eps)) - 5} more")
    
    def categorize_endpoints(self):
        """Categorize endpoints by type"""
        print("📂 ENDPOINT CATEGORIES")
        print("-" * 70)
        
        categories = defaultdict(int)
        
        for endpoint in self.all_endpoints:
            parsed = urlparse(endpoint)
            path = parsed.path.lower()
            
            if '/api' in path or '/v1' in path or '/v2' in path:
                categories['API Endpoints'] += 1
            elif any(x in path for x in ['admin', 'dashboard', 'panel']):
                categories['Admin Areas'] += 1
            elif any(x in path for x in ['login', 'signin', 'auth', 'oauth']):
                categories['Authentication'] += 1
            elif any(x in path for x in ['docs', 'swagger', 'documentation']):
                categories['Documentation'] += 1
            elif any(x in path for x in ['config', '.env', 'settings']):
                categories['Configuration'] += 1
            elif any(x in path for x in ['upload', 'download', 'file']):
                categories['File Operations'] += 1
            else:
                categories['Other'] += 1
        
        for category, count in sorted(categories.items(), key=lambda x: x[1], reverse=True):
            percentage = (count / len(self.all_endpoints) * 100) if self.all_endpoints else 0
            print(f"{category:.<40} {count:>5} ({percentage:>5.1f}%)")
    
    def find_potential_issues(self):
        """Find potential security issues"""
        print("⚠️  POTENTIAL SECURITY ISSUES")
        print("-" * 70)
        
        issues = defaultdict(list)
        
        for endpoint in self.all_endpoints:
            endpoint_lower = endpoint.lower()
            
            # Exposed sensitive files
            if any(x in endpoint_lower for x in ['.env', '.git', 'config.json', 'web.config', 'database.yml']):
                issues['🚨 Exposed Sensitive Files'].append(endpoint)
            
            # Backup files
            if any(x in endpoint_lower for x in ['backup', '.bak', '.old', '.backup', 'dump', 'sql']):
                issues['💾 Backup Files'].append(endpoint)
            
            # Debug/Test endpoints
            if any(x in endpoint_lower for x in ['/debug', '/test', '/dev', '/_debug', '/phpinfo']):
                issues['🐛 Debug/Test Endpoints'].append(endpoint)
            
            # Admin without subdomain
            if 'admin' in endpoint_lower and 'admin.' not in urlparse(endpoint).netloc:
                issues['🔑 Admin Paths on Main Domain'].append(endpoint)
            
            # GraphQL endpoints (often allow introspection)
            if 'graphql' in endpoint_lower or 'graphiql' in endpoint_lower:
                issues['📊 GraphQL Endpoints (Check Introspection)'].append(endpoint)
        
        if not any(issues.values()):
            print("No obvious security issues detected.")
            print("Note: Manual verification is still required!")
        else:
            for issue_type, eps in issues.items():
                if eps:
                    print(f"\n{issue_type}:")
                    for ep in sorted(set(eps))[:5]:
                        print(f"  • {ep}")
                    if len(set(eps)) > 5:
                        print(f"  ... and {len(set(eps)) - 5} more")
    
    def export_high_priority(self, output_file):
        """Export high-priority targets to a file"""
        high_priority = []
        
        priority_keywords = [
            '.env', '.git', 'config', 'admin', 'dashboard', 'api',
            'backup', 'debug', 'graphql', 'swagger', 'upload'
        ]
        
        for endpoint in self.all_endpoints:
            if any(kw in endpoint.lower() for kw in priority_keywords):
                high_priority.append(endpoint)
        
        with open(output_file, 'w') as f:
            f.write("# High Priority Targets\n")
            f.write(f"# Total: {len(set(high_priority))}\n\n")
            for ep in sorted(set(high_priority)):
                f.write(f"{ep}\n")
        
        print(f"\n✅ Exported {len(set(high_priority))} high-priority targets to {output_file}")


def main():
    parser = argparse.ArgumentParser(description='Analyze bug bounty scan results')
    parser.add_argument('-i', '--input', required=True, help='Input JSON results file')
    parser.add_argument('-o', '--output', help='Export high-priority targets to file')
    
    args = parser.parse_args()
    
    analyzer = ResultsAnalyzer(args.input)
    analyzer.analyze()
    
    if args.output:
        print()
        analyzer.export_high_priority(args.output)
    
    print("\n" + "=" * 70)
    print("⚠️  REMEMBER: Always verify findings manually!")
    print("=" * 70)


if __name__ == '__main__':
    main()
