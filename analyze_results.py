#!/usr/bin/env python3
"""
Bug Bounty Results Analyzer 
"""

import json
import argparse
from collections import defaultdict
from urllib.parse import urlparse
from datetime import datetime
import re

class Colors:
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    RESET = '\033[0m'

class ResultsAnalyzer:
    def __init__(self, results_file: str):
        with open(results_file, 'r') as f:
            self.data = json.load(f)
        
        self.endpoints = self.data.get('endpoints', {})
        self.subdomains = self.data.get('subdomains', [])
        self.all_endpoints = []
        
        for eps in self.endpoints.values():
            self.all_endpoints.extend(eps)

    def analyze(self):
        print(f"{Colors.GREEN}{'='*80}")
        print("          BUG BOUNTY RESULTS ANALYZER v2.0")
        print(f"{'='*80}{Colors.RESET}\n")

        self.show_summary()
        print()
        self.find_high_value_targets()
        print()
        self.categorize_endpoints()
        print()
        self.find_potential_vulnerabilities()
        print()
        self.recommend_next_steps()

    def show_summary(self):
        print(f"{Colors.BLUE}📊 SCAN SUMMARY{Colors.RESET}")
        print("-" * 80)
        print(f"Scan Time          : {self.data.get('scan_time', 'N/A')}")
        print(f"Total Subdomains   : {len(self.subdomains)}")
        print(f"Total URLs Scanned : {self.data.get('total_urls', 0)}")
        print(f"Total Endpoints    : {len(self.all_endpoints)}")
        
        if self.subdomains:
            print(f"\nTop 15 Subdomains:")
            for sd in sorted(self.subdomains)[:15]:
                print(f"   • {sd}")

    def find_high_value_targets(self):
        print(f"{Colors.BLUE}🔥 HIGH VALUE TARGETS{Colors.RESET}")
        print("-" * 80)

        high_value = defaultdict(list)
        patterns = {
            '🚨 Sensitive Files': ['.env', '.git', 'config.', 'web.config', 'database', 'backup'],
            '🔑 Admin Panels': ['admin', 'dashboard', 'panel', 'control', 'manage', 'cpanel'],
            '🔐 Authentication': ['login', 'signin', 'auth', 'oauth', 'token'],
            '📡 API Endpoints': ['/api', '/v1', '/v2', '/graphql', '/rest'],
            '📖 Documentation': ['swagger', 'docs', 'api-docs', 'graphiql', 'redoc'],
            '🐛 Debug/Test': ['debug', 'test', 'dev', 'staging', 'phpinfo'],
            '📤 File Uploads': ['upload', 'file', 'attachment'],
        }

        for ep in self.all_endpoints:
            lower = ep.lower()
            for category, keywords in patterns.items():
                if any(k in lower for k in keywords):
                    high_value[category].append(ep)

        for category, eps in high_value.items():
            unique = sorted(set(eps))
            if unique:
                print(f"\n{category} ({len(unique)} found):")
                for ep in unique[:6]:
                    print(f"   • {ep}")
                if len(unique) > 6:
                    print(f"   ... and {len(unique)-6} more")

    def categorize_endpoints(self):
        print(f"{Colors.BLUE}📂 ENDPOINT CATEGORIES{Colors.RESET}")
        print("-" * 80)

        categories = defaultdict(int)
        for ep in self.all_endpoints:
            path = urlparse(ep).path.lower()
            if '/api' in path or '/v' in path:
                categories['API'] += 1
            elif any(x in path for x in ['admin', 'dashboard', 'panel']):
                categories['Admin'] += 1
            elif any(x in path for x in ['login', 'auth', 'signin']):
                categories['Auth'] += 1
            elif any(x in path for x in ['upload', 'file']):
                categories['File Handling'] += 1
            elif any(x in path for x in ['debug', 'test', 'dev']):
                categories['Debug/Test'] += 1
            else:
                categories['Other'] += 1

        total = len(self.all_endpoints)
        for cat, count in sorted(categories.items(), key=lambda x: x[1], reverse=True):
            percentage = (count / total * 100) if total else 0
            print(f"{cat:<25} {count:>5} ({percentage:>5.1f}%)")

    def find_potential_vulnerabilities(self):
        print(f"{Colors.BLUE}⚠️  POTENTIAL VULNERABILITIES{Colors.RESET}")
        print("-" * 80)

        issues = defaultdict(list)

        for ep in self.all_endpoints:
            lower = ep.lower()
            if any(x in lower for x in ['.env', '.git/config', 'config.json', 'database']):
                issues['Exposed Sensitive Files'].append(ep)
            if 'graphql' in lower:
                issues['GraphQL (Check Introspection)'].append(ep)
            if any(x in lower for x in ['backup', '.bak', '.old', 'dump']):
                issues['Backup Files'].append(ep)
            if 'debug' in lower or 'phpinfo' in lower:
                issues['Debug Endpoints'].append(ep)

        if not issues:
            print("No high-risk issues detected.")
        else:
            for issue, eps in issues.items():
                print(f"\n{issue}:")
                for ep in sorted(set(eps))[:5]:
                    print(f"   • {ep}")

    def recommend_next_steps(self):
        print(f"{Colors.BLUE}🚀 RECOMMENDED NEXT STEPS{Colors.RESET}")
        print("-" * 80)
        print("1. Test high-value endpoints manually")
        print("2. Run nuclei: nuclei -l high_priority.txt -t http/")
        print("3. Check GraphQL introspection")
        print("4. Test .env and .git exposure")
        print("5. Use gf patterns on discovered endpoints")

    def export_high_priority(self, output_file: str):
        high_priority = []
        keywords = ['.env', '.git', 'admin', 'dashboard', 'api/', 'upload', 'debug', 'graphql', 'config']

        for ep in self.all_endpoints:
            if any(k in ep.lower() for k in keywords):
                high_priority.append(ep)

        with open(output_file, 'w') as f:
            f.write("# High Priority Targets for Manual Testing\n")
            f.write(f"# Generated: {datetime.now().isoformat()}\n\n")
            for ep in sorted(set(high_priority)):
                f.write(f"{ep}\n")

        print(f"{Colors.GREEN}[+] Exported {len(set(high_priority))} high-priority targets to {output_file}{Colors.RESET}")


def main():
    parser = argparse.ArgumentParser(description='Bug Bounty Results Analyzer')
    parser.add_argument('-i', '--input', required=True, help='Input JSON results file')
    parser.add_argument('-o', '--output', help='Export high priority targets')
    
    args = parser.parse_args()

    analyzer = ResultsAnalyzer(args.input)
    analyzer.analyze()

    if args.output:
        analyzer.export_high_priority(args.output)

    print(f"\n{Colors.GREEN}{'='*80}")
    print("Analysis Complete! Happy Hunting 🎯")
    print(f"{'='*80}{Colors.RESET}")


if __name__ == '__main__':
    main()
