"""
Advanced Subdomain Discovery and Scanning Module
Comprehensive subdomain enumeration with multiple techniques
"""

import asyncio
import json
import logging
import re
import socket
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Set, Optional, Tuple
from urllib.parse import urlparse

import httpx


class SubdomainEnumerator:
    """Advanced subdomain enumeration using multiple techniques."""
    
    def __init__(self, session: httpx.AsyncClient, logger: logging.Logger):
        self.session = session
        self.logger = logger
        self.discovered_subdomains = set()
        self.alive_subdomains = set()
        
        # Comprehensive wordlist for subdomain brute forcing
        self.wordlist = self._load_subdomain_wordlist()
        
        # DNS resolvers for faster enumeration
        self.dns_resolvers = [
            '8.8.8.8',      # Google
            '1.1.1.1',      # Cloudflare
            '208.67.222.222', # OpenDNS
            '9.9.9.9'       # Quad9
        ]
    
    def _load_subdomain_wordlist(self) -> List[str]:
        """Load comprehensive subdomain wordlist."""
        return [
            # Common web services
            'www', 'mail', 'webmail', 'email', 'smtp', 'pop', 'imap', 'exchange',
            'autodiscover', 'autoconfig', 'mx', 'ns', 'ns1', 'ns2', 'ns3', 'dns',
            
            # Development & Testing
            'dev', 'test', 'testing', 'stage', 'staging', 'demo', 'sandbox', 'beta',
            'alpha', 'preview', 'qa', 'uat', 'preprod', 'pre-prod', 'integration',
            
            # Administrative
            'admin', 'administrator', 'root', 'manage', 'management', 'control',
            'panel', 'cpanel', 'whm', 'plesk', 'directadmin', 'webmin',
            
            # API & Services
            'api', 'apis', 'service', 'services', 'ws', 'webservice', 'webservices',
            'rest', 'soap', 'graphql', 'gateway', 'proxy', 'load-balancer', 'lb',
            
            # Applications
            'app', 'application', 'apps', 'portal', 'dashboard', 'console',
            'interface', 'ui', 'gui', 'client', 'web', 'site', 'website',
            
            # Mobile & Devices
            'mobile', 'm', 'wap', 'touch', 'tablet', 'android', 'ios', 'windows',
            
            # Content & Media
            'blog', 'news', 'forum', 'forums', 'community', 'social', 'wiki',
            'docs', 'documentation', 'help', 'support', 'faq', 'kb', 'knowledge',
            'media', 'images', 'img', 'pics', 'photos', 'video', 'videos',
            'files', 'download', 'downloads', 'upload', 'uploads', 'assets',
            'static', 'cdn', 'content', 'resources', 'data',
            
            # E-commerce
            'shop', 'store', 'cart', 'checkout', 'payment', 'pay', 'payments',
            'billing', 'invoice', 'order', 'orders', 'product', 'products',
            'catalog', 'inventory', 'stock',
            
            # Security & Monitoring
            'secure', 'security', 'ssl', 'tls', 'vpn', 'firewall', 'ids', 'ips',
            'monitor', 'monitoring', 'metrics', 'stats', 'statistics', 'analytics',
            'log', 'logs', 'logging', 'audit', 'alerts', 'status', 'health',
            
            # Infrastructure
            'server', 'servers', 'host', 'hosts', 'node', 'nodes', 'cluster',
            'cloud', 'aws', 'azure', 'gcp', 'docker', 'k8s', 'kubernetes',
            'jenkins', 'gitlab', 'github', 'git', 'svn', 'repo', 'repository',
            
            # Databases
            'db', 'database', 'mysql', 'postgres', 'postgresql', 'oracle', 'mssql',
            'mongodb', 'redis', 'memcached', 'elasticsearch', 'elastic', 'solr',
            
            # Environments
            'prod', 'production', 'live', 'public', 'private', 'internal',
            'intranet', 'extranet', 'local', 'localhost', 'backup', 'backups',
            'archive', 'old', 'legacy', 'deprecated',
            
            # Business Functions
            'hr', 'finance', 'accounting', 'sales', 'marketing', 'support',
            'customer', 'client', 'partner', 'vendor', 'supplier', 'affiliate',
            
            # Geographic & Regional
            'us', 'eu', 'asia', 'uk', 'ca', 'au', 'de', 'fr', 'jp', 'cn',
            'east', 'west', 'north', 'south', 'central', 'regional',
            
            # Numbered variations
            'www1', 'www2', 'www3', 'api1', 'api2', 'web1', 'web2', 'app1', 'app2',
            'server1', 'server2', 'host1', 'host2', 'node1', 'node2',
            
            # Special characters and patterns
            'www-dev', 'www-test', 'api-dev', 'api-test', 'web-app', 'app-server',
            'mail-server', 'file-server', 'db-server', 'cache-server'
        ]
    
    async def enumerate_subdomains(self, domain: str, 
                                 methods: List[str] = None,
                                 max_subdomains: int = 100) -> Dict:
        """
        Comprehensive subdomain enumeration using multiple techniques.
        
        Args:
            domain: Target domain
            methods: List of enumeration methods to use
            max_subdomains: Maximum number of subdomains to discover
            
        Returns:
            Dict containing discovered subdomains and metadata
        """
        if methods is None:
            methods = ['brute_force', 'certificate_transparency', 'dns_enumeration', 'passive_sources']
        
        self.logger.info(f"Starting subdomain enumeration for {domain}")
        start_time = datetime.now()
        
        results = {
            'domain': domain,
            'started_at': start_time.isoformat(),
            'methods_used': methods,
            'discovered_subdomains': {},
            'alive_subdomains': [],
            'total_discovered': 0,
            'total_alive': 0,
            'enumeration_time': 0
        }
        
        try:
            # Dictionary/Brute Force Enumeration
            if 'brute_force' in methods:
                self.logger.info("Starting dictionary-based brute force enumeration...")
                brute_force_results = await self._brute_force_enumeration(domain)
                results['discovered_subdomains']['brute_force'] = list(brute_force_results)
                self.discovered_subdomains.update(brute_force_results)
            
            # Certificate Transparency Logs
            if 'certificate_transparency' in methods:
                self.logger.info("Querying certificate transparency logs...")
                ct_results = await self._certificate_transparency_enumeration(domain)
                results['discovered_subdomains']['certificate_transparency'] = list(ct_results)
                self.discovered_subdomains.update(ct_results)
            
            # DNS-based Enumeration
            if 'dns_enumeration' in methods:
                self.logger.info("Performing DNS-based enumeration...")
                dns_results = await self._dns_based_enumeration(domain)
                results['discovered_subdomains']['dns_enumeration'] = list(dns_results)
                self.discovered_subdomains.update(dns_results)
            
            # Passive Sources
            if 'passive_sources' in methods:
                self.logger.info("Querying passive reconnaissance sources...")
                passive_results = await self._passive_sources_enumeration(domain)
                results['discovered_subdomains']['passive_sources'] = list(passive_results)
                self.discovered_subdomains.update(passive_results)
            
            # Permutation-based Discovery
            if 'permutations' in methods:
                self.logger.info("Generating subdomain permutations...")
                perm_results = await self._permutation_enumeration(domain)
                results['discovered_subdomains']['permutations'] = list(perm_results)
                self.discovered_subdomains.update(perm_results)
            
            # Limit results
            all_subdomains = list(self.discovered_subdomains)[:max_subdomains]
            
            # Verify alive subdomains
            self.logger.info(f"Verifying {len(all_subdomains)} discovered subdomains...")
            alive_subdomains = await self._verify_alive_subdomains(all_subdomains)
            
            # Update results
            results['alive_subdomains'] = list(alive_subdomains)
            results['total_discovered'] = len(all_subdomains)
            results['total_alive'] = len(alive_subdomains)
            
            end_time = datetime.now()
            results['completed_at'] = end_time.isoformat()
            results['enumeration_time'] = (end_time - start_time).total_seconds()
            
            self.logger.info(
                f"Subdomain enumeration completed: {results['total_discovered']} discovered, "
                f"{results['total_alive']} alive in {results['enumeration_time']:.2f}s"
            )
            
        except Exception as e:
            self.logger.error(f"Error during subdomain enumeration: {e}")
            results['error'] = str(e)
        
        return results
    
    async def _brute_force_enumeration(self, domain: str) -> Set[str]:
        """Brute force subdomain discovery using wordlist."""
        discovered = set()
        
        # Create semaphore to limit concurrent DNS queries
        semaphore = asyncio.Semaphore(50)
        
        async def check_subdomain(subdomain_name: str):
            async with semaphore:
                subdomain = f"{subdomain_name}.{domain}"
                if await self._dns_resolve(subdomain):
                    discovered.add(subdomain)
                    self.logger.debug(f"Found subdomain: {subdomain}")
        
        # Create tasks for all wordlist entries
        tasks = [check_subdomain(word) for word in self.wordlist]
        
        # Execute with progress tracking
        batch_size = 100
        for i in range(0, len(tasks), batch_size):
            batch = tasks[i:i+batch_size]
            await asyncio.gather(*batch, return_exceptions=True)
            
            # Log progress
            progress = min(i + batch_size, len(tasks))
            self.logger.debug(f"Brute force progress: {progress}/{len(tasks)} ({progress/len(tasks)*100:.1f}%)")
        
        return discovered
    
    async def _certificate_transparency_enumeration(self, domain: str) -> Set[str]:
        """Discover subdomains from certificate transparency logs."""
        discovered = set()
        
        # Multiple CT log sources
        ct_sources = [
            f"https://crt.sh/?q=%.{domain}&output=json",
            f"https://api.certspotter.com/v1/issuances?domain={domain}&include_subdomains=true&expand=dns_names"
        ]
        
        for source in ct_sources:
            try:
                self.logger.debug(f"Querying CT source: {source}")
                response = await self.session.get(source, timeout=15)
                
                if response.status_code == 200:
                    if 'crt.sh' in source:
                        # Parse crt.sh response
                        try:
                            ct_data = response.json()
                            for entry in ct_data:
                                name_value = entry.get('name_value', '')
                                if name_value:
                                    # Parse certificate subject alternative names
                                    names = name_value.replace('\n', ' ').split()
                                    for name in names:
                                        name = name.strip()
                                        if name.endswith(f".{domain}") and '*' not in name:
                                            discovered.add(name)
                        except json.JSONDecodeError:
                            continue
                    
                    elif 'certspotter' in source:
                        # Parse certspotter response
                        try:
                            ct_data = response.json()
                            for entry in ct_data:
                                dns_names = entry.get('dns_names', [])
                                for name in dns_names:
                                    if name.endswith(f".{domain}") and '*' not in name:
                                        discovered.add(name)
                        except json.JSONDecodeError:
                            continue
            
            except Exception as e:
                self.logger.debug(f"Error querying CT source {source}: {e}")
                continue
        
        return discovered
    
    async def _dns_based_enumeration(self, domain: str) -> Set[str]:
        """DNS-based subdomain enumeration techniques."""
        discovered = set()
        
        try:
            # Zone transfer attempt (rarely successful but worth trying)
            zone_transfer_results = await self._attempt_zone_transfer(domain)
            discovered.update(zone_transfer_results)
            
            # Reverse DNS enumeration
            reverse_dns_results = await self._reverse_dns_enumeration(domain)
            discovered.update(reverse_dns_results)
            
            # DNS cache snooping
            cache_snoop_results = await self._dns_cache_snooping(domain)
            discovered.update(cache_snoop_results)
            
        except Exception as e:
            self.logger.debug(f"Error in DNS-based enumeration: {e}")
        
        return discovered
    
    async def _passive_sources_enumeration(self, domain: str) -> Set[str]:
        """Query passive reconnaissance sources."""
        discovered = set()
        
        # VirusTotal API (public API, limited requests)
        try:
            vt_url = f"https://www.virustotal.com/vtapi/v2/domain/report"
            vt_params = {"apikey": "public", "domain": domain}
            
            # Note: This would require a real API key in production
            # For now, we'll use a mock response or skip
            self.logger.debug("VirusTotal API requires authentication - skipping")
        except Exception as e:
            self.logger.debug(f"Error querying VirusTotal: {e}")
        
        # SecurityTrails API (requires API key)
        try:
            # Mock implementation - would require real API key
            self.logger.debug("SecurityTrails API requires authentication - skipping")
        except Exception as e:
            self.logger.debug(f"Error querying SecurityTrails: {e}")
        
        # HackerTarget API (free tier available)
        try:
            ht_url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
            response = await self.session.get(ht_url, timeout=10)
            
            if response.status_code == 200:
                lines = response.text.strip().split('\n')
                for line in lines:
                    if ',' in line:
                        subdomain = line.split(',')[0].strip()
                        if subdomain.endswith(f".{domain}"):
                            discovered.add(subdomain)
        except Exception as e:
            self.logger.debug(f"Error querying HackerTarget: {e}")
        
        return discovered
    
    async def _permutation_enumeration(self, domain: str) -> Set[str]:
        """Generate subdomain permutations based on existing subdomains."""
        discovered = set()
        
        # Common permutation patterns
        prefixes = ['dev-', 'test-', 'staging-', 'beta-', 'alpha-', 'pre-', 'post-']
        suffixes = ['-dev', '-test', '-staging', '-beta', '-alpha', '-new', '-old']
        separators = ['-', '_', '.']
        
        # Start with known subdomains
        base_subdomains = ['www', 'api', 'app', 'admin', 'mail']
        
        for base in base_subdomains:
            # Add prefixes
            for prefix in prefixes:
                candidate = f"{prefix}{base}.{domain}"
                if await self._dns_resolve(candidate):
                    discovered.add(candidate)
            
            # Add suffixes
            for suffix in suffixes:
                candidate = f"{base}{suffix}.{domain}"
                if await self._dns_resolve(candidate):
                    discovered.add(candidate)
            
            # Add numbered variations
            for i in range(1, 6):
                candidate = f"{base}{i}.{domain}"
                if await self._dns_resolve(candidate):
                    discovered.add(candidate)
        
        return discovered
    
    async def _attempt_zone_transfer(self, domain: str) -> Set[str]:
        """Attempt DNS zone transfer."""
        discovered = set()
        
        try:
            # This would require dnspython library
            # For now, return empty set
            pass
        except Exception as e:
            self.logger.debug(f"Zone transfer attempt failed: {e}")
        
        return discovered
    
    async def _reverse_dns_enumeration(self, domain: str) -> Set[str]:
        """Reverse DNS enumeration."""
        discovered = set()
        
        try:
            # Get IP range for domain and perform reverse lookups
            # This is a simplified implementation
            pass
        except Exception as e:
            self.logger.debug(f"Reverse DNS enumeration failed: {e}")
        
        return discovered
    
    async def _dns_cache_snooping(self, domain: str) -> Set[str]:
        """DNS cache snooping technique."""
        discovered = set()
        
        try:
            # DNS cache snooping implementation
            # This would require specialized DNS queries
            pass
        except Exception as e:
            self.logger.debug(f"DNS cache snooping failed: {e}")
        
        return discovered
    
    async def _dns_resolve(self, hostname: str) -> bool:
        """Check if hostname resolves via DNS."""
        try:
            # Use asyncio DNS resolution
            loop = asyncio.get_event_loop()
            result = await loop.getaddrinfo(hostname, None)
            return bool(result)
        except Exception:
            return False
    
    async def _verify_alive_subdomains(self, subdomains: List[str]) -> Set[str]:
        """Verify which subdomains are alive via HTTP requests."""
        alive = set()
        
        semaphore = asyncio.Semaphore(20)  # Limit concurrent requests
        
        async def check_alive(subdomain: str):
            async with semaphore:
                protocols = ['https', 'http']
                
                for protocol in protocols:
                    try:
                        url = f"{protocol}://{subdomain}"
                        response = await self.session.head(url, timeout=5, follow_redirects=True)
                        
                        # Consider various status codes as "alive"
                        if response.status_code in [200, 301, 302, 403, 401, 404, 500, 502, 503]:
                            alive.add(subdomain)
                            self.logger.debug(f"Subdomain alive: {subdomain} ({response.status_code})")
                            break  # Found alive, no need to try other protocol
                    
                    except Exception:
                        continue  # Try next protocol or move to next subdomain
        
        # Process in batches to avoid overwhelming the target
        batch_size = 50
        for i in range(0, len(subdomains), batch_size):
            batch = subdomains[i:i+batch_size]
            tasks = [check_alive(subdomain) for subdomain in batch]
            await asyncio.gather(*tasks, return_exceptions=True)
            
            # Brief pause between batches
            await asyncio.sleep(0.5)
        
        return alive
    
    def save_results(self, results: Dict, output_file: str = None) -> str:
        """Save enumeration results to file."""
        if not output_file:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            domain = results['domain'].replace('.', '_')
            output_file = f"reports/subdomains_{domain}_{timestamp}.json"
        
        output_path = Path(output_file)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        with open(output_path, 'w') as f:
            json.dump(results, f, indent=2)
        
        self.logger.info(f"Subdomain enumeration results saved to {output_path}")
        return str(output_path) 