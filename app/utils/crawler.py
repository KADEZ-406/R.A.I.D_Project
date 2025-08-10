"""
Advanced Crawler for Parameter and Endpoint Discovery
Comprehensive crawling to maximize bug detection coverage
"""

import asyncio
import re
import urllib.parse
from datetime import datetime
from typing import Dict, List, Set, Tuple, Optional
from pathlib import Path
import json
import logging

import httpx
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, unquote


class ParameterCrawler:
    """Advanced parameter discovery crawler."""
    
    def __init__(self, session: httpx.AsyncClient, logger: logging.Logger):
        self.session = session
        self.logger = logger
        self.discovered_params = {}
        self.visited_urls = set()
        self.max_depth = 3
        self.max_urls_per_depth = 50
        
        # Parameter discovery patterns
        self.param_patterns = [
            r'name=["\']([^"\']+)["\']',  # form inputs
            r'<input[^>]*name=["\']([^"\']+)["\']',  # input fields
            r'<select[^>]*name=["\']([^"\']+)["\']',  # select fields
            r'<textarea[^>]*name=["\']([^"\']+)["\']',  # textarea fields
            r'\?([^=&\s]+)=',  # URL parameters
            r'&([^=&\s]+)=',  # URL parameters
            r'data-param=["\']([^"\']+)["\']',  # data attributes
            r'param["\']?\s*:\s*["\']([^"\']+)["\']',  # JavaScript objects
            r'\.get\(["\']([^"\']+)["\']',  # request.get calls
            r'\.post\(["\']([^"\']+)["\']',  # request.post calls
            r'getElementById\(["\']([^"\']+)["\']',  # DOM element IDs
            r'querySelector\(["\'][^"\']*#([^"\']+)["\']',  # CSS selectors
        ]
        
        # Common parameter names to look for
        self.common_params = [
            'id', 'user', 'username', 'email', 'password', 'token', 'session',
            'search', 'q', 'query', 'keyword', 'term', 'filter', 'sort',
            'page', 'limit', 'offset', 'start', 'end', 'count', 'size',
            'file', 'path', 'url', 'redirect', 'callback', 'return',
            'action', 'method', 'type', 'format', 'lang', 'locale',
            'debug', 'test', 'admin', 'mode', 'view', 'tab', 'section',
            'category', 'tag', 'status', 'state', 'role', 'permission'
        ]
    
    async def crawl_parameters(self, target_url: str, max_depth: int = 3) -> Dict[str, List[str]]:
        """
        Comprehensive parameter discovery crawling.
        
        Returns:
            Dict mapping URLs to discovered parameters
        """
        self.max_depth = max_depth
        self.discovered_params = {}
        self.visited_urls = set()
        
        self.logger.info(f"Starting parameter crawling for {target_url}")
        
        try:
            await self._crawl_recursive(target_url, 0)
            
            # Additional discovery methods
            await self._discover_from_robots_txt(target_url)
            await self._discover_from_sitemap(target_url)
            await self._discover_from_common_endpoints(target_url)
            await self._discover_from_js_files(target_url)
            
            self.logger.info(f"Parameter crawling completed. Found {len(self.discovered_params)} URLs with parameters")
            
        except Exception as e:
            self.logger.error(f"Error during parameter crawling: {e}")
        
        return self.discovered_params
    
    async def _crawl_recursive(self, url: str, depth: int):
        """Recursive crawling with depth limit."""
        if depth >= self.max_depth or url in self.visited_urls:
            return
        
        if len(self.visited_urls) >= self.max_urls_per_depth * (depth + 1):
            return
        
        self.visited_urls.add(url)
        
        try:
            self.logger.debug(f"Crawling depth {depth}: {url}")
            
            response = await self.session.get(url, follow_redirects=True)
            if response.status_code != 200:
                return
            
            content_type = response.headers.get('content-type', '').lower()
            if 'text/html' not in content_type:
                return
            
            html_content = response.text
            
            # Discover parameters from current page
            params = await self._extract_parameters(url, html_content)
            if params:
                self.discovered_params[url] = params
            
            # Find links for next depth level
            if depth < self.max_depth - 1:
                links = await self._extract_links(url, html_content)
                
                # Limit links per depth to avoid infinite crawling
                limited_links = list(links)[:self.max_urls_per_depth]
                
                # Crawl discovered links
                tasks = []
                for link in limited_links:
                    if link not in self.visited_urls:
                        tasks.append(self._crawl_recursive(link, depth + 1))
                
                if tasks:
                    await asyncio.gather(*tasks, return_exceptions=True)
        
        except Exception as e:
            self.logger.debug(f"Error crawling {url}: {e}")
    
    async def _extract_parameters(self, url: str, html_content: str) -> List[str]:
        """Extract parameters from HTML content and URL."""
        params = set()
        
        try:
            # Extract from URL parameters
            parsed_url = urlparse(url)
            if parsed_url.query:
                query_params = parse_qs(parsed_url.query)
                params.update(query_params.keys())
            
            # Extract from HTML forms
            soup = BeautifulSoup(html_content, 'html.parser')
            
            # Form inputs
            for input_tag in soup.find_all('input'):
                name_attr = input_tag.get('name')
                if name_attr:
                    params.add(name_attr)
                
                # Also check for data attributes
                for attr in input_tag.attrs:
                    if attr.startswith('data-') and attr != 'data-param':
                        param_name = attr.replace('data-', '')
                        params.add(param_name)
            
            # Select fields
            for select_tag in soup.find_all('select'):
                name_attr = select_tag.get('name')
                if name_attr:
                    params.add(name_attr)
            
            # Textarea fields
            for textarea_tag in soup.find_all('textarea'):
                name_attr = textarea_tag.get('name')
                if name_attr:
                    params.add(name_attr)
            
            # Hidden fields
            for hidden_tag in soup.find_all('input', type='hidden'):
                name_attr = hidden_tag.get('name')
                if name_attr:
                    params.add(name_attr)
            
            # Form action parameters
            for form_tag in soup.find_all('form'):
                action = form_tag.get('action')
                if action:
                    action_url = urljoin(url, action)
                    action_parsed = urlparse(action_url)
                    if action_parsed.query:
                        action_params = parse_qs(action_parsed.query)
                        params.update(action_params.keys())
            
            # JavaScript parameters
            js_params = self._extract_js_parameters(html_content)
            params.update(js_params)
            
            # Common parameter patterns
            for pattern in self.param_patterns:
                matches = re.findall(pattern, html_content, re.IGNORECASE)
                params.update(matches)
            
            # Additional common parameters
            for common_param in self.common_params:
                if common_param.lower() in html_content.lower():
                    params.add(common_param)
            
            # Remove empty or invalid parameters
            params = {p for p in params if p and len(p.strip()) > 0 and not p.startswith('_')}
            
            self.logger.debug(f"Extracted {len(params)} parameters from {url}: {list(params)[:10]}")
            
        except Exception as e:
            self.logger.error(f"Error extracting parameters from {url}: {e}")
        
        return list(params)
    
    def _extract_js_parameters(self, js_content: str) -> Set[str]:
        """Extract parameters from JavaScript code."""
        params = set()
        
        try:
            # AJAX request parameters
            ajax_patterns = [
                r'\.get\(["\']([^"\']+)["\']',  # .get('param')
                r'\.post\(["\']([^"\']+)["\']',  # .post('param')
                r'\.ajax\([^)]*data\s*:\s*\{([^}]+)\}',  # .ajax({data: {param: value}})
                r'fetch\([^)]*body\s*:\s*JSON\.stringify\(([^)]+)\)',  # fetch body
                r'XMLHttpRequest[^}]*send\(([^)]+)\)',  # XHR send
                r'FormData\(\)\.append\(["\']([^"\']+)["\']',  # FormData.append
                r'new\s+URLSearchParams\(([^)]+)\)',  # URLSearchParams
                r'\.serialize\(\)',  # jQuery serialize
                r'\.serializeArray\(\)',  # jQuery serializeArray
            ]
            
            for pattern in ajax_patterns:
                matches = re.findall(pattern, js_content, re.IGNORECASE | re.DOTALL)
                for match in matches:
                    # Extract parameter names from the matched content
                    if ':' in match:
                        # Handle object notation {param: value}
                        param_matches = re.findall(r'["\']?([a-zA-Z0-9_\-]+)["\']?\s*:', match)
                        params.update(param_matches)
                    else:
                        # Handle simple parameter names
                        params.add(match.strip())
            
            # Form submission parameters
            form_patterns = [
                r'form\[["\']([^"\']+)["\']\]',  # form['param']
                r'form\.([a-zA-Z0-9_\-]+)',  # form.param
                r'document\.getElementById\(["\']([^"\']+)["\']',  # getElementById
                r'document\.querySelector\(["\']([^"\']+)["\']',  # querySelector
                r'document\.querySelectorAll\(["\']([^"\']+)["\']',  # querySelectorAll
            ]
            
            for pattern in form_patterns:
                matches = re.findall(pattern, js_content, re.IGNORECASE)
                params.update(matches)
            
            # URL parameter manipulation
            url_patterns = [
                r'URLSearchParams\(["\']([^"\']+)["\']',  # URLSearchParams('param=value')
                r'\.get\(["\']([^"\']+)["\']',  # .get('param')
                r'\.set\(["\']([^"\']+)["\']',  # .set('param')
                r'\.append\(["\']([^"\']+)["\']',  # .append('param')
                r'\.delete\(["\']([^"\']+)["\']',  # .delete('param')
            ]
            
            for pattern in url_patterns:
                matches = re.findall(pattern, js_content, re.IGNORECASE)
                params.update(matches)
            
            # Event handler parameters
            event_patterns = [
                r'on\w+\s*=\s*["\']([^"\']+)["\']',  # onclick="function(param)"
                r'addEventListener\(["\']([^"\']+)["\']',  # addEventListener('event')
                r'\.on\w+\s*=\s*function\s*\(([^)]+)\)',  # .onclick = function(param)
            ]
            
            for pattern in event_patterns:
                matches = re.findall(pattern, js_content, re.IGNORECASE)
                for match in matches:
                    # Extract parameter names from function parameters
                    if ',' in match:
                        param_names = [p.strip() for p in match.split(',')]
                        params.update(param_names)
                    else:
                        params.add(match.strip())
            
            # Remove empty and invalid parameters
            params = {p for p in params if p and len(p.strip()) > 0 and 
                     re.match(r'^[a-zA-Z0-9_\-\[\]]+$', p) and 
                     not p.startswith('_') and len(p) <= 50}
            
        except Exception as e:
            self.logger.debug(f"Error extracting JavaScript parameters: {e}")
        
        return params
    
    async def _extract_links(self, base_url: str, html_content: str) -> Set[str]:
        """Extract links from HTML content."""
        links = set()
        
        try:
            soup = BeautifulSoup(html_content, 'html.parser')
            
            # Extract all links
            for link in soup.find_all('a', href=True):
                href = link['href']
                full_url = urljoin(base_url, href)
                
                # Filter same-domain links
                if self._is_same_domain(base_url, full_url):
                    # Remove fragment
                    parsed = urlparse(full_url)
                    clean_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                    if parsed.query:
                        clean_url += f"?{parsed.query}"
                    links.add(clean_url)
            
            # Extract from forms
            for form in soup.find_all('form'):
                action = form.get('action', '')
                if action:
                    full_url = urljoin(base_url, action)
                    if self._is_same_domain(base_url, full_url):
                        links.add(full_url)
        
        except Exception as e:
            self.logger.debug(f"Error extracting links from {base_url}: {e}")
        
        return links
    
    def _is_same_domain(self, base_url: str, target_url: str) -> bool:
        """Check if target URL is in the same domain as base URL."""
        try:
            base_domain = urlparse(base_url).netloc.lower()
            target_domain = urlparse(target_url).netloc.lower()
            return base_domain == target_domain
        except:
            return False
    
    async def _discover_from_robots_txt(self, target_url: str):
        """Discover endpoints from robots.txt."""
        try:
            robots_url = urljoin(target_url, '/robots.txt')
            response = await self.session.get(robots_url)
            
            if response.status_code == 200:
                for line in response.text.split('\n'):
                    line = line.strip()
                    if line.startswith('Disallow:') or line.startswith('Allow:'):
                        path = line.split(':', 1)[1].strip()
                        if path and path != '/':
                            full_url = urljoin(target_url, path)
                            if '?' in full_url:
                                params = await self._extract_parameters(full_url, '')
                                if params:
                                    self.discovered_params[full_url] = params
        
        except Exception as e:
            self.logger.debug(f"Error reading robots.txt: {e}")
    
    async def _discover_from_sitemap(self, target_url: str):
        """Discover endpoints from sitemap.xml."""
        try:
            sitemap_urls = [
                urljoin(target_url, '/sitemap.xml'),
                urljoin(target_url, '/sitemap_index.xml'),
                urljoin(target_url, '/sitemaps.xml')
            ]
            
            for sitemap_url in sitemap_urls:
                try:
                    response = await self.session.get(sitemap_url)
                    if response.status_code == 200:
                        # Parse XML content for URLs
                        url_pattern = r'<loc>(.*?)</loc>'
                        urls = re.findall(url_pattern, response.text)
                        
                        for url in urls[:20]:  # Limit to avoid too many requests
                            if '?' in url:
                                params = await self._extract_parameters(url, '')
                                if params:
                                    self.discovered_params[url] = params
                except:
                    continue
        
        except Exception as e:
            self.logger.debug(f"Error reading sitemap: {e}")
    
    async def _discover_from_common_endpoints(self, target_url: str):
        """Test common endpoints that might have parameters."""
        common_endpoints = [
            '/search', '/api/search', '/login', '/register', '/contact',
            '/feedback', '/support', '/admin', '/dashboard', '/profile',
            '/settings', '/config', '/api/users', '/api/products',
            '/api/orders', '/api/data', '/download', '/upload', '/export'
        ]
        
        for endpoint in common_endpoints:
            try:
                test_url = urljoin(target_url, endpoint)
                response = await self.session.get(test_url)
                
                if response.status_code in [200, 403, 401]:  # Endpoint exists
                    # Test with common parameters
                    for param in self.common_params[:10]:  # Limit to avoid too many requests
                        param_url = f"{test_url}?{param}=test"
                        if param_url not in self.discovered_params:
                            self.discovered_params[param_url] = [param]
            
            except Exception:
                continue
    
    async def _discover_from_js_files(self, target_url: str):
        """Discover parameters from JavaScript files."""
        try:
            # First, get the main page to find JS files
            response = await self.session.get(target_url)
            if response.status_code != 200:
                return
            
            soup = BeautifulSoup(response.text, 'html.parser')
            js_files = []
            
            # Find JavaScript files
            for script in soup.find_all('script', src=True):
                src = script['src']
                full_url = urljoin(target_url, src)
                if self._is_same_domain(target_url, full_url):
                    js_files.append(full_url)
            
            # Analyze JavaScript files (limit to avoid too many requests)
            for js_url in js_files[:5]:
                try:
                    js_response = await self.session.get(js_url)
                    if js_response.status_code == 200:
                        js_params = self._extract_js_parameters(js_response.text)
                        if js_params:
                            # Create endpoint URLs with discovered parameters
                            base_path = urlparse(target_url).path or '/'
                            for param in list(js_params)[:10]:  # Limit parameters
                                param_url = f"{target_url.rstrip('/')}{base_path}?{param}=test"
                                if param_url not in self.discovered_params:
                                    self.discovered_params[param_url] = [param]
                
                except Exception:
                    continue
        
        except Exception as e:
            self.logger.debug(f"Error analyzing JS files: {e}")


class SubdomainDiscovery:
    """Comprehensive subdomain discovery."""
    
    def __init__(self, session: httpx.AsyncClient, logger: logging.Logger):
        self.session = session
        self.logger = logger
        
        # Common subdomain wordlist
        self.subdomain_wordlist = [
            'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 'webdisk',
            'ns2', 'cpanel', 'whm', 'autodiscover', 'autoconfig', 'secure', 'vpn', 'exchange',
            'api', 'app', 'admin', 'blog', 'dev', 'test', 'staging', 'demo', 'beta',
            'mobile', 'm', 'wap', 'portal', 'support', 'help', 'docs', 'forum', 'community',
            'shop', 'store', 'payment', 'pay', 'secure', 'ssl', 'www2', 'web', 'webservice',
            'cdn', 'static', 'media', 'img', 'images', 'js', 'css', 'assets', 'files',
            'download', 'downloads', 'ftp', 'sftp', 'mysql', 'sql', 'database', 'db',
            'search', 'solr', 'elastic', 'redis', 'memcached', 'cache', 'monitor', 'status',
            'stats', 'analytics', 'metrics', 'grafana', 'kibana', 'prometheus', 'alerts',
            'backup', 'backups', 'archive', 'repo', 'git', 'svn', 'ci', 'jenkins', 'build',
            'deploy', 'deployment', 'prod', 'production', 'live', 'public', 'private',
            'internal', 'intranet', 'extranet', 'partner', 'vendor', 'supplier', 'client'
        ]
    
    async def discover_subdomains(self, domain: str, max_subdomains: int = 50) -> List[str]:
        """
        Discover subdomains using multiple techniques.
        
        Args:
            domain: Root domain to discover subdomains for
            max_subdomains: Maximum number of subdomains to discover
            
        Returns:
            List of discovered subdomains
        """
        discovered_subdomains = set()
        
        self.logger.info(f"Starting subdomain discovery for {domain}")
        
        try:
            # Dictionary-based discovery
            dict_subdomains = await self._dictionary_discovery(domain)
            discovered_subdomains.update(dict_subdomains)
            
            # Certificate transparency logs
            ct_subdomains = await self._certificate_transparency_discovery(domain)
            discovered_subdomains.update(ct_subdomains)
            
            # DNS enumeration
            dns_subdomains = await self._dns_enumeration(domain)
            discovered_subdomains.update(dns_subdomains)
            
            # Search engine discovery
            search_subdomains = await self._search_engine_discovery(domain)
            discovered_subdomains.update(search_subdomains)
            
            # Limit results
            result_subdomains = list(discovered_subdomains)[:max_subdomains]
            
            self.logger.info(f"Subdomain discovery completed. Found {len(result_subdomains)} subdomains")
            
            return result_subdomains
        
        except Exception as e:
            self.logger.error(f"Error during subdomain discovery: {e}")
            return []
    
    async def _dictionary_discovery(self, domain: str) -> Set[str]:
        """Dictionary-based subdomain brute force."""
        subdomains = set()
        
        # Build limited tasks without creating un-awaited coroutines
        for subdomain in self.subdomain_wordlist:
            pass  # list consumed below in gather call
        
        # Limit concurrent requests
        semaphore = asyncio.Semaphore(10)
        
        async def limited_check(subdomain):
            async with semaphore:
                return await self._check_subdomain(subdomain)
        
        results = await asyncio.gather(
            *[limited_check(f"{sub}.{domain}") for sub in self.subdomain_wordlist],
            return_exceptions=True
        )
        
        for result in results:
            if result and not isinstance(result, Exception):
                subdomains.add(result)
        
        return subdomains
    
    async def _check_subdomain(self, subdomain: str) -> Optional[str]:
        """Check if subdomain exists and is accessible."""
        try:
            url = f"https://{subdomain}"
            response = await self.session.get(url, timeout=5)
            if response.status_code in [200, 301, 302, 403, 401]:
                return subdomain
        except:
            # Try HTTP if HTTPS fails
            try:
                url = f"http://{subdomain}"
                response = await self.session.get(url, timeout=5)
                if response.status_code in [200, 301, 302, 403, 401]:
                    return subdomain
            except:
                pass
        
        return None
    
    async def _certificate_transparency_discovery(self, domain: str) -> Set[str]:
        """Discover subdomains from certificate transparency logs."""
        subdomains = set()
        
        try:
            # Query crt.sh for certificate transparency logs
            ct_url = f"https://crt.sh/?q=%.{domain}&output=json"
            response = await self.session.get(ct_url, timeout=10)
            
            if response.status_code == 200:
                try:
                    ct_data = response.json()
                    for entry in ct_data[:50]:  # Limit results
                        name_value = entry.get('name_value', '')
                        if name_value:
                            # Parse certificate names
                            names = name_value.replace('\n', ' ').split()
                            for name in names:
                                if domain in name and name.endswith(domain):
                                    subdomains.add(name)
                except json.JSONDecodeError:
                    pass
        
        except Exception as e:
            self.logger.debug(f"Error in certificate transparency discovery: {e}")
        
        return subdomains
    
    async def _dns_enumeration(self, domain: str) -> Set[str]:
        """DNS-based subdomain enumeration."""
        subdomains = set()
        
        try:
            import dns.resolver
            
            # Try zone transfer (usually won't work but worth trying)
            try:
                ns_records = dns.resolver.resolve(domain, 'NS')
                for ns in ns_records:
                    try:
                        zone = dns.zone.from_xfr(dns.query.xfr(str(ns), domain))
                        for name in zone.nodes.keys():
                            subdomain = f"{name}.{domain}"
                            subdomains.add(subdomain)
                    except:
                        continue
            except:
                pass
            
            # DNS brute force with common subdomains
            resolver = dns.resolver.Resolver()
            resolver.timeout = 2
            resolver.lifetime = 2
            
            for subdomain in self.subdomain_wordlist[:20]:  # Limit for DNS queries
                try:
                    full_subdomain = f"{subdomain}.{domain}"
                    dns.resolver.resolve(full_subdomain, 'A')
                    subdomains.add(full_subdomain)
                except:
                    continue
        
        except ImportError:
            self.logger.debug("dnspython not available for DNS enumeration")
        except Exception as e:
            self.logger.debug(f"Error in DNS enumeration: {e}")
        
        return subdomains
    
    async def _search_engine_discovery(self, domain: str) -> Set[str]:
        """Discover subdomains using search engines."""
        subdomains = set()
        
        try:
            # Search for site:domain results (basic approach)
            search_query = f"site:{domain}"
            
            # This is a simplified approach - in production, you might use
            # Google Custom Search API or other search APIs
            
            # For now, we'll just add some common patterns found in search results
            common_search_patterns = [
                f"www.{domain}",
                f"mail.{domain}",
                f"api.{domain}",
                f"admin.{domain}",
                f"app.{domain}"
            ]
            
            for pattern in common_search_patterns:
                if await self._check_subdomain(pattern):
                    subdomains.add(pattern)
        
        except Exception as e:
            self.logger.debug(f"Error in search engine discovery: {e}")
        
        return subdomains


class EnhancedDiscovery:
    """Enhanced discovery combining parameter crawling and subdomain discovery."""
    
    def __init__(self, session: httpx.AsyncClient, logger: logging.Logger):
        self.session = session
        self.logger = logger
        self.param_crawler = ParameterCrawler(session, logger)
        self.subdomain_discovery = SubdomainDiscovery(session, logger)
    
    async def comprehensive_discovery(self, target_url: str, 
                                    include_subdomains: bool = True,
                                    max_depth: int = 3) -> Dict:
        """
        Perform comprehensive discovery including parameters and subdomains.
        
        Returns:
            Dict containing discovered endpoints, parameters, and subdomains
        """
        results = {
            "target_url": target_url,
            "discovered_at": datetime.now().isoformat(),
            "endpoints_with_parameters": {},
            "subdomains": [],
            "total_endpoints": 0,
            "total_parameters": 0,
            "total_subdomains": 0
        }
        
        parsed_url = urlparse(target_url)
        domain = parsed_url.netloc
        
        try:
            # Parameter discovery on main target
            self.logger.info("Starting parameter discovery...")
            endpoints_params = await self.param_crawler.crawl_parameters(target_url, max_depth)
            results["endpoints_with_parameters"] = endpoints_params
            
            # Count total parameters
            total_params = sum(len(params) for params in endpoints_params.values())
            results["total_parameters"] = total_params
            results["total_endpoints"] = len(endpoints_params)
            
            # Subdomain discovery
            if include_subdomains:
                self.logger.info("Starting subdomain discovery...")
                subdomains = await self.subdomain_discovery.discover_subdomains(domain)
                results["subdomains"] = subdomains
                results["total_subdomains"] = len(subdomains)
                
                # Parameter discovery on discovered subdomains
                subdomain_endpoints = {}
                for subdomain in subdomains[:10]:  # Limit to avoid too many requests
                    subdomain_url = f"https://{subdomain}"
                    try:
                        subdomain_params = await self.param_crawler.crawl_parameters(
                            subdomain_url, max_depth=2
                        )
                        if subdomain_params:
                            subdomain_endpoints[subdomain] = subdomain_params
                    except Exception as e:
                        self.logger.debug(f"Error crawling subdomain {subdomain}: {e}")
                
                if subdomain_endpoints:
                    results["subdomain_endpoints"] = subdomain_endpoints
            
            # Summary
            self.logger.info(
                f"Discovery completed: {results['total_endpoints']} endpoints, "
                f"{results['total_parameters']} parameters, "
                f"{results['total_subdomains']} subdomains"
            )
            
        except Exception as e:
            self.logger.error(f"Error during comprehensive discovery: {e}")
        
        return results
    
    def save_discovery_results(self, results: Dict, output_file: str = None):
        """Save discovery results to file."""
        if not output_file:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            domain = urlparse(results["target_url"]).netloc
            output_file = f"reports/discovery_{domain}_{timestamp}.json"
        
        output_path = Path(output_file)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        with open(output_path, 'w') as f:
            json.dump(results, f, indent=2)
        
        self.logger.info(f"Discovery results saved to {output_path}")
        return str(output_path) 