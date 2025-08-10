"""
R.A.I.D Scan Engine
Main orchestrator for security scanning operations
"""

import asyncio
import logging
import time
import urllib.parse
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

import httpx
from bs4 import BeautifulSoup

from .plugin_loader import PluginLoader
from .model import Finding
from .result_manager import ResultManager
from .payload_manager import PayloadManager
from .http_client import HTTPClient
from ..utils.logger import setup_logger
from ..utils.crawler import EnhancedDiscovery
from ..utils.subdomain_scanner import SubdomainEnumerator


class ScanContext:
    """Context object passed to plugins during execution."""
    
    def __init__(self, 
                 target: str,
                 mode: str,
                 session: HTTPClient,
                 payload_manager: PayloadManager,
                 logger: logging.Logger,
                 progress_manager=None):
        self.target = target
        self.mode = mode
        self.session = session
        self.payload_manager = payload_manager
        self.logger = logger
        self.progress_manager = progress_manager
        self.endpoints: Set[str] = set()
        self.parameters: Dict[str, Set[str]] = {}
        self.cookies: Dict[str, str] = {}
        self.forms: List[Dict[str, Any]] = []
        self.technologies: Set[str] = set()
        self.metadata: Dict[str, Any] = {}


class ScanEngine:
    """Main scanning engine that orchestrates the entire security assessment."""
    
    def __init__(self,
                 mode: str = "safe",
                 concurrency: int = 5,
                 timeout: int = 30,
                 user_agent: str = "R.A.I.D-Scanner/1.0",
                 proxy: Optional[str] = None,
                 force: bool = False,
                 output_dir: str = "./reports",
                 logger: Optional[logging.Logger] = None,
                 progress_manager=None,
                 max_param_checks: int = 0):
        
        self.mode = mode
        self.concurrency = concurrency
        self.timeout = timeout
        self.user_agent = user_agent
        self.proxy = proxy
        self.force = force
        self.output_dir = Path(output_dir)
        self.logger = logger or setup_logger()
        
        # Initialize components
        self.plugin_loader = PluginLoader()
        self.result_manager = ResultManager(output_dir)
        self.payload_manager = PayloadManager()
        self.progress_manager = progress_manager
        self.max_param_checks = max(0, int(max_param_checks))
        
        # Enhanced discovery components (initialized later with session)
        self.enhanced_discovery = None
        self.subdomain_enumerator = None
        self.enable_subdomain_discovery = True
        self.crawl_depth = 3
        
        # Statistics
        self.start_time: Optional[datetime] = None
        self.end_time: Optional[datetime] = None
        self.total_requests = 0
        self.total_findings = 0
        
        # Rate limiting
        self.semaphore = asyncio.Semaphore(concurrency)
        self.request_delay = 0.1  # Minimum delay between requests
        
    async def initialize(self) -> bool:
        """Initialize the scan engine and load plugins."""
        try:
            self.logger.info("Initializing R.A.I.D Scanner Engine")
            
            # Load plugins
            loaded_count = self.plugin_loader.load_all_plugins()
            if loaded_count == 0:
                self.logger.warning("No plugins loaded - scan will have limited functionality")
            
            # Load payload templates
            await self.payload_manager.load_templates()
            
            # Ensure output directory exists
            self.output_dir.mkdir(parents=True, exist_ok=True)
            
            self.logger.info(f"Engine initialized with {loaded_count} plugins in {self.mode} mode")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to initialize engine: {e}")
            return False
    
    def normalize_target(self, target: str) -> str:
        """Normalize target URL format."""
        if not target.startswith(('http://', 'https://')):
            target = f"https://{target}"
        
        # Parse and reconstruct to ensure proper formatting
        parsed = urllib.parse.urlparse(target)
        
        # Remove default ports
        port = parsed.port
        if (port == 80 and parsed.scheme == 'http') or (port == 443 and parsed.scheme == 'https'):
            netloc = parsed.hostname
        else:
            netloc = parsed.netloc
        
        normalized = urllib.parse.urlunparse((
            parsed.scheme,
            netloc,
            parsed.path.rstrip('/') or '/',
            parsed.params,
            parsed.query,
            parsed.fragment
        ))
        
        return normalized
    
    async def discover_endpoints(self, 
                               target: str, 
                               session: HTTPClient,
                               max_depth: int = 2) -> Set[str]:
        """Discover endpoints through crawling and common paths."""
        endpoints = {target}
        crawled = set()
        to_crawl = {target}
        depth = 0
        
        # Common paths to check
        common_paths = [
            '/robots.txt', '/sitemap.xml', '/admin', '/login', '/api',
            '/wp-admin', '/phpmyadmin', '/admin.php', '/login.php',
            '/api/v1', '/api/v2', '/rest', '/graphql'
        ]
        
        # Add common paths
        base_url = urllib.parse.urlparse(target)
        base = f"{base_url.scheme}://{base_url.netloc}"
        
        for path in common_paths:
            endpoints.add(f"{base}{path}")
        
        # Simple crawling
        while to_crawl and depth < max_depth:
            current_level = to_crawl.copy()
            to_crawl.clear()
            depth += 1
            
            for url in current_level:
                if url in crawled:
                    continue
                
                try:
                    async with self.semaphore:
                        response = await session.get(url)
                        crawled.add(url)
                        
                        if response.status_code == 200 and 'text/html' in response.headers.get('content-type', ''):
                            # Parse HTML for links
                            soup = BeautifulSoup(response.text, 'html.parser')
                            
                            for link in soup.find_all(['a', 'form'], href=True, action=True):
                                href = link.get('href') or link.get('action')
                                if href:
                                    absolute_url = urllib.parse.urljoin(url, href)
                                    parsed_abs = urllib.parse.urlparse(absolute_url)
                                    parsed_target = urllib.parse.urlparse(target)
                                    
                                    # Only include same-origin URLs
                                    if parsed_abs.netloc == parsed_target.netloc:
                                        endpoints.add(absolute_url)
                                        if depth < max_depth:
                                            to_crawl.add(absolute_url)
                
                except Exception as e:
                    self.logger.debug(f"Error crawling {url}: {e}")
                    continue
                
                # Rate limiting
                await asyncio.sleep(self.request_delay)
        
        self.logger.info(f"Discovered {len(endpoints)} endpoints for {target}")
        return endpoints
    
    async def collect_parameters(self, 
                               endpoints: Set[str], 
                               session: HTTPClient) -> Dict[str, Set[str]]:
        """Collect parameters from endpoints (query params, form fields)."""
        parameters = {}
        
        for endpoint in endpoints:
            params = set()
            
            # Extract query parameters
            parsed = urllib.parse.urlparse(endpoint)
            if parsed.query:
                query_params = urllib.parse.parse_qs(parsed.query)
                params.update(query_params.keys())
            
            # Try to get form parameters
            try:
                async with self.semaphore:
                    response = await session.get(endpoint)
                    
                    if response.status_code == 200 and 'text/html' in response.headers.get('content-type', ''):
                        soup = BeautifulSoup(response.text, 'html.parser')
                        
                        # Find form inputs
                        for form in soup.find_all('form'):
                            for input_elem in form.find_all(['input', 'select', 'textarea']):
                                name = input_elem.get('name')
                                if name:
                                    params.add(name)
                
            except Exception as e:
                self.logger.debug(f"Error collecting parameters from {endpoint}: {e}")
            
            if params:
                parameters[endpoint] = params
        
        total_params = sum(len(p) for p in parameters.values())
        self.logger.info(f"Collected {total_params} parameters across {len(parameters)} endpoints")
        return parameters
    
    async def create_scan_context(self, target: str) -> ScanContext:
        """Create a scan context with comprehensive target discovery."""
        session = HTTPClient(
            timeout=self.timeout,
            user_agent=self.user_agent,
            proxies=self.proxy,
            force=self.force,
        )
        
        # Initialize enhanced discovery components
        if not self.enhanced_discovery:
            # Get the httpx session from HTTPClient wrapper
            httpx_session = await session.get_underlying_httpx()
            self.enhanced_discovery = EnhancedDiscovery(httpx_session, self.logger)
        if not self.subdomain_enumerator:
            # Get the httpx session from HTTPClient wrapper
            httpx_session = await session.get_underlying_httpx()
            self.subdomain_enumerator = SubdomainEnumerator(httpx_session, self.logger)
        
        context = ScanContext(
            target=target,
            mode=self.mode,
            session=session,
            payload_manager=self.payload_manager,
            logger=self.logger,
            progress_manager=self.progress_manager
        )
        # propagate limits to plugins via context
        setattr(context, "max_param_checks", self.max_param_checks)
        
        # Enhanced discovery process
        self.logger.info("Starting comprehensive target discovery...")
        
        try:
            # Perform comprehensive discovery
            discovery_results = await self.enhanced_discovery.comprehensive_discovery(
                target, 
                include_subdomains=self.enable_subdomain_discovery,
                max_depth=self.crawl_depth
            )
            
            # Extract endpoints and parameters from discovery results
            endpoints_with_params = discovery_results.get("endpoints_with_parameters", {})
            context.endpoints = set(endpoints_with_params.keys())
            
            # Convert parameter format for context
            for endpoint, params in endpoints_with_params.items():
                context.parameters[endpoint] = set(params) if isinstance(params, list) else set()
            
            # Add subdomain endpoints if discovered
            subdomain_endpoints = discovery_results.get("subdomain_endpoints", {})
            for subdomain, endpoints in subdomain_endpoints.items():
                for endpoint, params in endpoints.items():
                    context.endpoints.add(endpoint)
                    context.parameters[endpoint] = set(params) if isinstance(params, list) else set()
            
            # Save discovery results
            discovery_file = self.enhanced_discovery.save_discovery_results(
                discovery_results, 
                str(self.output_dir / "discovery_results.json")
            )
            self.logger.info(f"Discovery results saved to {discovery_file}")
            
            # Store discovery metadata in context
            context.metadata["discovery"] = {
                "total_endpoints": len(context.endpoints),
                "total_parameters": sum(len(params) for params in context.parameters.values()),
                "subdomains_found": len(discovery_results.get("subdomains", [])),
                "discovery_method": "enhanced"
            }
            
            self.logger.info(
                f"Enhanced discovery completed: {len(context.endpoints)} endpoints, "
                f"{sum(len(params) for params in context.parameters.values())} parameters, "
                f"{len(discovery_results.get('subdomains', []))} subdomains"
            )
            
        except Exception as e:
            self.logger.warning(f"Enhanced discovery failed: {e}, falling back to basic discovery")
            
            # Fallback to legacy discovery methods
            context.endpoints = await self.discover_endpoints(target, session)
            context.parameters = await self.collect_parameters(context.endpoints, session)
            
            context.metadata["discovery"] = {
                "total_endpoints": len(context.endpoints),
                "total_parameters": sum(len(params) for params in context.parameters.values()),
                "subdomains_found": 0,
                "discovery_method": "basic"
            }
        
        return context
    
    async def run_plugin(self, 
                        plugin_name: str, 
                        plugin_module: Any, 
                        context: ScanContext) -> List[Finding]:
        """Run a single plugin against the target."""
        findings = []
        
        try:
            if self.progress_manager:
                self.progress_manager.log_message("INFO", f"Running check: {plugin_name}")
            else:
                self.logger.debug(f"Running plugin: {plugin_name}")
            
            # Run the plugin
            async with self.semaphore:
                plugin_findings = await plugin_module.run(
                    context.target, 
                    context.session, 
                    context
                )
            
            # Validate findings
            for finding in plugin_findings:
                if self.plugin_loader.validate_finding(finding):
                    # Calculate confidence score based on indicators
                    finding.confidence = self.calculate_confidence(finding)
                    findings.append(finding)
                    
                    # Log vulnerability through progress manager
                    if self.progress_manager:
                        self.progress_manager.log_vulnerability(
                            plugin_name,
                            finding.severity,
                            finding.description,
                            finding.endpoint
                        )
                else:
                    self.logger.warning(f"Invalid finding from plugin {plugin_name}: {finding}")
            
            if self.progress_manager:
                self.progress_manager.update_progress(plugin_name, context.target, "", len(findings))
            else:
                self.logger.debug(f"Plugin {plugin_name} found {len(findings)} valid findings")
            
        except Exception as e:
            self.logger.error(f"Error running plugin {plugin_name}: {e}")
            # Create an error finding
            error_finding = Finding(
                id=f"{plugin_name}_error",
                name=f"Plugin Error: {plugin_name}",
                plugin=plugin_name,
                target=context.target,
                endpoint=context.target,
                parameter=None,
                evidence={"error": str(e)},
                indicators=["plugin_error"],
                severity="info",
                confidence=0.0,
                timestamp=datetime.now().isoformat(),
                proof_mode=context.mode,
                description=f"Plugin {plugin_name} encountered an error during execution"
            )
            findings.append(error_finding)
        
        return findings
    
    def calculate_confidence(self, finding: Finding) -> int:
        """Calculate confidence score based on indicators and evidence."""
        base_confidence = 50
        
        # Indicator-based scoring
        indicator_weights = {
            'status_changed': 20,
            'error_signature': 25,
            'body_diff': 15,
            'timing_anomaly': 30,
            'header_change': 10,
            'response_pattern': 20,
            'known_signature': 35
        }
        
        confidence_boost = 0
        for indicator in finding.indicators:
            if indicator in indicator_weights:
                confidence_boost += indicator_weights[indicator]
        
        # Evidence-based scoring
        evidence = finding.evidence
        if 'similarity_score' in evidence:
            # Lower similarity = higher confidence for injection tests
            similarity = evidence['similarity_score']
            if similarity < 0.7:
                confidence_boost += 20
            elif similarity < 0.8:
                confidence_boost += 10
        
        if 'timing_delta' in evidence:
            # Significant timing differences increase confidence
            delta = evidence['timing_delta']
            if delta > 5.0:  # 5+ second delay
                confidence_boost += 25
            elif delta > 2.0:  # 2+ second delay
                confidence_boost += 15
        
        # Multiple indicators increase confidence
        if len(finding.indicators) > 2:
            confidence_boost += 10
        elif len(finding.indicators) > 1:
            confidence_boost += 5
        
        final_confidence = min(100, base_confidence + confidence_boost)
        return max(0, final_confidence)
    
    async def run_scan(self, 
                      targets: List[str], 
                      plugin_list: Optional[List[str]] = None,
                      log_payloads: bool = False) -> Dict[str, Any]:
        """Run the complete scan against all targets."""
        
        if not await self.initialize():
            raise RuntimeError("Failed to initialize scan engine")
        
        self.start_time = datetime.now()
        all_findings = []
        scan_results = {}
        
        # Get plugins to run (do this before starting progress to set accurate totals)
        plugins = self.plugin_loader.filter_plugins(
            plugin_list=plugin_list,
            mode=self.mode
        )

        # Initialize progress tracking with accurate plugin count
        if self.progress_manager:
            initial_checks = len(targets) * max(1, len(plugins))
            self.progress_manager.start_scan(initial_checks, log_payloads, self.mode, targets[0] if targets else "")
        
        try:
            if not plugins:
                self.logger.warning("No compatible plugins found for scan")
                return {"findings": [], "stats": {}}
            
            self.logger.info(f"Running scan with {len(plugins)} plugins against {len(targets)} targets")
            
            # Process each target
            for target_url in targets:
                normalized_target = self.normalize_target(target_url)
                if self.progress_manager:
                    self.progress_manager.log_message("INFO", f"Target: {normalized_target}")
                else:
                    self.logger.info(f"Scanning target: {normalized_target}")
                
                # Create scan context
                context = await self.create_scan_context(normalized_target)
                
                # Apply parameter check limits for safe mode or when explicitly set
                if self.max_param_checks > 0:
                    limited_parameters: Dict[str, Set[str]] = {}
                    # Flatten endpoints by priority: keep discovery order for now
                    total_assigned = 0
                    for endpoint, params in context.parameters.items():
                        if total_assigned >= self.max_param_checks:
                            break
                        remaining = self.max_param_checks - total_assigned
                        selected = set(list(params)[:max(0, remaining)])
                        if selected:
                            limited_parameters[endpoint] = selected
                            total_assigned += len(selected)
                    if limited_parameters:
                        context.parameters = limited_parameters
                
                # Log discovery information
                if self.progress_manager:
                    self.progress_manager.log_discovery_info(
                        len(context.endpoints),
                        sum(len(p) for p in context.parameters.values())
                    )
                
                # Run plugins
                target_findings = []
                plugin_tasks = []
                
                # Track plugin execution with progress
                plugin_count = 0
                plugin_total = len(plugins)
                for plugin_name, plugin_module in plugins.items():
                    plugin_count += 1
                    if self.progress_manager:
                        self.progress_manager.log_plugin_start(plugin_name, plugin_count, plugin_total)
                    
                    # For parameterized plugins, estimate additional progress units based on discovered parameters
                    if self.progress_manager and plugin_name in ("xss_heuristic", "sqli_heuristic"):
                        estimated_checks = max(1, sum(len(p) for p in context.parameters.values()))
                        # Each parameter will have multiple mutations; rough factor 3 for UI feel
                        self.progress_manager.add_checks(estimated_checks * 3)

                    task = self.run_plugin(plugin_name, plugin_module, context)
                    plugin_tasks.append(task)
                
                # Execute plugins concurrently
                plugin_results = await asyncio.gather(*plugin_tasks, return_exceptions=True)
                
                # Collect findings
                for result in plugin_results:
                    if isinstance(result, Exception):
                        self.logger.error(f"Plugin execution error: {result}")
                        continue
                    
                    if isinstance(result, list):
                        target_findings.extend(result)
                
                # Filter findings based on confidence threshold
                confidence_threshold = 30 if self.mode == "safe" else 20
                filtered_findings = [
                    f for f in target_findings 
                    if f.confidence >= confidence_threshold
                ]
                
                all_findings.extend(filtered_findings)
                scan_results[normalized_target] = {
                    "findings": filtered_findings,
                    "endpoints_discovered": len(context.endpoints),
                    "parameters_found": sum(len(p) for p in context.parameters.values())
                }
                
                self.logger.info(f"Target {normalized_target}: {len(filtered_findings)} findings")
                
                # Close session
                await context.session.close()
        
        finally:
            self.end_time = datetime.now()
        
        # Store results
        await self.result_manager.save_findings(all_findings)
        
        # Generate reports
        await self.result_manager.generate_reports(all_findings, self.get_scan_stats())
        
        self.total_findings = len(all_findings)
        
        # Complete progress tracking
        if self.progress_manager:
            self.progress_manager.complete_scan()
        else:
            self.logger.info(f"Scan completed: {self.total_findings} total findings")
        
        return {
            "findings": all_findings,
            "results": scan_results,
            "stats": self.get_scan_stats()
        }
    
    def get_scan_stats(self) -> Dict[str, Any]:
        """Get scan statistics."""
        duration = None
        if self.start_time and self.end_time:
            duration = (self.end_time - self.start_time).total_seconds()
        
        return {
            "start_time": self.start_time.isoformat() if self.start_time else None,
            "end_time": self.end_time.isoformat() if self.end_time else None,
            "duration_seconds": duration,
            "mode": self.mode,
            "total_findings": self.total_findings,
            "total_requests": self.total_requests,
            "concurrency": self.concurrency,
            "plugin_stats": self.plugin_loader.get_plugin_stats()
        } 