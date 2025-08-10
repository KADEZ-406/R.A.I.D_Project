"""
HTTP Client for R.A.I.D Scanner
Wrapper around httpx with retries, timeouts, and comprehensive response capture
"""

import asyncio
import logging
import time
import urllib.parse
import urllib.robotparser
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Union

import httpx


@dataclass
class Response:
    """Enhanced response object with additional metadata."""
    status_code: int
    headers: Dict[str, str]
    text: str
    content: bytes
    url: str
    elapsed: float
    request_method: str
    request_headers: Dict[str, str] = field(default_factory=dict)
    request_data: Optional[Union[str, bytes]] = None
    redirect_history: List[str] = field(default_factory=list)
    encoding: Optional[str] = None
    
    @property
    def json(self) -> Any:
        """Parse response as JSON."""
        try:
            import json
            return json.loads(self.text)
        except Exception:
            return None
    
    @property
    def is_success(self) -> bool:
        """Check if response indicates success."""
        return 200 <= self.status_code < 300
    
    @property
    def is_redirect(self) -> bool:
        """Check if response is a redirect."""
        return 300 <= self.status_code < 400
    
    @property
    def is_client_error(self) -> bool:
        """Check if response is a client error."""
        return 400 <= self.status_code < 500
    
    @property
    def is_server_error(self) -> bool:
        """Check if response is a server error."""
        return 500 <= self.status_code < 600


class HTTPClient:
    """Async HTTP client with security testing features."""
    
    def __init__(self,
                 timeout: int = 30,
                 user_agent: str = "R.A.I.D-Scanner/1.0",
                 proxy: Optional[str] = None,
                 verify_ssl: bool = True,
                 max_retries: int = 3,
                 retry_delay: float = 1.0,
                 max_redirects: int = 10):
        
        self.timeout = timeout
        self.user_agent = user_agent
        self.proxy = proxy
        self.verify_ssl = verify_ssl
        self.max_retries = max_retries
        self.retry_delay = retry_delay
        self.max_redirects = max_redirects
        self.logger = logging.getLogger(__name__)
        
        # Session configuration
        self.session_config = {
            "timeout": httpx.Timeout(timeout),
            "verify": verify_ssl,
            "follow_redirects": False,  # Handle redirects manually
        }
        
        if proxy:
            self.session_config["proxies"] = proxy
        
        self._session: Optional[httpx.AsyncClient] = None
        self._robots_cache: Dict[str, bool] = {}
        
    async def __aenter__(self):
        """Async context manager entry."""
        await self._ensure_session()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        await self.close()
    
    async def _ensure_session(self):
        """Ensure HTTP session is initialized."""
        if self._session is None:
            headers = {
                "User-Agent": self.user_agent,
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.5",
                "Accept-Encoding": "gzip, deflate",
                "Connection": "keep-alive",
                "Upgrade-Insecure-Requests": "1"
            }
            
            self._session = httpx.AsyncClient(
                headers=headers,
                **self.session_config
            )
        
        return self._session
    
    async def close(self):
        """Close the HTTP session."""
        if self._session:
            await self._session.aclose()
            self._session = None
    
    async def _check_robots_txt(self, url: str, force: bool = False) -> bool:
        """Check if URL is allowed by robots.txt."""
        if force:
            return True
        
        try:
            parsed_url = urllib.parse.urlparse(url)
            base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
            robots_url = f"{base_url}/robots.txt"
            
            # Check cache first
            if robots_url in self._robots_cache:
                return self._robots_cache[robots_url]
            
            # Fetch robots.txt
            try:
                response = await self._make_request("GET", robots_url, ignore_robots=True)
                if response.is_success:
                    # Parse robots.txt
                    rp = urllib.robotparser.RobotFileParser()
                    rp.set_url(robots_url)
                    rp.read()
                    
                    allowed = rp.can_fetch(self.user_agent, url)
                    self._robots_cache[robots_url] = allowed
                    return allowed
                else:
                    # No robots.txt found, assume allowed
                    self._robots_cache[robots_url] = True
                    return True
                    
            except Exception:
                # Error fetching robots.txt, assume allowed
                self._robots_cache[robots_url] = True
                return True
                
        except Exception as e:
            self.logger.debug(f"Error checking robots.txt for {url}: {e}")
            return True
    
    async def _make_request(self,
                          method: str,
                          url: str,
                          headers: Optional[Dict[str, str]] = None,
                          data: Optional[Union[str, bytes, Dict]] = None,
                          params: Optional[Dict[str, str]] = None,
                          ignore_robots: bool = False,
                          follow_redirects: bool = False) -> Response:
        """Make HTTP request with error handling and retries."""
        await self._ensure_session()
        
        start_time = time.time()
        request_headers = headers or {}
        redirect_history = []
        
        # Merge custom headers with defaults
        final_headers = self._session.headers.copy()
        final_headers.update(request_headers)
        
        for attempt in range(self.max_retries + 1):
            try:
                # Make the request
                response = await self._session.request(
                    method=method,
                    url=url,
                    headers=final_headers,
                    params=params,
                    content=data if isinstance(data, (str, bytes)) else None,
                    data=data if isinstance(data, dict) else None
                )
                
                elapsed_time = time.time() - start_time
                
                # Handle redirects manually if needed
                current_url = str(response.url)
                if follow_redirects and response.is_redirect:
                    redirect_count = 0
                    while response.is_redirect and redirect_count < self.max_redirects:
                        redirect_history.append(current_url)
                        location = response.headers.get('location')
                        if not location:
                            break
                        
                        # Resolve relative URLs
                        next_url = urllib.parse.urljoin(current_url, location)
                        
                        # Make redirect request
                        response = await self._session.request(
                            method="GET",  # Redirects are typically GET
                            url=next_url,
                            headers=final_headers
                        )
                        
                        current_url = str(response.url)
                        redirect_count += 1
                        
                        if redirect_count >= self.max_redirects:
                            self.logger.warning(f"Too many redirects for {url}")
                            break
                
                # Create enhanced response object
                enhanced_response = Response(
                    status_code=response.status_code,
                    headers=dict(response.headers),
                    text=response.text,
                    content=response.content,
                    url=current_url,
                    elapsed=elapsed_time,
                    request_method=method,
                    request_headers=dict(final_headers),
                    request_data=data,
                    redirect_history=redirect_history,
                    encoding=response.encoding
                )
                
                return enhanced_response
                
            except httpx.TimeoutException:
                if attempt < self.max_retries:
                    self.logger.debug(f"Timeout for {url}, retrying in {self.retry_delay}s (attempt {attempt + 1})")
                    await asyncio.sleep(self.retry_delay)
                    continue
                else:
                    # Create timeout response
                    elapsed_time = time.time() - start_time
                    return Response(
                        status_code=0,
                        headers={},
                        text="Request timeout",
                        content=b"Request timeout",
                        url=url,
                        elapsed=elapsed_time,
                        request_method=method,
                        request_headers=dict(final_headers),
                        request_data=data
                    )
                    
            except Exception as e:
                if attempt < self.max_retries:
                    self.logger.debug(f"Error for {url}: {e}, retrying in {self.retry_delay}s (attempt {attempt + 1})")
                    await asyncio.sleep(self.retry_delay)
                    continue
                else:
                    # Create error response
                    elapsed_time = time.time() - start_time
                    return Response(
                        status_code=0,
                        headers={},
                        text=f"Request error: {e}",
                        content=f"Request error: {e}".encode(),
                        url=url,
                        elapsed=elapsed_time,
                        request_method=method,
                        request_headers=dict(final_headers),
                        request_data=data
                    )
    
    async def get(self, 
                  url: str, 
                  headers: Optional[Dict[str, str]] = None,
                  params: Optional[Dict[str, str]] = None,
                  follow_redirects: bool = True,
                  respect_robots: bool = True) -> Response:
        """Make GET request."""
        # Check robots.txt
        if respect_robots and not await self._check_robots_txt(url):
            self.logger.warning(f"URL blocked by robots.txt: {url}")
            return Response(
                status_code=403,
                headers={},
                text="Blocked by robots.txt",
                content=b"Blocked by robots.txt",
                url=url,
                elapsed=0.0,
                request_method="GET"
            )
        
        return await self._make_request(
            method="GET",
            url=url,
            headers=headers,
            params=params,
            follow_redirects=follow_redirects
        )
    
    async def post(self,
                   url: str,
                   data: Optional[Union[str, bytes, Dict]] = None,
                   headers: Optional[Dict[str, str]] = None,
                   follow_redirects: bool = False,
                   respect_robots: bool = True) -> Response:
        """Make POST request."""
        # Check robots.txt
        if respect_robots and not await self._check_robots_txt(url):
            self.logger.warning(f"URL blocked by robots.txt: {url}")
            return Response(
                status_code=403,
                headers={},
                text="Blocked by robots.txt",
                content=b"Blocked by robots.txt",
                url=url,
                elapsed=0.0,
                request_method="POST"
            )
        
        return await self._make_request(
            method="POST",
            url=url,
            headers=headers,
            data=data,
            follow_redirects=follow_redirects
        )
    
    async def put(self,
                  url: str,
                  data: Optional[Union[str, bytes, Dict]] = None,
                  headers: Optional[Dict[str, str]] = None,
                  respect_robots: bool = True) -> Response:
        """Make PUT request."""
        if respect_robots and not await self._check_robots_txt(url):
            self.logger.warning(f"URL blocked by robots.txt: {url}")
            return Response(
                status_code=403,
                headers={},
                text="Blocked by robots.txt",
                content=b"Blocked by robots.txt",
                url=url,
                elapsed=0.0,
                request_method="PUT"
            )
        
        return await self._make_request(
            method="PUT",
            url=url,
            headers=headers,
            data=data
        )
    
    async def delete(self,
                     url: str,
                     headers: Optional[Dict[str, str]] = None,
                     respect_robots: bool = True) -> Response:
        """Make DELETE request."""
        if respect_robots and not await self._check_robots_txt(url):
            self.logger.warning(f"URL blocked by robots.txt: {url}")
            return Response(
                status_code=403,
                headers={},
                text="Blocked by robots.txt",
                content=b"Blocked by robots.txt",
                url=url,
                elapsed=0.0,
                request_method="DELETE"
            )
        
        return await self._make_request(
            method="DELETE",
            url=url,
            headers=headers
        )
    
    async def head(self,
                   url: str,
                   headers: Optional[Dict[str, str]] = None,
                   respect_robots: bool = True) -> Response:
        """Make HEAD request."""
        if respect_robots and not await self._check_robots_txt(url):
            self.logger.warning(f"URL blocked by robots.txt: {url}")
            return Response(
                status_code=403,
                headers={},
                text="Blocked by robots.txt",
                content=b"Blocked by robots.txt",
                url=url,
                elapsed=0.0,
                request_method="HEAD"
            )
        
        return await self._make_request(
            method="HEAD",
            url=url,
            headers=headers
        )
    
    async def options(self,
                      url: str,
                      headers: Optional[Dict[str, str]] = None,
                      respect_robots: bool = True) -> Response:
        """Make OPTIONS request."""
        if respect_robots and not await self._check_robots_txt(url):
            self.logger.warning(f"URL blocked by robots.txt: {url}")
            return Response(
                status_code=403,
                headers={},
                text="Blocked by robots.txt",
                content=b"Blocked by robots.txt",
                url=url,
                elapsed=0.0,
                request_method="OPTIONS"
            )
        
        return await self._make_request(
            method="OPTIONS",
            url=url,
            headers=headers
        )
    
    def set_user_agent(self, user_agent: str):
        """Update User-Agent string."""
        self.user_agent = user_agent
        if self._session:
            self._session.headers["User-Agent"] = user_agent
    
    def add_default_header(self, key: str, value: str):
        """Add default header for all requests."""
        if self._session:
            self._session.headers[key] = value
    
    def get_session_stats(self) -> Dict[str, Any]:
        """Get session statistics."""
        return {
            "timeout": self.timeout,
            "user_agent": self.user_agent,
            "proxy": self.proxy,
            "verify_ssl": self.verify_ssl,
            "max_retries": self.max_retries,
            "robots_cache_size": len(self._robots_cache)
        } 