"""
Test suite untuk Enhanced Discovery features
"""

import asyncio
import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from datetime import datetime

from app.utils.crawler import ParameterCrawler, SubdomainDiscovery, EnhancedDiscovery
from app.utils.subdomain_scanner import SubdomainEnumerator


class TestParameterCrawler:
    """Test cases untuk Parameter Crawler."""
    
    @pytest.fixture
    def mock_session(self):
        """Mock HTTP session."""
        session = AsyncMock()
        return session
    
    @pytest.fixture
    def mock_logger(self):
        """Mock logger."""
        return MagicMock()
    
    @pytest.fixture
    def param_crawler(self, mock_session, mock_logger):
        """Parameter crawler instance."""
        return ParameterCrawler(mock_session, mock_logger)
    
    @pytest.mark.asyncio
    async def test_extract_parameters_from_html(self, param_crawler):
        """Test parameter extraction dari HTML content."""
        html_content = """
        <html>
        <form method="post" action="/login">
            <input name="username" type="text">
            <input name="password" type="password">
            <select name="role">
                <option value="user">User</option>
                <option value="admin">Admin</option>
            </select>
            <textarea name="message"></textarea>
        </form>
        <a href="/search?q=test&category=web">Search</a>
        <script>
            var data = {
                search_term: "test",
                filter: "active"
            };
        </script>
        </html>
        """
        
        url = "https://example.com/page"
        params = await param_crawler._extract_parameters(url, html_content)
        
        # Verify form parameters
        assert "username" in params
        assert "password" in params
        assert "role" in params
        assert "message" in params
        
        # Verify URL parameters
        assert "q" in params
        assert "category" in params
        
        # Verify JavaScript parameters
        assert "search_term" in params or "filter" in params
    
    @pytest.mark.asyncio
    async def test_extract_parameters_from_url(self, param_crawler):
        """Test parameter extraction dari URL query string."""
        url = "https://example.com/search?q=test&page=1&sort=date&limit=10"
        html_content = ""
        
        params = await param_crawler._extract_parameters(url, html_content)
        
        assert "q" in params
        assert "page" in params
        assert "sort" in params
        assert "limit" in params
    
    def test_extract_js_parameters(self, param_crawler):
        """Test parameter extraction dari JavaScript content."""
        js_content = """
        var apiData = {
            userId: 123,
            sessionToken: "abc123",
            preferences: {
                theme: "dark",
                language: "en"
            }
        };
        
        $.get('/api/data', {
            id: userId,
            format: 'json'
        });
        
        form.username = "test";
        request.method = "POST";
        """
        
        params = param_crawler._extract_js_parameters(js_content)
        
        assert "userId" in params or "sessionToken" in params
        assert "id" in params or "format" in params
        assert "username" in params or "method" in params
    
    @pytest.mark.asyncio
    async def test_crawl_parameters_comprehensive(self, param_crawler, mock_session, mock_logger):
        """Test comprehensive parameter crawling."""
        # Mock HTTP responses
        main_response = MagicMock()
        main_response.status_code = 200
        main_response.text = """
        <html>
        <body>
            <form action="/submit">
                <input name="data" type="text">
            </form>
            <a href="/page1?param1=value1">Link 1</a>
            <a href="/page2?param2=value2">Link 2</a>
        </body>
        </html>
        """
        main_response.headers = {'content-type': 'text/html'}
        
        sub_response = MagicMock()
        sub_response.status_code = 200
        sub_response.text = """
        <html>
        <form action="/api/submit">
            <input name="api_key" type="hidden">
            <input name="user_id" type="text">
        </form>
        </html>
        """
        sub_response.headers = {'content-type': 'text/html'}
        
        mock_session.get.side_effect = [main_response, sub_response, sub_response]
        
        result = await param_crawler.crawl_parameters("https://example.com", max_depth=2)
        
        # Verify results structure
        assert isinstance(result, dict)
        assert "https://example.com" in result or len(result) > 0
        
        # Verify parameters were discovered
        all_params = []
        for params in result.values():
            all_params.extend(params)
        
        assert len(all_params) > 0


class TestSubdomainDiscovery:
    """Test cases untuk Subdomain Discovery."""
    
    @pytest.fixture
    def mock_session(self):
        """Mock HTTP session."""
        return AsyncMock()
    
    @pytest.fixture
    def mock_logger(self):
        """Mock logger.""" 
        return MagicMock()
    
    @pytest.fixture
    def subdomain_discovery(self, mock_session, mock_logger):
        """Subdomain discovery instance."""
        return SubdomainDiscovery(mock_session, mock_logger)
    
    @pytest.mark.asyncio
    async def test_dictionary_discovery(self, subdomain_discovery):
        """Test dictionary-based subdomain discovery."""
        # Mock DNS resolution
        with patch.object(subdomain_discovery, '_check_subdomain') as mock_check:
            mock_check.side_effect = lambda x: "www.example.com" if "www" in x else None
            
            result = await subdomain_discovery._dictionary_discovery("example.com")
            
            assert "www.example.com" in result
            assert len(result) >= 1
    
    @pytest.mark.asyncio
    async def test_certificate_transparency_discovery(self, subdomain_discovery, mock_session):
        """Test Certificate Transparency discovery."""
        # Mock CT API response
        ct_response = MagicMock()
        ct_response.status_code = 200
        ct_response.json.return_value = [
            {"name_value": "www.example.com\napi.example.com"},
            {"name_value": "mail.example.com"}
        ]
        
        mock_session.get.return_value = ct_response
        
        result = await subdomain_discovery._certificate_transparency_discovery("example.com")
        
        assert "www.example.com" in result
        assert "api.example.com" in result 
        assert "mail.example.com" in result
    
    @pytest.mark.asyncio
    async def test_check_subdomain(self, subdomain_discovery, mock_session):
        """Test subdomain accessibility check."""
        # Mock successful response
        response = MagicMock()
        response.status_code = 200
        mock_session.get.return_value = response
        
        result = await subdomain_discovery._check_subdomain("www.example.com")
        assert result == "www.example.com"
        
        # Mock failed response
        mock_session.get.side_effect = Exception("Connection failed")
        result = await subdomain_discovery._check_subdomain("nonexistent.example.com")
        assert result is None


class TestSubdomainEnumerator:
    """Test cases untuk Subdomain Enumerator."""
    
    @pytest.fixture
    def mock_session(self):
        """Mock HTTP session."""
        return AsyncMock()
    
    @pytest.fixture 
    def mock_logger(self):
        """Mock logger."""
        return MagicMock()
    
    @pytest.fixture
    def subdomain_enumerator(self, mock_session, mock_logger):
        """Subdomain enumerator instance."""
        return SubdomainEnumerator(mock_session, mock_logger)
    
    def test_load_subdomain_wordlist(self, subdomain_enumerator):
        """Test wordlist loading."""
        wordlist = subdomain_enumerator._load_subdomain_wordlist()
        
        assert isinstance(wordlist, list)
        assert len(wordlist) > 100  # Should have comprehensive wordlist
        assert "www" in wordlist
        assert "api" in wordlist
        assert "admin" in wordlist
        assert "mail" in wordlist
    
    @pytest.mark.asyncio
    async def test_brute_force_enumeration(self, subdomain_enumerator):
        """Test brute force subdomain enumeration."""
        # Mock DNS resolution
        with patch.object(subdomain_enumerator, '_dns_resolve') as mock_dns:
            mock_dns.side_effect = lambda x: "www" in x or "api" in x
            
            result = await subdomain_enumerator._brute_force_enumeration("example.com")
            
            assert len(result) >= 2  # Should find www and api
            assert any("www.example.com" in sub for sub in result)
            assert any("api.example.com" in sub for sub in result)
    
    @pytest.mark.asyncio
    async def test_verify_alive_subdomains(self, subdomain_enumerator, mock_session):
        """Test subdomain alive verification."""
        subdomains = ["www.example.com", "api.example.com", "dead.example.com"]
        
        # Mock HTTP responses
        def mock_response(url):
            if "dead" in url:
                raise Exception("Connection failed")
            response = MagicMock()
            response.status_code = 200
            return response
        
        mock_session.head.side_effect = mock_response
        
        result = await subdomain_enumerator._verify_alive_subdomains(subdomains)
        
        assert "www.example.com" in result
        assert "api.example.com" in result
        assert "dead.example.com" not in result


class TestEnhancedDiscovery:
    """Test cases untuk Enhanced Discovery integration."""
    
    @pytest.fixture
    def mock_session(self):
        """Mock HTTP session."""
        return AsyncMock()
    
    @pytest.fixture
    def mock_logger(self):
        """Mock logger."""
        return MagicMock()
    
    @pytest.fixture
    def enhanced_discovery(self, mock_session, mock_logger):
        """Enhanced discovery instance."""
        return EnhancedDiscovery(mock_session, mock_logger)
    
    @pytest.mark.asyncio
    async def test_comprehensive_discovery(self, enhanced_discovery):
        """Test comprehensive discovery process."""
        target_url = "https://example.com"
        
        # Mock parameter crawler
        mock_param_results = {
            "https://example.com/login": ["username", "password"],
            "https://example.com/search": ["q", "category"]
        }
        
        # Mock subdomain discovery
        mock_subdomain_results = ["www.example.com", "api.example.com"]
        
        with patch.object(enhanced_discovery.param_crawler, 'crawl_parameters') as mock_crawl:
            with patch.object(enhanced_discovery.subdomain_discovery, 'discover_subdomains') as mock_subdomains:
                mock_crawl.return_value = mock_param_results
                mock_subdomains.return_value = mock_subdomain_results
                
                result = await enhanced_discovery.comprehensive_discovery(
                    target_url, 
                    include_subdomains=True,
                    max_depth=2
                )
                
                # Verify results structure
                assert "target_url" in result
                assert "endpoints_with_parameters" in result
                assert "subdomains" in result
                assert "total_endpoints" in result
                assert "total_parameters" in result
                assert "total_subdomains" in result
                
                # Verify data
                assert result["target_url"] == target_url
                assert result["total_endpoints"] == 2
                assert result["total_parameters"] == 4  # username, password, q, category
                assert result["total_subdomains"] == 2
    
    def test_save_discovery_results(self, enhanced_discovery, tmp_path):
        """Test discovery results saving."""
        results = {
            "target_url": "https://example.com",
            "discovered_at": datetime.now().isoformat(),
            "endpoints_with_parameters": {
                "https://example.com/test": ["param1", "param2"]
            },
            "subdomains": ["sub.example.com"],
            "total_endpoints": 1,
            "total_parameters": 2,
            "total_subdomains": 1
        }
        
        output_file = tmp_path / "test_discovery.json"
        saved_path = enhanced_discovery.save_discovery_results(results, str(output_file))
        
        assert output_file.exists()
        assert saved_path == str(output_file)
        
        # Verify file content
        import json
        with open(output_file) as f:
            loaded_results = json.load(f)
        
        assert loaded_results["target_url"] == "https://example.com"
        assert loaded_results["total_endpoints"] == 1


class TestDiscoveryIntegration:
    """Integration tests untuk discovery features."""
    
    @pytest.mark.asyncio
    async def test_discovery_with_scan_engine(self):
        """Test discovery integration dengan scan engine."""
        from app.core.engine import ScanEngine
        
        # Mock discovery results
        mock_discovery_results = {
            "endpoints_with_parameters": {
                "https://example.com/login": ["username", "password"],
                "https://example.com/search": ["q", "sort"]
            },
            "subdomains": ["api.example.com"],
            "total_endpoints": 2,
            "total_parameters": 4,
            "total_subdomains": 1
        }
        
        engine = ScanEngine(mode="safe", timeout=5)
        
        with patch.object(engine, '_create_http_session'):
            with patch('app.utils.crawler.EnhancedDiscovery') as MockDiscovery:
                mock_discovery_instance = MockDiscovery.return_value
                mock_discovery_instance.comprehensive_discovery.return_value = mock_discovery_results
                mock_discovery_instance.save_discovery_results.return_value = "test_results.json"
                
                # Test context creation
                context = await engine.create_scan_context("https://example.com")
                
                # Verify discovery results integration
                assert len(context.endpoints) == 2
                assert "https://example.com/login" in context.endpoints
                assert "https://example.com/search" in context.endpoints
                
                # Verify parameters
                assert "username" in context.parameters.get("https://example.com/login", set())
                assert "q" in context.parameters.get("https://example.com/search", set())
                
                # Verify metadata
                discovery_meta = context.metadata.get("discovery", {})
                assert discovery_meta["total_endpoints"] == 2
                assert discovery_meta["total_parameters"] == 4
                assert discovery_meta["subdomains_found"] == 1
    
    @pytest.mark.asyncio 
    async def test_discovery_error_handling(self):
        """Test error handling dalam discovery process."""
        from app.core.engine import ScanEngine
        
        engine = ScanEngine(mode="safe", timeout=5)
        
        with patch.object(engine, '_create_http_session'):
            with patch('app.utils.crawler.EnhancedDiscovery') as MockDiscovery:
                # Mock discovery failure
                mock_discovery_instance = MockDiscovery.return_value
                mock_discovery_instance.comprehensive_discovery.side_effect = Exception("Discovery failed")
                
                # Should fallback to basic discovery
                with patch.object(engine, 'discover_endpoints') as mock_basic_discovery:
                    with patch.object(engine, 'collect_parameters') as mock_basic_params:
                        mock_basic_discovery.return_value = {"https://example.com"}
                        mock_basic_params.return_value = {"https://example.com": {"param1"}}
                        
                        context = await engine.create_scan_context("https://example.com")
                        
                        # Verify fallback worked
                        assert len(context.endpoints) == 1
                        assert "https://example.com" in context.endpoints
                        assert context.metadata["discovery"]["discovery_method"] == "basic"


@pytest.mark.asyncio
async def test_performance_limits():
    """Test performance limits dan rate limiting."""
    from app.utils.crawler import ParameterCrawler
    
    session = AsyncMock()
    logger = MagicMock()
    crawler = ParameterCrawler(session, logger)
    
    # Test depth limit
    crawler.max_depth = 2
    assert crawler.max_depth == 2
    
    # Test URL limit per depth
    crawler.max_urls_per_depth = 10
    assert crawler.max_urls_per_depth == 10
    
    # Verify rate limiting exists
    assert hasattr(crawler, 'delay_between_requests')
    

def test_wordlist_comprehensiveness():
    """Test bahwa wordlist subdomain cukup comprehensive."""
    from app.utils.subdomain_scanner import SubdomainEnumerator
    
    session = AsyncMock()
    logger = MagicMock()
    enumerator = SubdomainEnumerator(session, logger)
    
    wordlist = enumerator._load_subdomain_wordlist()
    
    # Test essential subdomains
    essential = ['www', 'api', 'admin', 'mail', 'dev', 'test', 'staging']
    for word in essential:
        assert word in wordlist, f"Essential subdomain '{word}' missing from wordlist"
    
    # Test variety of categories
    assert any('admin' in word for word in wordlist)  # Administrative
    assert any('dev' in word for word in wordlist)    # Development
    assert any('api' in word for word in wordlist)    # API services
    assert any('mail' in word for word in wordlist)   # Mail services
    
    # Test reasonable size
    assert len(wordlist) >= 100, "Wordlist should be comprehensive"
    assert len(wordlist) <= 1000, "Wordlist should not be excessive" 