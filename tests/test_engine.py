"""
Test suite for R.A.I.D Scanner Core Engine
"""

import asyncio
import pytest
from datetime import datetime
from unittest.mock import AsyncMock, MagicMock, patch

from app.core.engine import ScanEngine, ScanContext
from app.core.plugin_loader import Finding
from app.utils.http_client import HTTPClient


class TestScanEngine:
    """Test cases for the main scan engine."""
    
    @pytest.fixture
    def scan_engine(self):
        """Create a scan engine instance for testing."""
        return ScanEngine(
            mode="safe",
            concurrency=2,
            timeout=10,
            output_dir="./test_reports"
        )
    
    def test_scan_engine_initialization(self, scan_engine):
        """Test scan engine initialization."""
        assert scan_engine.mode == "safe"
        assert scan_engine.concurrency == 2
        assert scan_engine.timeout == 10
        assert scan_engine.output_dir.name == "test_reports"
    
    def test_normalize_target(self, scan_engine):
        """Test target URL normalization."""
        # Test adding https
        assert scan_engine.normalize_target("example.com") == "https://example.com/"
        
        # Test preserving existing protocol
        assert scan_engine.normalize_target("http://example.com") == "http://example.com/"
        
        # Test removing trailing slash duplication
        assert scan_engine.normalize_target("https://example.com/") == "https://example.com/"
    
    @pytest.mark.asyncio
    async def test_initialize(self, scan_engine):
        """Test scan engine initialization."""
        with patch.object(scan_engine.plugin_loader, 'load_all_plugins', return_value=5):
            with patch.object(scan_engine.payload_manager, 'load_templates'):
                result = await scan_engine.initialize()
                assert result is True
    
    @pytest.mark.asyncio
    async def test_discover_endpoints(self, scan_engine):
        """Test endpoint discovery."""
        mock_session = AsyncMock()
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.headers = {'content-type': 'text/html'}
        mock_response.text = '<html><a href="/test">Test</a></html>'
        mock_session.get.return_value = mock_response
        
        endpoints = await scan_engine.discover_endpoints(
            "https://example.com", 
            mock_session, 
            max_depth=1
        )
        
        assert "https://example.com" in endpoints
        assert len(endpoints) >= 1
    
    def test_calculate_confidence(self, scan_engine):
        """Test confidence calculation."""
        finding = Finding(
            id="test_001",
            name="Test Finding",
            plugin="test_plugin",
            target="https://example.com",
            endpoint="https://example.com/test",
            param=None,
            evidence={"similarity_score": 0.5, "timing_delta": 3.0},
            indicators=["status_changed", "error_signature"],
            severity="medium",
            confidence=0,  # Will be calculated
            timestamp=datetime.now(),
            proof_mode="safe"
        )
        
        confidence = scan_engine.calculate_confidence(finding)
        assert 0 <= confidence <= 100
        assert confidence > 50  # Should be elevated due to multiple indicators
    
    @pytest.mark.asyncio
    async def test_create_scan_context(self, scan_engine):
        """Test scan context creation."""
        target = "https://example.com"
        
        with patch.object(scan_engine, 'discover_endpoints') as mock_discover:
            with patch.object(scan_engine, 'collect_parameters') as mock_collect:
                mock_discover.return_value = {target}
                mock_collect.return_value = {}
                
                context = await scan_engine.create_scan_context(target)
                
                assert isinstance(context, ScanContext)
                assert context.target == target
                assert context.mode == scan_engine.mode
                assert isinstance(context.session, HTTPClient)


class TestScanContext:
    """Test cases for scan context."""
    
    @pytest.fixture
    def scan_context(self):
        """Create a scan context for testing."""
        mock_session = MagicMock()
        mock_payload_manager = MagicMock()
        mock_logger = MagicMock()
        
        return ScanContext(
            target="https://example.com",
            mode="safe",
            session=mock_session,
            payload_manager=mock_payload_manager,
            logger=mock_logger
        )
    
    def test_scan_context_initialization(self, scan_context):
        """Test scan context initialization."""
        assert scan_context.target == "https://example.com"
        assert scan_context.mode == "safe"
        assert len(scan_context.endpoints) == 0
        assert len(scan_context.parameters) == 0
        assert len(scan_context.technologies) == 0


class TestIntegration:
    """Integration tests for the complete scanning process."""
    
    @pytest.mark.asyncio
    async def test_safe_mode_scan_flow(self):
        """Test complete safe mode scan flow."""
        engine = ScanEngine(mode="safe", concurrency=1, timeout=5)
        
        # Mock all external dependencies
        with patch.object(engine, 'initialize', return_value=True):
            with patch.object(engine.plugin_loader, 'filter_plugins') as mock_filter:
                with patch.object(engine, 'create_scan_context') as mock_context:
                    with patch.object(engine, 'run_plugin') as mock_run_plugin:
                        with patch.object(engine.result_manager, 'save_findings'):
                            with patch.object(engine.result_manager, 'generate_reports'):
                                
                                # Setup mocks
                                mock_filter.return_value = {"test_plugin": MagicMock()}
                                mock_context.return_value = MagicMock()
                                mock_context.return_value.session.close = AsyncMock()
                                
                                mock_finding = Finding(
                                    id="test_001",
                                    name="Test Finding",
                                    plugin="test_plugin",
                                    target="https://example.com",
                                    endpoint="https://example.com",
                                    param=None,
                                    evidence={},
                                    indicators=["test"],
                                    severity="info",
                                    confidence=50,
                                    timestamp=datetime.now(),
                                    proof_mode="safe"
                                )
                                mock_run_plugin.return_value = [mock_finding]
                                
                                # Run scan
                                result = await engine.run_scan(["https://example.com"])
                                
                                # Verify results
                                assert "findings" in result
                                assert "stats" in result
                                assert len(result["findings"]) == 1
                                assert result["findings"][0].name == "Test Finding"


@pytest.mark.asyncio
async def test_error_handling():
    """Test error handling in scan engine."""
    engine = ScanEngine(mode="safe")
    
    # Test initialization failure
    with patch.object(engine.plugin_loader, 'load_all_plugins', side_effect=Exception("Plugin load error")):
        result = await engine.initialize()
        assert result is False


def test_get_scan_stats():
    """Test scan statistics generation."""
    engine = ScanEngine(mode="safe")
    engine.start_time = datetime.now()
    engine.end_time = datetime.now()
    engine.total_findings = 5
    
    stats = engine.get_scan_stats()
    
    assert stats["mode"] == "safe"
    assert stats["total_findings"] == 5
    assert "duration_seconds" in stats
    assert "plugin_stats" in stats 