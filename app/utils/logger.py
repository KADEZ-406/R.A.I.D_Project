"""
Logger Utility for R.A.I.D Scanner
Provides consistent logging configuration and utilities
"""

import logging
import sys
from datetime import datetime
from pathlib import Path
from typing import Optional

from rich.console import Console
from rich.logging import RichHandler


def setup_logger(verbosity: int = 1,
                log_file: Optional[str] = None,
                logger_name: str = "raid") -> logging.Logger:
    """Set up logger with console and file output."""
    
    # Create logger
    logger = logging.getLogger(logger_name)
    logger.setLevel(logging.DEBUG if verbosity >= 2 else logging.INFO)
    
    # Clear existing handlers
    logger.handlers.clear()
    
    # Console handler with rich formatting
    console = Console()
    console_handler = RichHandler(
        console=console,
        show_time=True,
        show_path=(verbosity >= 2),
        rich_tracebacks=True,
        markup=True
    )
    
    console_level = logging.DEBUG if verbosity >= 2 else logging.INFO
    console_handler.setLevel(console_level)
    
    # Format for console
    console_format = "%(message)s"
    console_handler.setFormatter(logging.Formatter(console_format))
    
    logger.addHandler(console_handler)
    
    # File handler if specified
    if log_file:
        log_path = Path(log_file)
        log_path.parent.mkdir(parents=True, exist_ok=True)
        
        file_handler = logging.FileHandler(log_path, encoding='utf-8')
        file_handler.setLevel(logging.DEBUG)
        
        # Detailed format for file
        file_format = "%(asctime)s - %(name)s - %(levelname)s - %(funcName)s:%(lineno)d - %(message)s"
        file_handler.setFormatter(logging.Formatter(file_format))
        
        logger.addHandler(file_handler)
    
    # Default file logging to logs directory
    else:
        logs_dir = Path("logs")
        logs_dir.mkdir(exist_ok=True)
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        default_log_file = logs_dir / f"raid_scan_{timestamp}.log"
        
        file_handler = logging.FileHandler(default_log_file, encoding='utf-8')
        file_handler.setLevel(logging.DEBUG)
        
        file_format = "%(asctime)s - %(name)s - %(levelname)s - %(funcName)s:%(lineno)d - %(message)s"
        file_handler.setFormatter(logging.Formatter(file_format))
        
        logger.addHandler(file_handler)
        
        # Log the file location
        logger.info(f"Detailed logs saved to: {default_log_file}")
    
    # Suppress overly verbose third-party loggers unless in debug
    noisy_loggers = [
        "httpx", "asyncio", "urllib3",
    ]
    for name in noisy_loggers:
        logging.getLogger(name).setLevel(logging.WARNING if verbosity < 2 else logging.INFO)

    return logger


def create_plugin_logger(plugin_name: str, verbose: bool = False) -> logging.Logger:
    """Create a logger specifically for a plugin."""
    logger_name = f"raid.plugin.{plugin_name}"
    return setup_logger(verbose=verbose, logger_name=logger_name)


class SecurityLogger:
    """Security-focused logger for sensitive operations."""
    
    def __init__(self, audit_log_file: str = "logs/security_audit.log"):
        self.audit_log_file = Path(audit_log_file)
        self.audit_log_file.parent.mkdir(parents=True, exist_ok=True)
        
        # Create dedicated security logger
        self.logger = logging.getLogger("raid.security")
        self.logger.setLevel(logging.INFO)
        
        # Clear existing handlers
        self.logger.handlers.clear()
        
        # Secure file handler - always log security events
        handler = logging.FileHandler(self.audit_log_file, encoding='utf-8')
        handler.setLevel(logging.INFO)
        
        # Detailed format for security logs
        security_format = (
            "%(asctime)s - SECURITY - %(levelname)s - "
            "%(funcName)s:%(lineno)d - %(message)s"
        )
        handler.setFormatter(logging.Formatter(security_format))
        
        self.logger.addHandler(handler)
    
    def log_scan_start(self, targets: list, mode: str, user_context: str = ""):
        """Log scan initiation."""
        self.logger.info(
            f"SCAN_START - Mode: {mode} - Targets: {len(targets)} - "
            f"First_Target: {targets[0] if targets else 'None'} - "
            f"Context: {user_context}"
        )
    
    def log_scan_end(self, findings_count: int, duration: float):
        """Log scan completion."""
        self.logger.info(
            f"SCAN_END - Findings: {findings_count} - Duration: {duration:.2f}s"
        )
    
    def log_payload_refusal(self, requested_payload: str, reason: str, context: str = ""):
        """Log refused payload requests."""
        self.logger.warning(
            f"PAYLOAD_REFUSAL - Reason: {reason} - "
            f"Payload: {requested_payload[:100]}... - Context: {context}"
        )
    
    def log_mode_escalation(self, from_mode: str, to_mode: str, reason: str):
        """Log scan mode changes."""
        self.logger.info(
            f"MODE_ESCALATION - From: {from_mode} - To: {to_mode} - Reason: {reason}"
        )
    
    def log_attestation_check(self, target: str, success: bool, details: str = ""):
        """Log attestation validation attempts."""
        status = "SUCCESS" if success else "FAILURE"
        self.logger.info(
            f"ATTESTATION_CHECK - Status: {status} - Target: {target} - "
            f"Details: {details}"
        )
    
    def log_plugin_execution(self, plugin_name: str, target: str, findings_count: int):
        """Log plugin execution results."""
        self.logger.info(
            f"PLUGIN_EXECUTION - Plugin: {plugin_name} - Target: {target} - "
            f"Findings: {findings_count}"
        )
    
    def log_high_confidence_finding(self, finding_id: str, target: str, 
                                  severity: str, confidence: int):
        """Log high-confidence security findings."""
        self.logger.warning(
            f"HIGH_CONFIDENCE_FINDING - ID: {finding_id} - Target: {target} - "
            f"Severity: {severity} - Confidence: {confidence}%"
        )
    
    def log_error(self, error_type: str, error_message: str, context: str = ""):
        """Log security-relevant errors."""
        self.logger.error(
            f"ERROR - Type: {error_type} - Message: {error_message} - "
            f"Context: {context}"
        )


class RequestLogger:
    """Logger for HTTP requests and responses."""
    
    def __init__(self, log_file: str = "logs/requests.log", max_body_size: int = 1000):
        self.log_file = Path(log_file)
        self.log_file.parent.mkdir(parents=True, exist_ok=True)
        self.max_body_size = max_body_size
        
        # Create request logger
        self.logger = logging.getLogger("raid.requests")
        self.logger.setLevel(logging.DEBUG)
        
        # Clear existing handlers
        self.logger.handlers.clear()
        
        # File handler for requests
        handler = logging.FileHandler(self.log_file, encoding='utf-8')
        handler.setLevel(logging.DEBUG)
        
        # Simple format for request logs
        request_format = "%(asctime)s - %(message)s"
        handler.setFormatter(logging.Formatter(request_format))
        
        self.logger.addHandler(handler)
    
    def log_request(self, method: str, url: str, headers: dict, 
                   data: str = None, response_code: int = None, 
                   response_time: float = None):
        """Log HTTP request details."""
        # Truncate large data
        if data and len(data) > self.max_body_size:
            data = data[:self.max_body_size] + "... (truncated)"
        
        # Sanitize headers (remove sensitive data)
        safe_headers = {}
        for key, value in headers.items():
            if key.lower() in ['authorization', 'cookie', 'x-api-key']:
                safe_headers[key] = "[REDACTED]"
            else:
                safe_headers[key] = value
        
        log_message = (
            f"REQUEST - {method} {url} - "
            f"Headers: {safe_headers} - "
            f"Data: {data or 'None'}"
        )
        
        if response_code is not None:
            log_message += f" - Response: {response_code}"
        
        if response_time is not None:
            log_message += f" - Time: {response_time:.3f}s"
        
        self.logger.debug(log_message)
    
    def log_response(self, url: str, status_code: int, headers: dict, 
                    body: str = None, elapsed: float = None):
        """Log HTTP response details."""
        # Truncate large body
        if body and len(body) > self.max_body_size:
            body = body[:self.max_body_size] + "... (truncated)"
        
        log_message = (
            f"RESPONSE - {url} - Status: {status_code} - "
            f"Headers: {headers} - Body: {body or 'None'}"
        )
        
        if elapsed is not None:
            log_message += f" - Elapsed: {elapsed:.3f}s"
        
        self.logger.debug(log_message)


def get_log_files() -> dict:
    """Get paths to all log files."""
    logs_dir = Path("logs")
    if not logs_dir.exists():
        return {}
    
    log_files = {
        "main_logs": list(logs_dir.glob("raid_scan_*.log")),
        "security_audit": logs_dir / "security_audit.log",
        "requests": logs_dir / "requests.log",
        "refusal": Path("refusal.log")
    }
    
    return {k: v for k, v in log_files.items() if 
            (isinstance(v, Path) and v.exists()) or 
            (isinstance(v, list) and v)}


def cleanup_old_logs(days: int = 30):
    """Clean up log files older than specified days."""
    import time
    
    logs_dir = Path("logs")
    if not logs_dir.exists():
        return
    
    cutoff_time = time.time() - (days * 24 * 60 * 60)
    
    for log_file in logs_dir.glob("*.log"):
        if log_file.stat().st_mtime < cutoff_time:
            try:
                log_file.unlink()
                print(f"Deleted old log file: {log_file}")
            except Exception as e:
                print(f"Error deleting {log_file}: {e}")


# Initialize global loggers
security_logger = SecurityLogger()
request_logger = RequestLogger() 