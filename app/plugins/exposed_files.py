"""
Exposed Files Detection Plugin for R.A.I.D Scanner
Detects commonly exposed sensitive files and directories
"""

from datetime import datetime
from typing import List
import urllib.parse

from app.core.model import Finding


METADATA = {
    "id": "exposed_files",
    "name": "Exposed Files Detection",
    "category": "file_exposure",
    "severity_hint": "Medium",
    "required_mode": "safe",
    "implemented": True,
}


# Common sensitive files to check
SENSITIVE_FILES = [
    # Configuration files
    ".env", ".env.local", ".env.production",
    "config.php", "config.ini", "config.yaml", "config.json",
    "settings.py", "local_settings.py",
    "web.config", "app.config",
    
    # Database files
    "database.sql", "dump.sql", "backup.sql",
    "database.sqlite", "database.db",
    
    # Backup files
    "backup.zip", "backup.tar.gz", "site-backup.tar.gz",
    "wwwroot.zip", "website.tar.gz",
    
    # Version control
    ".git/config", ".git/HEAD", ".gitignore",
    ".svn/entries", ".hg/hgrc",
    
    # IDE files
    ".vscode/settings.json", ".idea/workspace.xml",
    
    # Log files
    "error.log", "access.log", "debug.log",
    "application.log", "app.log",
    
    # Admin interfaces
    "admin/", "administrator/", "admin.php",
    "wp-admin/", "phpmyadmin/",
    
    # Test files
    "test.php", "test.html", "phpinfo.php",
    "info.php", "debug.php"
]


async def run(target: str, session, context) -> List[Finding]:
    """Run exposed files detection."""
    findings = []
    
    try:
        base_url = target.rstrip('/')
        
        for file_path in SENSITIVE_FILES:
            try:
                test_url = f"{base_url}/{file_path}"
                response = await session.get(test_url)
                
                if response.status_code == 200:
                    # File exists and is accessible
                    severity = determine_severity(file_path, response)
                    
                    finding = Finding(
                        id=f"exposed_file_{file_path.replace('/', '_').replace('.', '_')}",
                        name=f"Exposed Sensitive File: {file_path}",
                        plugin="exposed_files",
                        target=target,
                        endpoint=test_url,
                        parameter=None,
                        evidence={
                            "file_path": file_path,
                            "response_length": len(response.text),
                            "content_type": response.headers.get('content-type', 'unknown'),
                            "response_snippet": response.text[:200]
                        },
                        indicators=["file_exposure", "sensitive_data"],
                        severity=severity,
                        confidence=95.0,
                        timestamp=datetime.now().isoformat(),
                        proof_mode="safe",
                        description=f"Sensitive file {file_path} is publicly accessible",
                        recommendation=f"Remove or restrict access to {file_path}"
                    )
                    findings.append(finding)
                    
            except Exception:
                continue  # Skip failed requests
                
    except Exception as e:
        error_finding = Finding(
            id="exposed_files_error",
            name="Exposed Files Check Error",
            plugin="exposed_files", 
            target=target,
            endpoint=target,
            parameter=None,
            evidence={"error": str(e)},
            indicators=["plugin_error"],
            severity="info",
            confidence=0.0,
            timestamp=datetime.now().isoformat(),
            proof_mode=context.mode,
            description=f"Error during exposed files check: {e}"
        )
        findings.append(error_finding)
    
    return findings


def determine_severity(file_path: str, response) -> str:
    """Determine severity based on file type and content."""
    file_lower = file_path.lower()
    
    # High severity files
    if any(pattern in file_lower for pattern in ['.env', 'database', 'backup', 'config']):
        return "high"
    
    # Medium severity files  
    if any(pattern in file_lower for pattern in ['.git', 'admin', 'log']):
        return "medium"
    
    # Low severity files
    return "low" 