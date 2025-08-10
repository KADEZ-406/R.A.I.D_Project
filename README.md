# KADEZ-406 | R.A.I.D Scanner

```
████████████████████████████████████████
████████████████████████████████████████
██████████████─────────────█████████████
███████████───────────────────██████████
█████████───────────────────────████████
███████─────██─────────────██─────██████
██████─────████───────────████─────█████
█████─────██████─────────█████──────████
████──────██████────────███████──────███
███──────██████████████████████──────███
███──────███─────███████─────███──────██
██───────█─────█───███───█─────█──────██
██──────██─────█────█────█─────██─────██
██──────█──────█────█────█─────██─────██
███─────██─────█────█────█─────██─────██
███─▄▄▄▄███────█───███───█────███▄▄▄▄─██
████─▄▄▄▄████────███████────████▄▄▄▄─███
████─▄▄▄▄▄▄███████████████████▄▄▄▄▄▄─███
█████─────────█████████████─────────████
██████─────────────███─────────────█████
███████────────────███────────────██████
█████████──────────███──────────████████
███████████───────█████───────██████████
██████████████────█████────█████████████
████████████████████████████████████████

            KADEZ-406  |  R.A.I.D  — Reconnaissance and Automated Intrusion Detector
```

**R.A.I.D** (Reconnaissance and Automated Intrusion Detector) is a comprehensive security testing framework designed for authorized penetration testing and vulnerability assessment in controlled environments.

## ⚠️ IMPORTANT ETHICAL NOTICE

### 🚨 AUTHORIZED USE ONLY 🚨

**This tool is designed for AUTHORIZED security testing only.**

- ✅ **Allowed**: Testing systems you own or have explicit written permission to test
- ✅ **Allowed**: Educational use in controlled lab environments  
- ✅ **Allowed**: Authorized penetration testing with proper documentation
- ❌ **PROHIBITED**: Unauthorized scanning of systems you do not own
- ❌ **PROHIBITED**: Malicious use or causing damage to systems
- ❌ **PROHIBITED**: Testing without proper authorization

**By using this tool, you agree to:**
- Only test systems you own or have explicit permission to test
- Follow all applicable laws and regulations
- Use responsible disclosure practices for any vulnerabilities found
- Not cause damage or disruption to target systems

**Unauthorized use is illegal and unethical. You are responsible for ensuring you have proper authorization before testing any system.**

## 🚀 Quick Start

### Installation

```bash
# Clone repository
git clone https://github.com/KADEZ-406/R.A.I.D_Project
cd R.A.I.D_Project

# Install dependencies
pip install -r requirements.txt

# Verify installation
python -m app.cli version
```

### Basic Usage

```bash
# Safe mode scan with enhanced discovery
python -m app.cli scan --target https://example.com --mode safe

# Deep discovery scan dengan subdomain enumeration
python -m app.cli scan --target https://example.com --crawl-depth 5 --max-subdomains 200

# Discovery-only mode (tanpa security scanning)
python -m app.cli discover --target https://example.com --output discovery_results.json

# Lab mode scan (against test applications)
python -m app.cli scan --target http://localhost:3000 --mode lab

# List available checks
python -m app.cli list-checks

# Generate plugin template
python -m app.cli generate-plugin my_custom_check --category custom
```

## 🏗️ Features

### 🔍 **Enhanced Discovery & Reconnaissance**
- **Advanced Parameter Crawling**: Deep web crawling hingga 5 level dengan ekstraksi parameter dari HTML, JavaScript, dan APIs
- **Comprehensive Subdomain Discovery**: Multiple enumeration techniques (DNS, Certificate Transparency, Dictionary attack, Passive sources)
- **Smart Attack Surface Mapping**: 5-25x lebih banyak attack surface coverage dibanding traditional scanning
- **Live Verification**: Otomatis verifikasi subdomain dan endpoint yang aktif
- Banner grabbing and technology fingerprinting
- Certificate analysis dan SSL/TLS assessment

### 🛡️ **Security Analysis**
- Security headers assessment
- SSL/TLS configuration analysis
- Authentication and authorization testing
- Input validation testing

### 🔌 **Plugin System**
- Modular plugin architecture
- 265+ security checks organized by category
- Easy plugin development framework
- Safe/Lab/Audit mode compatibility

### 📊 **Reporting**
- HTML reports with detailed findings
- JSON export for integration
- CSV format for spreadsheet analysis  
- External tool compatibility (Burp, Nessus)

### 🧪 **Lab Environment**
- Docker-based vulnerable applications
- OWASP DVWA, Juice Shop, WebGoat
- Isolated testing environment
- Safe learning and development

## 📋 Scan Modes

### Safe Mode (Default)
- **Purpose**: Non-destructive reconnaissance and analysis
- **Behavior**: Only passive checks and safe requests
- **Target**: Any authorized system
- **Payloads**: Safe test markers only

```bash
python -m app.cli scan --target https://example.com --mode safe
```

### Lab Mode  
- **Purpose**: Controlled testing against vulnerable applications
- **Behavior**: More aggressive testing with safe payloads
- **Target**: Docker lab environment applications
- **Payloads**: Lab-safe testing payloads

```bash
# Start lab environment first
docker-compose -f docker/docker-compose.lab.yml up -d

# Run lab mode scan
python -m app.cli scan --target http://localhost:3000 --mode lab
```

### Audit Mode
- **Purpose**: Comprehensive testing with attestation requirement
- **Behavior**: Full testing capabilities with enhanced logging
- **Target**: Systems with documented authorization
- **Payloads**: Comprehensive testing (lab environment only)

```bash
# Create attestation file
echo "I confirm I have authorization to scan https://example.com" > attestation.txt

# Run audit mode scan
python -m app.cli scan --target https://example.com --mode audit
```

## 🔧 Configuration

### Command Line Options

```bash
python -m app.cli scan \
  --target https://example.com \
  --mode safe \
  --concurrency 5 \
  --timeout 30 \
  --output-dir ./reports \
  --plugins banner_grab,health_header_check \
  --verbose
```

### Options Reference

| Option | Description | Default |
|--------|-------------|---------|
| `--target` | Target URL to scan | Required |
| `--mode` | Scan mode (safe/lab/audit) | safe |
| `--concurrency` | Concurrent requests | 5 |
| `--timeout` | Request timeout (seconds) | 30 |
| `--output-dir` | Reports output directory | ./reports |
| `--plugins` | Specific plugins to run | all |
| `--scope-file` | File with multiple targets | None |
| `--proxy` | HTTP proxy URL | None |
| `--user-agent` | Custom User-Agent string | R.A.I.D-Scanner/1.0 |
| `--verbose` | Enable verbose logging | False |
| `--force` | Ignore robots.txt | False |

## 🧪 Lab Environment

The Docker lab provides a safe environment for testing and learning:

### Start Lab Environment

```bash
# Start all vulnerable applications
docker-compose -f docker/docker-compose.lab.yml up -d

# Check status  
docker-compose -f docker/docker-compose.lab.yml ps

# Access applications:
# - OWASP Juice Shop: http://localhost:3000
# - DVWA: http://localhost:8082 (admin:password)
# - WebGoat: http://localhost:8080/WebGoat
# - bWAPP: http://localhost:8083/install.php
```

### Test Against Lab

```bash
# Safe reconnaissance
python -m app.cli scan --target http://localhost:3000 --mode safe

# Lab mode testing
python -m app.cli scan --target http://localhost:3000 --mode lab

# Specific vulnerability testing
python -m app.cli scan --target http://localhost:8082 --mode lab --plugins sqli_heuristic,xss_heuristic
```

### Stop Lab Environment

```bash
# Stop services
docker-compose -f docker/docker-compose.lab.yml down

# Remove all data
docker-compose -f docker/docker-compose.lab.yml down -v
```

## 🔌 Plugin Development

### Create New Plugin

```bash
# Generate plugin template
python -m app.cli generate-plugin my_security_check --category custom --mode safe
```

### Plugin Structure (Updated)

```python
# app/plugins/my_security_check.py
from typing import List
from app.core.model import Finding

METADATA = {
    "id": "my_security_check",
    "name": "My Security Check",
    "category": "custom",
    "severity_hint": "Medium",
    "required_mode": "safe",
    "implemented": False,
}

async def run(target: str, http, ctx) -> list[Finding]:
    return []
```

### Plugin Categories

| Category | Description | Mode |
|----------|-------------|------|
| reconnaissance | Information gathering | safe |
| configuration | Security configuration | safe |
| file_exposure | Exposed files and directories | safe |
| input_validation | Input validation testing | lab |
| authentication | Authentication testing | lab |
| authorization | Authorization testing | lab |
| api_security | API security testing | lab |
| tls_security | SSL/TLS analysis | safe |

## 📊 Reporting

R.A.I.D generates comprehensive reports in multiple formats:

### HTML Reports
- Visual dashboard with findings summary
- Detailed finding descriptions and evidence
- Recommendations and remediation guidance
- Lab reproduction instructions

### JSON Reports  
- Machine-readable format for integration
- Complete finding data with metadata
- Suitable for custom processing and analysis

### CSV Reports
- Spreadsheet-compatible format
- Finding summaries for tracking and metrics
- Easy filtering and sorting

### External Tool Integration
- Burp Suite XML format
- Nessus-compatible JSON
- Generic formats for other tools

## 🧪 Testing Framework

### Running Tests

```bash
# Install test dependencies
pip install pytest pytest-asyncio pytest-cov

# Run all tests
pytest

# Run with coverage
pytest --cov=app tests/

# Run specific test categories
pytest tests/test_plugins.py
pytest tests/test_engine.py
```

### Test Structure

```
tests/
├── test_engine.py          # Core engine tests
├── test_plugins.py         # Plugin tests
├── test_utils.py           # Utility function tests
├── integration/            # Integration tests
│   ├── test_lab_scan.py    # Lab environment tests
│   └── test_safe_scan.py   # Safe mode tests
└── fixtures/               # Test data and fixtures
```

## 🔒 Security Considerations

### Safe Mode Guarantees
- No exploit payloads in public mode
- Respects robots.txt by default
- Rate limiting to prevent overload
- Non-destructive testing only

### Lab Mode Safety
- Only works against containerized applications
- Isolated Docker network environment
- No external network access from lab
- Controlled payload testing

### Audit Trail
- All actions logged with timestamps
- Security events in dedicated audit log
- Payload refusal logging
- Attestation requirement for audit mode

## 📚 Documentation

### Additional Resources
- [Lab Environment Guide](docker/README_LAB.md) - Complete lab setup and usage
- [Plugin Development Guide](docs/plugin-development.md) - Creating custom plugins
- [API Reference](docs/api-reference.md) - Internal API documentation
- [Security Best Practices](docs/security-practices.md) - Safe usage guidelines

### Security Research
- OWASP Testing Guide compliance
- CWE/CVE reference integration
- Industry standard methodologies
- Academic research backing

## 🤝 Contributing

### Development Setup

```bash
# Clone repository
git clone https://github.com/kadez-406/raid-scanner.git
cd raid-scanner

# Create virtual environment
python -m venv venv
source venv/bin/activate  # Linux/Mac
# or
venv\Scripts\activate     # Windows

# Install development dependencies
pip install -r requirements.txt
pip install -e .

# Install pre-commit hooks
pre-commit install

# Run tests
pytest
```

### Contributing Guidelines

1. **Fork** the repository
2. **Create** a feature branch (`git checkout -b feature/amazing-feature`)
3. **Make** your changes following coding standards
4. **Add** tests for new functionality
5. **Ensure** all tests pass (`pytest`)
6. **Run** code quality checks (`black`, `isort`, `flake8`)
7. **Commit** changes (`git commit -m 'Add amazing feature'`)
8. **Push** to branch (`git push origin feature/amazing-feature`)
9. **Create** a Pull Request

### Code Standards
- Follow PEP 8 style guidelines
- Add type hints for all functions
- Include comprehensive docstrings
- Write tests for new features
- Maintain backwards compatibility

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## ⚖️ Legal Disclaimer

**IMPORTANT LEGAL NOTICE**

The R.A.I.D Scanner is provided for educational and authorized testing purposes only. Users must:

1. **Obtain proper authorization** before testing any system
2. **Comply with all applicable laws** and regulations
3. **Use responsibly** and ethically
4. **Not cause damage** or disruption to systems
5. **Follow responsible disclosure** practices

The developers and contributors of R.A.I.D Scanner:
- Are **not responsible** for misuse of this tool
- **Disclaim liability** for any damages caused by unauthorized use
- **Strongly condemn** malicious or unauthorized use
- **Encourage responsible** security research and testing

**Unauthorized use of this tool is illegal and unethical. You assume full responsibility for your actions.**

## 🏆 Credits

### KADEZ-406 Team
- **Security Researchers**: Advanced vulnerability research and detection
- **Software Engineers**: Robust and scalable scanner architecture  
- **DevOps Engineers**: Lab environment and deployment automation
- **QA Engineers**: Comprehensive testing and quality assurance

### Special Thanks
- OWASP Foundation for vulnerable applications and security guidance
- Security research community for methodologies and best practices
- Open source contributors for tools and libraries used

### Vulnerable Applications Used in Lab
- **OWASP Juice Shop** - Modern vulnerable web application
- **OWASP WebGoat** - Educational vulnerable application
- **DVWA** - Damn Vulnerable Web Application  
- **bWAPP** - Buggy Web Application
- **NodeGoat** - Vulnerable Node.js application
- **VAmPI** - Vulnerable REST API

## 📞 Support

### Community
- **GitHub Issues**: Bug reports and feature requests
- **Discussions**: Questions and community support  
- **Security**: Responsible disclosure of security issues



---

**Remember: With great power comes great responsibility. Use R.A.I.D ethically and legally.** 
