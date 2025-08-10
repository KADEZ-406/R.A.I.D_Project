# Enhanced Discovery Features

R.A.I.D Scanner telah diperlengkapi dengan sistem discovery yang sangat canggih untuk memaksimalkan coverage dan menemukan lebih banyak bug security. Fitur ini mencakup **Parameter Crawling** dan **Subdomain Discovery** yang terintegrasi penuh dengan scan engine.

## 🎯 Overview Fitur

### 🕷️ **Advanced Parameter Crawler**
- **Deep Web Crawling**: Crawl hingga depth 3 level secara default
- **Multi-Source Parameter Discovery**: Ekstraksi dari HTML forms, JavaScript, URL parameters, APIs
- **Smart Parameter Recognition**: Deteksi parameter dari berbagai konteks (DOM, AJAX, form inputs)
- **False Positive Reduction**: Filtering parameter yang valid dan menghindari noise

### 🌐 **Comprehensive Subdomain Discovery**
- **Multiple Enumeration Techniques**: Dictionary attack, Certificate Transparency, DNS enumeration, Passive sources
- **Large Wordlist**: 200+ subdomain patterns yang umum digunakan
- **Live Verification**: Memverifikasi subdomain yang benar-benar aktif
- **Integration with Scanning**: Otomatis scan parameter pada subdomain yang ditemukan

## 🚀 Penggunaan

### Basic Scanning dengan Discovery
```bash
# Scan dengan enhanced discovery (default)
python -m app.cli scan --target https://example.com

# Scan tanpa subdomain discovery
python -m app.cli scan --target https://example.com --no-subdomain-discovery

# Scan dengan custom crawl depth
python -m app.cli scan --target https://example.com --crawl-depth 5

# Scan dengan limit subdomain
python -m app.cli scan --target https://example.com --max-subdomains 100
```

### Discovery-Only Mode
```bash
# Discovery saja tanpa security scanning
python -m app.cli discover --target https://example.com

# Discovery dengan output custom
python -m app.cli discover --target https://example.com --output discovery_results.json

# Discovery dengan konfigurasi advanced
python -m app.cli discover \
  --target https://example.com \
  --crawl-depth 4 \
  --max-subdomains 200 \
  --verbose
```

## 🔧 Konfigurasi Advanced

### Parameter Crawler Settings
```python
# Di engine.py, dapat dikustomisasi:
crawler_config = {
    'max_depth': 3,              # Maksimal depth crawling
    'max_urls_per_depth': 50,    # Maksimal URL per level
    'delay_between_requests': 0.5, # Delay antar request
    'common_params': [...],      # Parameter umum yang dicari
    'param_patterns': [...],     # Regex pattern untuk deteksi parameter
}
```

### Subdomain Discovery Settings
```python
# Konfigurasi subdomain enumeration
subdomain_config = {
    'max_subdomains': 100,       # Maksimal subdomain yang ditemukan
    'wordlist_size': 200,        # Ukuran wordlist
    'concurrent_checks': 50,     # Concurrent DNS checks
    'verify_alive': True,        # Verifikasi subdomain hidup
    'methods': [                 # Metode enumeration yang digunakan
        'brute_force',
        'certificate_transparency', 
        'dns_enumeration',
        'passive_sources'
    ]
}
```

## 🎯 Discovery Methods

### 1. Parameter Discovery Techniques

#### **HTML Form Analysis**
- Ekstraksi dari `<input>`, `<select>`, `<textarea>` elements
- Analisis form action URLs
- Deteksi hidden input fields

#### **JavaScript Parameter Mining**
- Parsing JavaScript untuk AJAX parameters
- Deteksi object properties dan method calls
- Analisis jQuery selectors

#### **URL Parameter Extraction**
- Parsing query strings dari links
- Ekstraksi dari href attributes
- Analysis redirect parameters

#### **API Endpoint Discovery**
- Deteksi REST API endpoints
- Analysis AJAX calls
- Discovery dari JS frameworks (React, Vue, Angular)

### 2. Subdomain Enumeration Techniques

#### **Dictionary-Based Brute Force**
- Comprehensive wordlist dengan 200+ patterns
- Common service subdomains (www, mail, api, admin)
- Development environments (dev, test, staging)
- Infrastructure subdomains (cdn, static, assets)

#### **Certificate Transparency Logs**
- Query crt.sh database
- Certspotter API integration
- SSL certificate SAN analysis

#### **DNS-Based Enumeration**
- Zone transfer attempts
- Reverse DNS lookups
- DNS cache snooping

#### **Passive Reconnaissance**
- HackerTarget API integration
- Search engine dorks
- Public database queries

## 📊 Output & Results

### Discovery Results Structure
```json
{
  "target_url": "https://example.com",
  "discovered_at": "2024-01-15T10:30:00Z",
  "endpoints_with_parameters": {
    "https://example.com/search": ["q", "category", "sort"],
    "https://example.com/login": ["username", "password", "token"],
    "https://example.com/api/users": ["id", "limit", "offset"]
  },
  "subdomains": [
    "www.example.com",
    "api.example.com", 
    "admin.example.com",
    "mail.example.com"
  ],
  "total_endpoints": 156,
  "total_parameters": 423,
  "total_subdomains": 12,
  "subdomain_endpoints": {
    "api.example.com": {
      "https://api.example.com/v1/users": ["id", "fields"],
      "https://api.example.com/v1/products": ["category", "limit"]
    }
  }
}
```

### Integration dengan Scan Results
```json
{
  "scan_metadata": {
    "discovery": {
      "total_endpoints": 156,
      "total_parameters": 423,
      "subdomains_found": 12,
      "discovery_method": "enhanced"
    }
  },
  "findings": [
    {
      "endpoint": "https://api.example.com/v1/users",
      "parameter": "id",
      "vulnerability": "SQL Injection",
      "discovered_via": "subdomain_crawling"
    }
  ]
}
```

## 🚦 Performance & Limits

### Default Limits
- **Crawl Depth**: 3 levels
- **URLs per Depth**: 50 URLs
- **Max Subdomains**: 50 subdomains
- **Concurrent DNS Checks**: 50 concurrent
- **Request Timeout**: 30 seconds
- **Rate Limiting**: 0.5s delay antar request

### Performance Optimization
```bash
# High-performance scanning
python -m app.cli scan \
  --target https://example.com \
  --crawl-depth 2 \
  --max-subdomains 20 \
  --concurrency 10

# Comprehensive deep scanning  
python -m app.cli scan \
  --target https://example.com \
  --crawl-depth 5 \
  --max-subdomains 200 \
  --concurrency 3
```

## 🔍 Advanced Use Cases

### 1. Large Organization Scanning
```bash
# Comprehensive corporate assessment
python -m app.cli scan \
  --target https://company.com \
  --crawl-depth 4 \
  --max-subdomains 500 \
  --mode lab \
  --verbose
```

### 2. API Discovery & Testing
```bash
# Focus pada API discovery
python -m app.cli discover \
  --target https://api.company.com \
  --crawl-depth 3 \
  --no-subdomain-discovery
```

### 3. Multi-Target Discovery
```bash
# Gunakan scope file untuk multiple targets
echo "https://app1.company.com" > targets.txt
echo "https://app2.company.com" >> targets.txt

python -m app.cli scan \
  --scope-file targets.txt \
  --crawl-depth 3 \
  --max-subdomains 100
```

## 🛡️ Ethical Considerations

### Rate Limiting & Respectful Scanning
- Built-in delay antar requests (0.5s default)
- Respect untuk robots.txt (kecuali --force)
- Concurrent limits untuk menghindari DDoS
- Request timeout yang reasonable

### Target Authorization
```bash
# Discovery mode tetap memerlukan authorization untuk target publik
echo "I confirm I have authorization to scan target.com" > attestation.txt

python -m app.cli discover --target https://target.com --mode audit
```

## 📈 Expected Bug Discovery Improvement

Dengan enhanced discovery, diharapkan peningkatan signifikan dalam bug detection:

### Parameter Coverage Increase
- **Traditional Scanning**: ~10-20 parameters per target
- **Enhanced Discovery**: ~100-500 parameters per target
- **Improvement**: 5-25x lebih banyak attack surface

### Subdomain Coverage
- **Traditional**: Hanya main domain
- **Enhanced**: 10-200 subdomains per target  
- **Additional Attack Surface**: 10-200x lebih luas

### Bug Discovery Rate
- **SQLi Detection**: +300% (lebih banyak parameter)
- **XSS Detection**: +400% (form inputs & JS parameters)
- **IDOR**: +500% (API endpoints dari subdomains)
- **Information Disclosure**: +600% (subdomain files & configs)

## 🔧 Troubleshooting

### Common Issues

#### Discovery Timeout
```bash
# Increase timeout untuk target yang lambat
python -m app.cli discover --target https://slow-site.com --timeout 60
```

#### Too Many Subdomains
```bash
# Limit subdomain discovery untuk performa
python -m app.cli scan --target https://huge-org.com --max-subdomains 50
```

#### Memory Usage
```bash
# Reduce crawl depth untuk menghemat memory
python -m app.cli scan --target https://complex-site.com --crawl-depth 2
```

### Debug Mode
```bash
# Enable verbose logging untuk debugging
python -m app.cli discover --target https://target.com --verbose
```

## 📚 Integration Examples

### Custom Plugin Integration
```python
# Plugin dapat mengakses discovery results
async def run(target: str, session, context):
    # Access discovered parameters
    for endpoint, params in context.parameters.items():
        for param in params:
            # Test parameter for vulnerability
            await test_parameter_injection(endpoint, param, session)
    
    # Access subdomain metadata
    discovery_meta = context.metadata.get('discovery', {})
    subdomain_count = discovery_meta.get('subdomains_found', 0)
    
    if subdomain_count > 10:
        # High-value target dengan banyak subdomains
        await run_intensive_testing(context)
```

### CI/CD Integration
```yaml
# GitHub Actions example
- name: R.A.I.D Discovery
  run: |
    python -m app.cli discover \
      --target ${{ secrets.TARGET_URL }} \
      --output discovery_results.json \
      --crawl-depth 3
    
    python -m app.cli scan \
      --target ${{ secrets.TARGET_URL }} \
      --mode safe \
      --output-dir ./security_reports
```

Dengan fitur enhanced discovery ini, R.A.I.D Scanner sekarang mampu menemukan jauh lebih banyak attack surface dan berpotensi mengidentifikasi bug security yang sebelumnya terlewat karena keterbatasan coverage traditional scanning. 