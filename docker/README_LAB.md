# R.A.I.D Security Testing Lab Environment

This Docker lab environment provides a safe, isolated testing environment for R.A.I.D scanner development and vulnerability testing.

## ⚠️ IMPORTANT SECURITY NOTICE

**THIS LAB CONTAINS INTENTIONALLY VULNERABLE APPLICATIONS**

- Only run this lab in isolated environments
- Never expose these services to public networks
- Use only for authorized security testing and learning
- Destroy lab environment after testing

## Quick Start

### Prerequisites

- Docker Engine 20.10+ 
- Docker Compose 2.0+
- At least 4GB RAM available
- At least 10GB disk space

### Start the Lab

```bash
# Start all vulnerable applications
docker-compose -f docker-compose.lab.yml up -d

# Check status
docker-compose -f docker-compose.lab.yml ps

# View logs
docker-compose -f docker-compose.lab.yml logs -f
```

### Stop the Lab

```bash
# Stop all services
docker-compose -f docker-compose.lab.yml down

# Stop and remove all data
docker-compose -f docker-compose.lab.yml down -v
```

## Available Applications

### Lab Dashboard
- **URL**: http://localhost:8000
- **Description**: Central management dashboard for the lab
- **Purpose**: Overview of all available applications

### OWASP Juice Shop
- **URL**: http://localhost:3000
- **Description**: Modern vulnerable web application
- **Technologies**: Node.js, Angular, Express
- **Focus**: Modern web vulnerabilities, client-side attacks

### OWASP WebGoat
- **URL**: http://localhost:8080/WebGoat
- **WebWolf**: http://localhost:9090/WebWolf  
- **Description**: Java-based vulnerable web application
- **Technologies**: Java, Spring Boot
- **Focus**: Educational vulnerability lessons

### DVWA (Damn Vulnerable Web Application)
- **URL**: http://localhost:8082
- **Credentials**: admin:password
- **Description**: PHP-based vulnerable web application
- **Technologies**: PHP, MySQL
- **Focus**: Traditional web vulnerabilities
- **Setup**: Login and click "Create/Reset Database"

### bWAPP (Buggy Web Application)
- **URL**: http://localhost:8083/install.php
- **Description**: Over 100 web vulnerabilities
- **Technologies**: PHP, MySQL
- **Focus**: Comprehensive vulnerability collection
- **Setup**: Run install.php first

### Mutillidae II
- **URL**: http://localhost:8084/mutillidae
- **Description**: OWASP vulnerable web application
- **Technologies**: PHP, MySQL
- **Focus**: OWASP Top 10 vulnerabilities

### NodeGoat
- **URL**: http://localhost:4000
- **Description**: Node.js vulnerable application
- **Technologies**: Node.js, MongoDB
- **Focus**: Node.js specific vulnerabilities

### VAmPI (Vulnerable API)
- **URL**: http://localhost:5000
- **Description**: Vulnerable REST API
- **Technologies**: Python, Flask
- **Focus**: API security testing

## Using R.A.I.D with the Lab

### Safe Mode Testing
```bash
# Test against lab applications safely
python -m app.cli scan --target http://localhost:3000 --mode safe
python -m app.cli scan --target http://localhost:8082 --mode safe
```

### Lab Mode Testing  
```bash
# Enable lab mode for more aggressive testing
python -m app.cli scan --target http://localhost:3000 --mode lab
python -m app.cli scan --target http://localhost:8082 --mode lab

# Test specific plugins
python -m app.cli scan --target http://localhost:3000 --mode lab --plugins sqli_heuristic,xss_heuristic
```

### Audit Mode Testing
```bash
# Create attestation file
echo "I confirm I have authorization to scan http://localhost:3000" > attestation.txt

# Run in audit mode
python -m app.cli scan --target http://localhost:3000 --mode audit
```

## Lab Network Architecture

- **Network**: `raid-lab-network` (172.20.0.0/16)
- **Isolation**: All services run in isolated Docker network
- **Persistence**: Database volumes for stateful applications
- **Monitoring**: Health checks on all services

## Troubleshooting

### Port Conflicts
If ports are already in use, modify the port mappings in `docker-compose.lab.yml`:

```yaml
ports:
  - "8080:8080"  # Change first port number
```

### Memory Issues
If applications fail to start:
```bash
# Check available memory
docker system info | grep Memory

# Increase Docker memory limit in Docker Desktop settings
```

### Database Issues
If database applications fail:
```bash
# Reset database volumes
docker-compose -f docker-compose.lab.yml down -v
docker-compose -f docker-compose.lab.yml up -d
```

### Application Setup
Some applications require initial setup:

1. **DVWA**: Login with admin:password, click "Create/Reset Database"
2. **bWAPP**: Visit /install.php to set up database
3. **WebGoat**: Register a new user account

## Security Best Practices

### Isolation
- Run lab on isolated networks only
- Use VPN or air-gapped systems for sensitive testing
- Never connect lab to production networks

### Data Handling
- Don't use real credentials in testing
- Clear browser data after testing
- Destroy lab environment when not in use

### Monitoring
- Monitor lab access and usage
- Log all testing activities
- Review findings in controlled environment

## Lab Maintenance

### Updates
```bash
# Pull latest images
docker-compose -f docker-compose.lab.yml pull

# Restart with updates
docker-compose -f docker-compose.lab.yml down
docker-compose -f docker-compose.lab.yml up -d
```

### Cleanup
```bash
# Remove unused Docker resources
docker system prune -a

# Remove all lab data
docker-compose -f docker-compose.lab.yml down -v --rmi all
```

## Educational Usage

### Learning Path
1. Start with **DVWA** on low security setting
2. Progress to **Juice Shop** for modern vulnerabilities  
3. Use **WebGoat** for guided learning exercises
4. Test **API security** with VAmPI
5. Explore **Node.js** vulnerabilities with NodeGoat

### Testing Methodology
1. Run R.A.I.D in safe mode for reconnaissance
2. Analyze findings and plan lab mode tests
3. Execute targeted tests in lab mode
4. Validate findings manually
5. Document and remediate vulnerabilities

## Support and Documentation

- **R.A.I.D Documentation**: See main README.md
- **Application Documentation**: Check individual application docs
- **Security Resources**: OWASP.org, CWE.mitre.org
- **Issues**: Report issues in the main project repository

## Legal and Ethical Notes

- Use only for authorized testing and education
- Respect applicable laws and regulations  
- Follow responsible disclosure practices
- Never test against systems you don't own
- Always obtain proper authorization before testing 