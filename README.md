# ZooKeeper Security Auditor

A comprehensive security auditing and penetration testing tool for Apache ZooKeeper servers. This tool is designed for security professionals to assess the security posture of ZooKeeper deployments in production environments.

**Author:** Garland Glessner  
**Email:** gglessner@gmail.com

## License

This project is licensed under the GNU General Public License v3.0 - see the [LICENSE](LICENSE) file for details.

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.

## Features

### 🔍 Security Testing Capabilities
- **Authentication Bypass Testing**: Tests common default credentials and authentication schemes
- **ACL Enumeration**: Discovers and analyzes Access Control Lists on nodes
- **Data Exposure Scanning**: Identifies sensitive data stored in ZooKeeper
- **Privilege Escalation Testing**: Tests ability to create/modify nodes in sensitive locations
- **Information Disclosure Testing**: Tests access to system and internal paths
- **CVE Vulnerability Analysis**: Comprehensive integrated database of known ZooKeeper vulnerabilities
- **Advanced Penetration Testing**: Production-safe advanced security testing techniques
- **Comprehensive Reporting**: Generates detailed security audit reports
- **Automatic Cleanup**: All tests clean up after themselves, leaving no artifacts

### 🛡️ Production-Safe Design
- **No DoS Testing**: Removed all denial-of-service functionality for production safety
- **Automatic Cleanup**: All test nodes and artifacts are automatically removed
- **Non-Destructive**: Tests are designed to be safe for production environments
- **No authentication or encryption required** for testing
- **Identifies common ZooKeeper security misconfigurations**
- **Tests for data exposure and access control issues**

### 🚀 Advanced Penetration Testing Features
- **Session Hijacking Testing**: Analyzes session ID patterns and predictability
- **Race Condition Testing**: Tests for race conditions in node operations
- **Path Traversal Testing**: Tests for path traversal vulnerabilities
- **Injection Attack Testing**: Tests for various injection vulnerabilities
- **ACL Bypass Techniques**: Tests multiple ACL bypass methods
- **Ephemeral Node Manipulation**: Tests ephemeral node security
- **Quota Bypass Testing**: Tests quota enforcement mechanisms
- **Connection Security Testing**: Tests connection timeout and authentication enforcement
- **Authentication Scheme Enumeration**: Discovers available authentication methods
- **Node Watcher Bypass**: Tests watcher mechanism security
- **Serialization Vulnerability Testing**: Tests for serialization-based attacks

### 📊 Data Discovery & Analysis
- **Pattern Search**: Search for specific patterns in node names and data
- **Data Export**: Export all discovered data to JSON format
- **Credential Harvesting**: Extract credentials, tokens, and keys from data
- **Configuration Analysis**: Analyze configuration patterns and service endpoints
- **Deep Scanning**: Comprehensive recursive scanning with detailed analysis
- **Recursive Path Reading**: Read all data from specific paths

## Prerequisites

- Python 3.6 or higher
- Apache ZooKeeper server running (default: localhost:2181)
- Network access to ZooKeeper server

## Installation

1. Clone or download the repository
2. Install the required dependencies:
```bash
pip install -r requirements.txt
```

**Note:** The tool is now fully self-contained. All CVE functionality is integrated into the main script - no additional files are required.

## Usage

### Basic Connection Test

Test basic connectivity to ZooKeeper:
```bash
python ZookeeperClient.py
```

### Get Server Version with CVE Analysis

Quickly get the ZooKeeper server version with comprehensive CVE analysis:
```bash
python ZookeeperClient.py --version
```

### CVE Vulnerability Analysis

Check for known CVEs affecting the ZooKeeper version:
```bash
# Get version with CVE analysis
python ZookeeperClient.py --version

# Only perform CVE analysis
python ZookeeperClient.py --cve-check
```

**Note:** CVE checking is now fully integrated into the main script. The tool includes a comprehensive database of 30+ known ZooKeeper CVEs with version information, severity levels, and detailed descriptions.

### Comprehensive Security Audit

Run all security tests:
```bash
python ZookeeperClient.py --audit
```

### Advanced Penetration Testing

Run all advanced penetration testing techniques:
```bash
python ZookeeperClient.py --advanced-pentest
```

### Individual Security Tests

Test specific security aspects:

```bash
# Basic Security Tests
python ZookeeperClient.py --auth-bypass
python ZookeeperClient.py --enumerate-acls
python ZookeeperClient.py --data-exposure
python ZookeeperClient.py --privilege-escalation
python ZookeeperClient.py --info-disclosure

# Advanced Penetration Testing
python ZookeeperClient.py --session-hijacking
python ZookeeperClient.py --race-conditions
python ZookeeperClient.py --path-traversal
python ZookeeperClient.py --injection-attacks
python ZookeeperClient.py --acl-bypass
python ZookeeperClient.py --ephemeral-manipulation
python ZookeeperClient.py --quota-bypass
python ZookeeperClient.py --connection-security
python ZookeeperClient.py --auth-enumeration
python ZookeeperClient.py --watcher-bypass
python ZookeeperClient.py --serialization
```

### Data Discovery & Analysis

Advanced data discovery and analysis features:

```bash
# Search for specific patterns in node names and data
python ZookeeperClient.py --search-pattern "database|password|secret"

# Export all discovered data to JSON file
python ZookeeperClient.py --export-data zk_data.json

# Extract credentials, tokens, and keys from discovered data
python ZookeeperClient.py --harvest-creds

# Analyze configuration patterns and extract service endpoints
python ZookeeperClient.py --analyze-configs

# Perform deep recursive scanning with comprehensive coverage
python ZookeeperClient.py --deep-scan

# Read all data from a specific path recursively
python ZookeeperClient.py --read-path /config
```

### Custom Server Configuration

```bash
# Audit specific ZooKeeper server
python ZookeeperClient.py --server zk1.example.com:2181 --audit

# Test with custom timeout
python ZookeeperClient.py --server zk1.example.com:2181 --timeout 30 --audit
```

### TLS/SSL Secure Connections

Connect to ZooKeeper servers with TLS/SSL encryption:

```bash
# Basic TLS connection (default port 2181)
python ZookeeperClient.py --tls --server zk1.example.com:2181

# TLS with client certificate authentication
python ZookeeperClient.py --tls --cert-file client.pem --key-file client.key --server zk1.example.com:2181

# TLS with CA certificate verification
python ZookeeperClient.py --tls --ca-file ca.pem --server zk1.example.com:2181

# TLS without certificate verification (not recommended for production)
python ZookeeperClient.py --tls --no-verify-ssl --server zk1.example.com:2181

# Comprehensive audit with TLS
python ZookeeperClient.py --tls --cert-file client.pem --key-file client.key --ca-file ca.pem --server zk1.example.com:2181 --audit
```

## Command Line Options

### Basic Options
- `--server, -s`: ZooKeeper server:port (default: localhost:2181)
- `--timeout`: Connection timeout in seconds (default: 10)
- `--version`: Display ZooKeeper server version with CVE analysis and exit
- `--cve-check`: Only perform CVE vulnerability analysis
- `--help, -h`: Show help message and exit

### Basic Security Tests
- `--audit, -a`: Run comprehensive security audit
- `--auth-bypass, -b`: Test authentication bypass vulnerabilities
- `--enumerate-acls, -e`: Enumerate ACLs on nodes
- `--data-exposure, -d`: Test for sensitive data exposure
- `--privilege-escalation, -p`: Test privilege escalation opportunities
- `--info-disclosure, -i`: Test information disclosure vulnerabilities

### Advanced Penetration Testing
- `--advanced-pentest`: Run all advanced penetration testing techniques
- `--session-hijacking`: Test for session hijacking vulnerabilities
- `--race-conditions`: Test for race condition vulnerabilities
- `--path-traversal`: Test for path traversal vulnerabilities
- `--injection-attacks`: Test for injection vulnerabilities
- `--acl-bypass`: Test ACL bypass techniques
- `--ephemeral-manipulation`: Test ephemeral node manipulation vulnerabilities
- `--quota-bypass`: Test quota bypass vulnerabilities
- `--connection-security`: Test connection security vulnerabilities (production-safe)
- `--auth-enumeration`: Test authentication scheme enumeration
- `--watcher-bypass`: Test node watcher bypass vulnerabilities
- `--serialization`: Test serialization vulnerabilities

### Data Discovery & Analysis
- `--read-path`: Recursively read all data from specified path (e.g., /config)
- `--search-pattern`: Search for specific patterns in node names and data (e.g., "database|password|secret")
- `--export-data`: Export all discovered data to specified file (JSON format)
- `--harvest-creds`: Extract and display credentials, tokens, and keys from discovered data
- `--analyze-configs`: Analyze configuration patterns and extract service endpoints, IPs, and domains
- `--deep-scan`: Perform deep recursive scanning with increased depth and comprehensive coverage

### TLS/SSL Options
- `--tls`: Enable TLS/SSL connection
- `--cert-file`: Path to client certificate file (PEM format)
- `--key-file`: Path to client private key file (PEM format)
- `--ca-file`: Path to CA certificate file (PEM format)
- `--no-verify-ssl`: Disable SSL certificate verification (not recommended for production)

## Examples

### Quick Start
```bash
# Basic connection test
python ZookeeperClient.py

# Get version and CVE analysis
python ZookeeperClient.py --version

# Run comprehensive audit
python ZookeeperClient.py --audit

# Test specific server
python ZookeeperClient.py --server zk1.example.com:2181 --audit
```

### Security Testing
```bash
# Test authentication bypass
python ZookeeperClient.py --auth-bypass

# Enumerate ACLs
python ZookeeperClient.py --enumerate-acls

# Test for data exposure
python ZookeeperClient.py --data-exposure

# Run advanced penetration testing
python ZookeeperClient.py --advanced-pentest
```

### Data Discovery
```bash
# Search for sensitive patterns
python ZookeeperClient.py --search-pattern "password|secret|key"

# Export all data
python ZookeeperClient.py --export-data zk_data.json

# Harvest credentials
python ZookeeperClient.py --harvest-creds

# Deep scan
python ZookeeperClient.py --deep-scan
```

### TLS/SSL Testing
```bash
# TLS connection
python ZookeeperClient.py --tls --server zk1.example.com:2181

# TLS with client certificates
python ZookeeperClient.py --tls --cert-file client.pem --key-file client.key --server zk1.example.com:2181

# Comprehensive audit with TLS
python ZookeeperClient.py --tls --cert-file client.pem --key-file client.key --ca-file ca.pem --server zk1.example.com:2181 --audit
```

## CVE Database

The tool includes a comprehensive database of known ZooKeeper vulnerabilities:

- **30+ CVEs** covering versions from 3.4.0 to 3.8.2
- **Severity levels**: CRITICAL, HIGH, MEDIUM, LOW
- **Detailed descriptions** and CVSS scores
- **Version range matching** for accurate vulnerability assessment
- **Automatic analysis** during version checks

### CVE Categories
- Remote Code Execution vulnerabilities
- Authentication bypass issues
- Information disclosure vulnerabilities
- Denial of Service vulnerabilities
- Log4j/Log4Shell vulnerabilities
- Serialization vulnerabilities

## Security Considerations

### Production Safety
- **No DoS Testing**: All denial-of-service functionality has been removed
- **Automatic Cleanup**: All test artifacts are automatically removed
- **Non-Destructive**: Tests are designed to be safe for production use
- **Connection Limits**: Tests use reasonable connection limits to avoid overwhelming servers

### Testing Environment
- Test in a controlled environment first
- Ensure you have permission to test the target ZooKeeper server
- Monitor server performance during testing
- Review all findings before taking action

## Troubleshooting

### Common Issues

**Connection Failed**
```bash
# Check if ZooKeeper is running
telnet localhost 2181

# Try with explicit server
python ZookeeperClient.py --server localhost:2181
```

**Timeout Issues**
```bash
# Increase timeout
python ZookeeperClient.py --timeout 30 --server zk1.example.com:2181
```

**TLS Connection Issues**
```bash
# Check certificate files
python ZookeeperClient.py --tls --cert-file client.pem --key-file client.key --server zk1.example.com:2181

# Try without certificate verification (test only)
python ZookeeperClient.py --tls --no-verify-ssl --server zk1.example.com:2181
```

### Error Messages

- **"Connection failed"**: Check if ZooKeeper server is running and accessible
- **"Authentication failed"**: Server may require authentication
- **"Permission denied"**: Server may have restrictive ACLs
- **"Timeout"**: Increase timeout value or check network connectivity

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the GNU General Public License v3.0 - see the [LICENSE](LICENSE) file for details.

## Disclaimer

This tool is designed for security testing and auditing purposes only. Always ensure you have proper authorization before testing any ZooKeeper server. The authors are not responsible for any misuse of this tool. 