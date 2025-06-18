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
- **Comprehensive Reporting**: Generates detailed security audit reports
- **Automatic Cleanup**: All tests clean up after themselves, leaving no artifacts

### 🛡️ Production-Safe Design
- **No DoS Testing**: Removed all denial-of-service functionality for production safety
- **Automatic Cleanup**: All test nodes and artifacts are automatically removed
- **Non-Destructive**: Tests are designed to be safe for production environments
- **No authentication or encryption required** for testing
- **Identifies common ZooKeeper security misconfigurations**
- **Tests for data exposure and access control issues**

## Prerequisites

- Python 3.6 or higher
- Apache ZooKeeper server running (default: localhost:2181)
- Network access to ZooKeeper server

## Installation

1. Install the required dependencies:
```bash
pip install -r requirements.txt
```

## Usage

### Basic Connection Test

Test basic connectivity to ZooKeeper:
```bash
python ZookeeperClient.py
```

### Comprehensive Security Audit

Run all security tests:
```bash
python ZookeeperClient.py --audit
```

### Individual Security Tests

Test specific security aspects:

```bash
# Test authentication bypass vulnerabilities
python ZookeeperClient.py --auth-bypass

# Enumerate ACLs on nodes
python ZookeeperClient.py --enumerate-acls

# Scan for sensitive data exposure
python ZookeeperClient.py --data-exposure

# Test privilege escalation opportunities
python ZookeeperClient.py --privilege-escalation

# Test information disclosure
python ZookeeperClient.py --info-disclosure
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
# Basic TLS connection (default port 2281)
python ZookeeperClient.py --tls --server zk1.example.com:2281

# TLS with client certificate authentication
python ZookeeperClient.py --tls --cert-file client.pem --key-file client.key --server zk1.example.com:2281

# TLS with CA certificate verification
python ZookeeperClient.py --tls --ca-file ca.pem --server zk1.example.com:2281

# TLS without certificate verification (not recommended for production)
python ZookeeperClient.py --tls --no-verify-ssl --server zk1.example.com:2281

# Comprehensive audit with TLS
python ZookeeperClient.py --tls --cert-file client.pem --key-file client.key --ca-file ca.pem --server zk1.example.com:2281 --audit
```

### Quick Connection Test

Simple connectivity test without security scanning:
```bash
python test_connection.py
```

With TLS:
```bash
python test_connection.py --tls --server zk1.example.com:2281
```

## Command Line Options

| Option | Short | Description |
|--------|-------|-------------|
| `--server` | `-s` | ZooKeeper server:port (default: localhost:2181) |
| `--audit` | `-a` | Run comprehensive security audit |
| `--auth-bypass` | `-b` | Test authentication bypass vulnerabilities |
| `--enumerate-acls` | `-e` | Enumerate ACLs on nodes |
| `--data-exposure` | `-d` | Test for sensitive data exposure |
| `--privilege-escalation` | `-p` | Test privilege escalation opportunities |
| `--info-disclosure` | `-i` | Test information disclosure vulnerabilities |
| `--read-path` | | Recursively read all data from specified path |
| `--timeout` | | Connection timeout in seconds (default: 10) |
| `--tls` | | Enable TLS/SSL connection |
| `--cert-file` | | Path to client certificate file (PEM format) |
| `--key-file` | | Path to client private key file (PEM format) |
| `--ca-file` | | Path to CA certificate file (PEM format) |
| `--no-verify-ssl` | | Disable SSL certificate verification (not recommended) |
| `--search-pattern` | | Search for specific patterns in node names and data |
| `--export-data` | | Export all discovered data to JSON file |
| `--harvest-creds` | | Extract credentials, tokens, and keys from data |
| `--analyze-configs` | | Analyze configuration patterns and extract endpoints |
| `--deep-scan` | | Perform deep recursive scanning with comprehensive coverage |

## Security Tests Explained

### Authentication Bypass Testing
Tests common default credentials and authentication schemes:
- `admin:admin`, `zookeeper:zookeeper`, `admin:password`
- Empty credentials and various authentication schemes
- Identifies weak or default authentication configurations

### ACL Enumeration
Recursively discovers Access Control Lists on ZooKeeper nodes:
- Maps out permission structures
- Identifies overly permissive ACLs
- Finds nodes with no access controls

### Data Exposure Scanning
Scans for sensitive data patterns in node values:
- Passwords, secrets, keys, tokens
- Configuration data, database connections
- Internal endpoints and credentials

### Privilege Escalation Testing
Tests ability to create/modify nodes in sensitive locations:
- `/admin`, `/config`, `/system`, `/internal`
- `/security`, `/users`, `/auth`, `/credentials`
- Tests ACL modification capabilities
- **Automatically cleans up all test nodes**

### Information Disclosure Testing
Tests access to system and internal paths:
- `/zookeeper`, `/zookeeper/config`
- `/system`, `/admin`, `/internal`
- `/debug`, `/metrics`

## Data Discovery & Analysis Features

### 🔍 Pattern-Based Data Hunting
- **Regex pattern matching** in node names and data content
- **Flexible search patterns** for specific data types
- **Case-insensitive searching** for comprehensive coverage
- **Depth-controlled scanning** to manage performance

### 📤 Data Export & Analysis
- **Complete data export** to JSON format with metadata
- **Structured output** including ACLs, statistics, and node information
- **Error handling** for inaccessible nodes
- **Comprehensive coverage** of all accessible data

### 🔑 Credential Harvesting
- **Password extraction** from configuration data
- **API key discovery** and token identification
- **Private key detection** (RSA, DSA, EC, OpenSSH)
- **Certificate identification** (X.509, PEM formats)
- **URL and endpoint extraction** from configuration data
- **IP address and domain discovery**

### 🔧 Configuration Analysis
- **Service identification** (Kafka, Hadoop, Elasticsearch, etc.)
- **Database connection extraction** (JDBC, MongoDB, Redis, etc.)
- **Endpoint discovery** (HTTP, WebSocket, FTP, etc.)
- **Environment variable detection**
- **Port and protocol identification**
- **JSON/YAML configuration parsing**

### 🔍 Deep Scanning
- **Comprehensive node enumeration** with increased depth
- **Data size analysis** and large node identification
- **Interesting path detection** based on naming patterns
- **ACL pattern analysis** across all nodes
- **Error tracking** and access issue identification
- **Statistical reporting** of discovered data

## TLS/SSL Security Features

### 🔒 Secure Connection Support
- **TLS/SSL encryption** for secure communication
- **Client certificate authentication** for mutual TLS
- **CA certificate verification** for server authentication
- **Configurable certificate verification** for testing environments

### 📜 Certificate Requirements
- **Client certificates**: PEM format with private key
- **CA certificates**: PEM format for server verification
- **Certificate chains**: Supported for complex PKI setups
- **Key formats**: RSA and ECDSA keys supported

### 🛡️ TLS Security Best Practices
- **Always verify SSL certificates** in production environments
- **Use strong cipher suites** (automatically selected by Python SSL)
- **Keep certificates and keys secure** with appropriate file permissions
- **Regular certificate rotation** for enhanced security
- **Monitor certificate expiration** to prevent connection failures

## Production Safety Features

### 🧹 Automatic Cleanup
- All test nodes are automatically created with unique timestamps
- Test nodes are immediately deleted after testing
- Cleanup runs even if tests fail or are interrupted
- No artifacts left behind in production environments

### 🚫 No DoS Testing
- Removed all denial-of-service functionality
- No rapid node creation tests
- No resource exhaustion scenarios
- Safe for production environments

### 🔒 Non-Destructive Operations
- Tests are read-only where possible
- Write operations are minimal and temporary
- All changes are reverted automatically
- Designed for security assessment, not exploitation

## Sample Output

### Comprehensive Audit Report
```
=== ZooKeeper Security Auditor ===
Connecting to ZooKeeper at localhost:2181...
✅ Successfully connected to ZooKeeper!
ZooKeeper server version: 3.9.3-${mvngit.commit.id}, built on 2024-10-24 22:44 UTC

🚀 Starting Comprehensive Security Audit...

🔍 Testing Authentication Bypass...
⚠️  Potential auth bypass with digest:admin:admin

🔍 Enumerating ACLs starting from /...
📁 /config: 2 ACLs found
   - ACL(perms=31, acl_list=['ALL'], id=Id(scheme='world', id='anyone'))

🔍 Testing for Data Exposure starting from /...
⚠️  Potential sensitive data in /config/database: contains 'password'

🔍 Testing Privilege Escalation...
⚠️  Can create nodes in /admin
🧹 Cleaning up test nodes...
   ✅ Cleaned up: /admin/test_privilege_escalation_1234567890

🔍 Testing Information Disclosure...
📁 System path accessible: /zookeeper

🧹 Cleaning up any remaining test artifacts...
   ✅ No test artifacts found to clean up

============================================================
🔒 ZOOKEEPER SECURITY AUDIT REPORT
============================================================

📡 CONNECTION INFORMATION:
   Server: localhost:2181
   Version: 3.9.3-${mvngit.commit.id}, built on 2024-10-24 22:44 UTC
   State: CONNECTED

🚨 VULNERABILITIES FOUND (2):
   [HIGH] authentication_bypass
       Auth: digest:admin:admin
   [HIGH] privilege_escalation
       Location: /admin

⚠️  SECURITY FINDINGS (1):
   [MEDIUM] information_disclosure
       Path: /zookeeper

📊 DATA EXPOSURE (1):
   [MEDIUM] /config/database
       Pattern: password
       Preview: {"host": "db.example.com", "password": "secret123", "user": "admin"}...

🔐 ACCESS CONTROL SUMMARY:
   /config: 2 ACLs

============================================================
Audit completed successfully!
============================================================
```

## Security Considerations

### Legal and Ethical Use
- Only use this tool on systems you own or have explicit permission to test
- Follow responsible disclosure practices
- Comply with applicable laws and regulations

### Production Environment Safety
- **All tests are designed to be production-safe**
- **Automatic cleanup ensures no artifacts remain**
- **No DoS or destructive testing included**
- Monitor system resources during testing

### Common Findings
- **Weak Authentication**: Default credentials or no authentication
- **Overly Permissive ACLs**: World-readable or world-writable nodes
- **Data Exposure**: Sensitive configuration data stored in plain text
- **Information Disclosure**: Access to system paths and metrics
- **Privilege Escalation**: Ability to create nodes in sensitive locations

## Troubleshooting

### Connection Issues
- Verify ZooKeeper server is running and accessible
- Check firewall settings and network connectivity
- Ensure correct server:port format

### Permission Errors
- Some tests may fail due to legitimate access controls
- This is expected behavior and indicates proper security

### Timeout Issues
- Increase timeout value for slow networks: `--timeout 30`
- Check network latency and server performance

### Cleanup Issues
- If cleanup fails, manually remove any test nodes with patterns:
  - `/test_privilege_escalation_*`
  - `/test_node_*`
  - `/auth_test_*`

## Dependencies

- `kazoo==2.8.0` - Python client for Apache ZooKeeper

## Contributing

This tool is designed for security professionals. Contributions should focus on:
- Additional security test vectors
- Improved detection capabilities
- Better reporting and output formatting
- Performance optimizations
- **Production safety improvements**

## Disclaimer

This tool is for security auditing and penetration testing purposes only. Users are responsible for ensuring they have proper authorization before testing any systems. The authors are not responsible for any misuse of this tool. **This tool is designed to be production-safe with automatic cleanup, but always test in a controlled environment first.** 