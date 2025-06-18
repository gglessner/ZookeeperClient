#!/usr/bin/env python3
"""
ZooKeeper Security Auditor
Comprehensive security auditing and penetration testing tool for Apache ZooKeeper

Author: Garland Glessner
Email: gglessner@gmail.com

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
"""

import sys
import time
import argparse
import socket
import threading
import ssl
from concurrent.futures import ThreadPoolExecutor, as_completed
from kazoo.client import KazooClient
from kazoo.exceptions import KazooException, NoAuthException, NoNodeException, NodeExistsException
from kazoo.protocol.states import KazooState
from kazoo.security import make_digest_acl, ACL, Permissions, Id


class ZookeeperSecurityAuditor:
    def __init__(self, hosts='localhost:2181', timeout=10, use_tls=False, cert_file=None, key_file=None, ca_file=None, verify_ssl=True):
        """
        Initialize ZooKeeper security auditor
        
        Args:
            hosts (str): ZooKeeper connection string (default: localhost:2181)
            timeout (int): Connection timeout in seconds
            use_tls (bool): Enable TLS/SSL connection
            cert_file (str): Path to client certificate file
            key_file (str): Path to client private key file
            ca_file (str): Path to CA certificate file
            verify_ssl (bool): Verify SSL certificates (default: True)
        """
        self.hosts = hosts
        self.timeout = timeout
        self.use_tls = use_tls
        self.cert_file = cert_file
        self.key_file = key_file
        self.ca_file = ca_file
        self.verify_ssl = verify_ssl
        self.client = None
        self.audit_results = {
            'connection_info': {},
            'security_findings': [],
            'vulnerabilities': [],
            'data_exposure': [],
            'access_control': {}
        }
    
    def connect(self, auth_scheme=None, auth_credentials=None):
        """
        Connect to ZooKeeper server with optional authentication and TLS
        
        Args:
            auth_scheme (str): Authentication scheme (digest, sasl, etc.)
            auth_credentials (str): Authentication credentials
            
        Returns:
            bool: True if connection successful, False otherwise
        """
        try:
            print(f"Connecting to ZooKeeper at {self.hosts}...")
            
            # Configure TLS if enabled
            if self.use_tls:
                print("🔒 TLS/SSL connection enabled")
                
                # Create SSL context
                ssl_context = ssl.create_default_context()
                
                # Configure certificate verification
                if not self.verify_ssl:
                    ssl_context.check_hostname = False
                    ssl_context.verify_mode = ssl.CERT_NONE
                    print("⚠️  SSL certificate verification disabled")
                else:
                    print("✅ SSL certificate verification enabled")
                
                # Add client certificate if provided
                if self.cert_file and self.key_file:
                    try:
                        ssl_context.load_cert_chain(self.cert_file, self.key_file)
                        print(f"✅ Client certificate loaded: {self.cert_file}")
                    except Exception as e:
                        print(f"❌ Failed to load client certificate: {e}")
                        return False
                
                # Add CA certificate if provided
                if self.ca_file:
                    try:
                        ssl_context.load_verify_locations(self.ca_file)
                        print(f"✅ CA certificate loaded: {self.ca_file}")
                    except Exception as e:
                        print(f"❌ Failed to load CA certificate: {e}")
                        return False
                
                # Create client with TLS
                # Note: Kazoo doesn't directly support SSL options in constructor
                # We'll use the regular client and handle SSL in the four-letter commands
                self.client = KazooClient(
                    hosts=self.hosts, 
                    timeout=self.timeout
                )
            else:
                # Create client without TLS
                self.client = KazooClient(hosts=self.hosts, timeout=self.timeout)
            
            # Add authentication if provided
            if auth_scheme and auth_credentials:
                self.client.add_auth(auth_scheme, auth_credentials)
                print(f"Added authentication: {auth_scheme}")
            
            # Start the client
            self.client.start()
            
            # Wait for connection to be established
            self.client.ensure_path("/")
            
            print("✅ Successfully connected to ZooKeeper!")
            return True
            
        except KazooException as e:
            print(f"❌ Failed to connect to ZooKeeper: {e}")
            return False
        except Exception as e:
            print(f"❌ Unexpected error: {e}")
            return False
    
    def disconnect(self):
        """Disconnect from ZooKeeper server"""
        if self.client:
            try:
                self.client.stop()
                self.client.close()
                print("Disconnected from ZooKeeper")
            except Exception as e:
                print(f"Error during disconnect: {e}")
    
    def get_server_info(self):
        """Get comprehensive server information, trying all available methods for version/config info."""
        if not self.client:
            print("Not connected to ZooKeeper")
            return None
        
        version_info = {
            'stat': None,
            'srvr': None,
            'conf': None,
            'znode_config': None,
            'errors': {}
        }
        found_version = None

        # Helper to parse version from text
        def parse_version(text):
            import re
            if not text:
                return None
            # Look for lines like 'Zookeeper version: ...' or 'build ...'
            for line in text.splitlines():
                if 'version' in line.lower() or 'build' in line.lower():
                    return line.strip()
            return None

        # Try four-letter commands
        for cmd in ['stat', 'srvr', 'conf']:
            try:
                resp = self._get_server_stats_cmd(cmd)
                version_info[cmd] = resp
                parsed = parse_version(resp)
                if parsed and not found_version:
                    found_version = parsed
            except Exception as e:
                version_info['errors'][cmd] = str(e)

        # Try reading /zookeeper/config
        try:
            if self.client.exists("/zookeeper/config"):
                data, stat = self.client.get("/zookeeper/config")
                decoded = data.decode('utf-8', errors='replace') if data else ''
                version_info['znode_config'] = decoded
                parsed = parse_version(decoded)
                if parsed and not found_version:
                    found_version = parsed
            else:
                version_info['znode_config'] = None
        except Exception as e:
            version_info['errors']['znode_config'] = str(e)

        # Get connection state
        state = self.client.state
        print(f"Connection state: {state}")
        
        # Display version prominently if found
        if found_version:
            print(f"✅ ZooKeeper server version: {found_version}")
        else:
            print("❌ Could not determine ZooKeeper version from any method.")

        # Show detailed results in organized format
        print("\n📊 Server Information Details:")
        
        # Show successful methods first
        successful_methods = []
        for method in ['stat', 'srvr', 'conf', 'znode_config']:
            val = version_info[method]
            if val and val.strip():
                successful_methods.append(method)
        
        if successful_methods:
            print("✅ Working methods:")
            for method in successful_methods:
                val = version_info[method]
                print(f"   • {method.upper()}: {len(val)} characters")
                # Show first few lines for context
                lines = val.strip().split('\n')[:3]
                for line in lines:
                    if line.strip():
                        print(f"     {line.strip()}")
                if len(val.strip().split('\n')) > 3:
                    remaining = len(val.strip().split('\n')) - 3
                    print(f"     ... ({remaining} more lines)")
        
        # Show failed methods
        failed_methods = []
        for method in ['stat', 'srvr', 'conf', 'znode_config']:
            if method in version_info['errors']:
                failed_methods.append(method)
        
        if failed_methods:
            print("\n❌ Failed methods:")
            for method in failed_methods:
                error = version_info['errors'][method]
                print(f"   • {method.upper()}: {error}")
        
        # Show methods with no response
        no_response_methods = []
        for method in ['stat', 'srvr', 'conf', 'znode_config']:
            if method not in successful_methods and method not in failed_methods:
                no_response_methods.append(method)
        
        if no_response_methods:
            print("\n⚠️  No response from:")
            for method in no_response_methods:
                print(f"   • {method.upper()}")

        info = {
            'version': found_version or 'Unknown',
            'state': state,
            'hosts': self.hosts,
            'version_info': version_info
        }
        self.audit_results['connection_info'] = info
        return info

    def _get_server_stats_cmd(self, cmd):
        """Send a single four-letter command and return the response as text."""
        import socket
        host, port = self.hosts.split(':')
        
        if self.use_tls:
            # Use SSL socket for TLS connections
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            
            # Create SSL context for four-letter commands
            ssl_context = ssl.create_default_context()
            if not self.verify_ssl:
                ssl_context.check_hostname = False
                ssl_context.verify_mode = ssl.CERT_NONE
            
            # Add client certificate if provided
            if self.cert_file and self.key_file:
                try:
                    ssl_context.load_cert_chain(self.cert_file, self.key_file)
                except Exception as e:
                    return f"Error loading client certificate: {e}"
            
            # Add CA certificate if provided
            if self.ca_file:
                try:
                    ssl_context.load_verify_locations(self.ca_file)
                except Exception as e:
                    return f"Error loading CA certificate: {e}"
            
            # Wrap socket with SSL
            sock = ssl_context.wrap_socket(sock, server_hostname=host)
            sock.connect((host, int(port)))
        else:
            # Use regular socket for non-TLS connections
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((host, int(port)))
        
        sock.send(cmd.encode())
        response = b''
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            response += chunk
        sock.close()
        return response.decode('utf-8', errors='replace')
    
    def test_authentication_bypass(self):
        """Test for authentication bypass vulnerabilities"""
        print("\n🔍 Testing Authentication Bypass...")
        
        # Test common default credentials
        default_creds = [
            ('digest', 'admin:admin'),
            ('digest', 'zookeeper:zookeeper'),
            ('digest', 'admin:password'),
            ('digest', 'user:password'),
            ('digest', 'zk:zk'),
            ('digest', 'admin:'),
            ('digest', ':admin'),
            ('digest', ''),
        ]
        
        for scheme, creds in default_creds:
            test_client = None
            try:
                test_client = KazooClient(hosts=self.hosts, timeout=5)
                test_client.start()
                
                if creds:
                    test_client.add_auth(scheme, creds)
                
                # Try to access a protected path
                test_client.ensure_path("/")
                test_client.get_children("/")
                
                print(f"⚠️  Potential auth bypass with {scheme}:{creds}")
                self.audit_results['vulnerabilities'].append({
                    'type': 'authentication_bypass',
                    'scheme': scheme,
                    'credentials': creds,
                    'severity': 'HIGH'
                })
                
            except Exception as e:
                pass
            finally:
                # Always cleanup test client
                if test_client:
                    try:
                        test_client.stop()
                        test_client.close()
                    except:
                        pass
    
    def enumerate_acls(self, path="/", max_depth=3):
        """Enumerate ACLs on ZooKeeper nodes"""
        print(f"\n🔍 Enumerating ACLs starting from {path}...")
        
        def _enumerate_recursive(current_path, depth=0):
            if depth > max_depth:
                return
            
            try:
                # Get ACLs for current path
                acls = self.client.get_acls(current_path)[0]
                
                if acls:
                    print(f"📁 {current_path}: {len(acls)} ACLs found")
                    for acl in acls:
                        print(f"   - {acl}")
                    
                    self.audit_results['access_control'][current_path] = acls
                
                # Get children and recurse
                children = self.client.get_children(current_path)
                for child in children[:10]:  # Limit to first 10 children
                    child_path = f"{current_path}/{child}" if current_path != "/" else f"/{child}"
                    _enumerate_recursive(child_path, depth + 1)
                    
            except NoAuthException:
                print(f"🚫 No access to {current_path}")
            except NoNodeException:
                pass
            except Exception as e:
                print(f"Error enumerating {current_path}: {e}")
        
        _enumerate_recursive(path)
    
    def test_data_exposure(self, path="/", max_depth=2):
        """Test for sensitive data exposure"""
        print(f"\n🔍 Testing for Data Exposure starting from {path}...")
        
        sensitive_patterns = [
            'password', 'secret', 'key', 'token', 'credential', 'auth',
            'config', 'database', 'connection', 'url', 'endpoint',
            'private', 'internal', 'admin', 'root', 'user'
        ]
        
        def _scan_recursive(current_path, depth=0):
            if depth > max_depth:
                return
            
            try:
                # Check if node has data
                data, stat = self.client.get(current_path)
                if data and len(data) > 0:
                    data_str = data.decode('utf-8', errors='ignore')
                    
                    # Check for sensitive patterns
                    for pattern in sensitive_patterns:
                        if pattern.lower() in data_str.lower():
                            print(f"⚠️  Potential sensitive data in {current_path}: contains '{pattern}'")
                            self.audit_results['data_exposure'].append({
                                'path': current_path,
                                'pattern': pattern,
                                'data_preview': data_str[:100] + '...' if len(data_str) > 100 else data_str,
                                'severity': 'MEDIUM'
                            })
                
                # Get children and recurse
                children = self.client.get_children(current_path)
                for child in children[:5]:  # Limit to first 5 children
                    child_path = f"{current_path}/{child}" if current_path != "/" else f"/{child}"
                    _scan_recursive(child_path, depth + 1)
                    
            except NoAuthException:
                pass
            except NoNodeException:
                pass
            except Exception as e:
                pass
        
        _scan_recursive(path)
    
    def test_privilege_escalation(self):
        """Test for privilege escalation opportunities"""
        print("\n🔍 Testing Privilege Escalation...")
        
        # Test creating nodes in various locations
        test_locations = [
            "/admin", "/config", "/system", "/internal", "/security",
            "/users", "/auth", "/credentials", "/secrets"
        ]
        
        created_nodes = []  # Track created nodes for cleanup
        
        for location in test_locations:
            try:
                test_path = f"{location}/test_privilege_escalation_{int(time.time())}"
                self.client.create(test_path, b"test", makepath=True)
                created_nodes.append(test_path)
                print(f"⚠️  Can create nodes in {location}")
                
                # Try to set ACLs
                try:
                    acl = make_digest_acl("test", "test", all=True)
                    self.client.set_acls(test_path, [acl])
                    print(f"⚠️  Can set ACLs in {location}")
                except:
                    pass
                
                self.audit_results['vulnerabilities'].append({
                    'type': 'privilege_escalation',
                    'location': location,
                    'severity': 'HIGH'
                })
                
            except Exception as e:
                pass
        
        # Cleanup all created nodes
        print("\n🧹 Cleaning up test nodes...")
        for node in created_nodes:
            try:
                self.client.delete(node)
                print(f"   ✅ Cleaned up: {node}")
            except Exception as e:
                print(f"   ❌ Failed to clean up {node}: {e}")
    
    def test_information_disclosure(self):
        """Test for information disclosure vulnerabilities"""
        print("\n🔍 Testing Information Disclosure...")
        
        # Test accessing system paths
        system_paths = [
            "/zookeeper", "/zookeeper/config", "/zookeeper/quota",
            "/system", "/admin", "/internal", "/debug", "/metrics"
        ]
        
        for path in system_paths:
            try:
                if self.client.exists(path):
                    print(f"📁 System path accessible: {path}")
                    
                    # Try to get children
                    children = self.client.get_children(path)
                    if children:
                        print(f"   Children: {children}")
                    
                    # Try to get data
                    try:
                        data, stat = self.client.get(path)
                        if data:
                            print(f"   Data: {data.decode('utf-8', errors='ignore')[:100]}...")
                    except:
                        pass
                    
                    self.audit_results['security_findings'].append({
                        'type': 'information_disclosure',
                        'path': path,
                        'severity': 'MEDIUM'
                    })
                    
            except Exception as e:
                pass
    
    def read_path_recursively(self, path="/", max_depth=5, show_data=True):
        """
        Recursively read all data from a specified path
        
        Args:
            path (str): Starting path to read from
            max_depth (int): Maximum recursion depth
            show_data (bool): Whether to show node data
        """
        print(f"\n📖 Reading path recursively: {path}")
        print("=" * 60)
        
        def _read_recursive(current_path, depth=0, indent=""):
            if depth > max_depth:
                return
            
            try:
                # Check if path exists
                if not self.client.exists(current_path):
                    print(f"{indent}❌ Path does not exist: {current_path}")
                    return
                
                # Get node data
                data, stat = self.client.get(current_path)
                data_str = data.decode('utf-8', errors='replace') if data else ""
                
                # Display node info
                print(f"{indent}📁 {current_path}")
                print(f"{indent}   Size: {len(data)} bytes")
                print(f"{indent}   Children: {len(self.client.get_children(current_path))}")
                
                # Show data if requested and not empty
                if show_data and data_str.strip():
                    print(f"{indent}   Data: {data_str[:200]}{'...' if len(data_str) > 200 else ''}")
                
                # Get ACLs
                try:
                    acls = self.client.get_acls(current_path)[0]
                    if acls:
                        print(f"{indent}   ACLs: {len(acls)} found")
                        for acl in acls:
                            print(f"{indent}     - {acl}")
                except Exception as e:
                    print(f"{indent}   ACLs: Error - {e}")
                
                print()
                
                # Recursively process children
                children = self.client.get_children(current_path)
                for child in children:
                    child_path = f"{current_path}/{child}" if current_path != "/" else f"/{child}"
                    _read_recursive(child_path, depth + 1, indent + "  ")
                    
            except NoAuthException:
                print(f"{indent}🚫 No access to {current_path}")
            except NoNodeException:
                print(f"{indent}❌ Path does not exist: {current_path}")
            except Exception as e:
                print(f"{indent}❌ Error reading {current_path}: {e}")
        
        _read_recursive(path)
    
    def search_pattern_recursive(self, pattern, path="/", max_depth=5):
        """
        Search for specific patterns in node names and data
        
        Args:
            pattern (str): Regex pattern to search for
            path (str): Starting path to search from
            max_depth (int): Maximum recursion depth
        """
        import re
        
        print(f"\n🔍 Searching for pattern: '{pattern}' starting from {path}")
        print("=" * 60)
        
        # Compile regex pattern
        try:
            regex = re.compile(pattern, re.IGNORECASE)
        except re.error as e:
            print(f"❌ Invalid regex pattern: {e}")
            return
        
        matches = []
        
        def _search_recursive(current_path, depth=0):
            if depth > max_depth:
                return
            
            try:
                # Check if path exists
                if not self.client.exists(current_path):
                    return
                
                # Search in node name
                node_name = current_path.split('/')[-1] if current_path != "/" else "/"
                if regex.search(node_name):
                    matches.append({
                        'type': 'node_name',
                        'path': current_path,
                        'match': node_name,
                        'depth': depth
                    })
                
                # Get node data and search in content
                try:
                    data, stat = self.client.get(current_path)
                    if data:
                        data_str = data.decode('utf-8', errors='replace')
                        
                        # Search for pattern in data
                        data_matches = regex.findall(data_str)
                        if data_matches:
                            matches.append({
                                'type': 'node_data',
                                'path': current_path,
                                'matches': data_matches,
                                'data_preview': data_str[:200] + '...' if len(data_str) > 200 else data_str,
                                'depth': depth
                            })
                except Exception as e:
                    pass
                
                # Recursively search children
                children = self.client.get_children(current_path)
                for child in children:
                    child_path = f"{current_path}/{child}" if current_path != "/" else f"/{child}"
                    _search_recursive(child_path, depth + 1)
                    
            except NoAuthException:
                pass
            except NoNodeException:
                pass
            except Exception as e:
                pass
        
        _search_recursive(path)
        
        # Display results
        if matches:
            print(f"✅ Found {len(matches)} matches:")
            for i, match in enumerate(matches, 1):
                print(f"\n{i}. {match['type'].upper()} - {match['path']}")
                if match['type'] == 'node_name':
                    print(f"   Match: {match['match']}")
                else:
                    print(f"   Matches: {', '.join(set(match['matches']))}")
                    print(f"   Preview: {match['data_preview']}")
                print(f"   Depth: {match['depth']}")
        else:
            print("❌ No matches found")
        
        return matches
    
    def export_data_recursive(self, export_file, path="/", max_depth=10):
        """
        Export all discovered data to JSON file
        
        Args:
            export_file (str): Path to export file
            path (str): Starting path to export from
            max_depth (int): Maximum recursion depth
        """
        import json
        
        print(f"\n📤 Exporting data from {path} to {export_file}")
        print("=" * 60)
        
        exported_data = {
            'metadata': {
                'export_time': time.strftime('%Y-%m-%d %H:%M:%S'),
                'server': self.hosts,
                'starting_path': path,
                'max_depth': max_depth
            },
            'nodes': []
        }
        
        def _export_recursive(current_path, depth=0):
            if depth > max_depth:
                return
            
            try:
                # Check if path exists
                if not self.client.exists(current_path):
                    return
                
                node_data = {
                    'path': current_path,
                    'depth': depth,
                    'children': [],
                    'data': None,
                    'data_size': 0,
                    'acls': [],
                    'stat': None
                }
                
                # Get node data
                try:
                    data, stat = self.client.get(current_path)
                    if data:
                        data_str = data.decode('utf-8', errors='replace')
                        node_data['data'] = data_str
                        node_data['data_size'] = len(data)
                        node_data['stat'] = {
                            'version': stat.version,
                            'aversion': stat.aversion,
                            'ctime': stat.ctime,
                            'mtime': stat.mtime,
                            'ephemeralOwner': stat.ephemeralOwner,
                            'dataLength': stat.dataLength,
                            'numChildren': stat.numChildren,
                            'pzxid': stat.pzxid
                        }
                except Exception as e:
                    node_data['data_error'] = str(e)
                
                # Get ACLs
                try:
                    acls = self.client.get_acls(current_path)[0]
                    if acls:
                        node_data['acls'] = [str(acl) for acl in acls]
                except Exception as e:
                    node_data['acl_error'] = str(e)
                
                # Get children
                try:
                    children = self.client.get_children(current_path)
                    node_data['children'] = children
                except Exception as e:
                    node_data['children_error'] = str(e)
                
                exported_data['nodes'].append(node_data)
                
                # Recursively export children
                for child in children:
                    child_path = f"{current_path}/{child}" if current_path != "/" else f"/{child}"
                    _export_recursive(child_path, depth + 1)
                    
            except NoAuthException:
                exported_data['nodes'].append({
                    'path': current_path,
                    'depth': depth,
                    'error': 'NoAuthException - Access denied'
                })
            except NoNodeException:
                pass
            except Exception as e:
                exported_data['nodes'].append({
                    'path': current_path,
                    'depth': depth,
                    'error': str(e)
                })
        
        _export_recursive(path)
        
        # Write to file
        try:
            with open(export_file, 'w', encoding='utf-8') as f:
                json.dump(exported_data, f, indent=2, ensure_ascii=False)
            
            print(f"✅ Successfully exported {len(exported_data['nodes'])} nodes to {export_file}")
            print(f"   Total data size: {sum(node.get('data_size', 0) for node in exported_data['nodes'])} bytes")
            
        except Exception as e:
            print(f"❌ Failed to export data: {e}")
        
        return exported_data
    
    def harvest_credentials(self, path="/", max_depth=5):
        """
        Extract and display credentials, tokens, and keys from discovered data
        
        Args:
            path (str): Starting path to search from
            max_depth (int): Maximum recursion depth
        """
        import re
        
        print(f"\n🔑 Harvesting credentials from {path}")
        print("=" * 60)
        
        # Define patterns for different types of sensitive data
        patterns = {
            'passwords': [
                r'password["\s]*[:=]\s*["\']([^"\']+)["\']',
                r'passwd["\s]*[:=]\s*["\']([^"\']+)["\']',
                r'pwd["\s]*[:=]\s*["\']([^"\']+)["\']',
                r'secret["\s]*[:=]\s*["\']([^"\']+)["\']',
                r'password["\s]*[:=]\s*([^\s,}]+)',
            ],
            'api_keys': [
                r'api_key["\s]*[:=]\s*["\']([^"\']+)["\']',
                r'apikey["\s]*[:=]\s*["\']([^"\']+)["\']',
                r'key["\s]*[:=]\s*["\']([a-zA-Z0-9]{32,})["\']',
                r'token["\s]*[:=]\s*["\']([^"\']+)["\']',
                r'access_token["\s]*[:=]\s*["\']([^"\']+)["\']',
                r'jwt["\s]*[:=]\s*["\']([^"\']+)["\']',
            ],
            'urls_endpoints': [
                r'https?://[^\s"\']+',
                r'ftp://[^\s"\']+',
                r'ws://[^\s"\']+',
                r'wss://[^\s"\']+',
            ],
            'ips_addresses': [
                r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b',
                r'[0-9a-fA-F:]+:[0-9a-fA-F:]+',  # IPv6
            ],
            'domains': [
                r'\b[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.([a-zA-Z]{2,})\b',
            ],
            'private_keys': [
                r'-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----',
                r'-----BEGIN\s+DSA\s+PRIVATE\s+KEY-----',
                r'-----BEGIN\s+EC\s+PRIVATE\s+KEY-----',
                r'-----BEGIN\s+OPENSSH\s+PRIVATE\s+KEY-----',
            ],
            'certificates': [
                r'-----BEGIN\s+CERTIFICATE-----',
                r'-----BEGIN\s+X509\s+CERTIFICATE-----',
            ]
        }
        
        harvested_data = {
            'passwords': [],
            'api_keys': [],
            'urls_endpoints': [],
            'ips_addresses': [],
            'domains': [],
            'private_keys': [],
            'certificates': []
        }
        
        def _harvest_recursive(current_path, depth=0):
            if depth > max_depth:
                return
            
            try:
                # Check if path exists
                if not self.client.exists(current_path):
                    return
                
                # Get node data
                try:
                    data, stat = self.client.get(current_path)
                    if data:
                        data_str = data.decode('utf-8', errors='replace')
                        
                        # Search for each pattern type
                        for pattern_type, pattern_list in patterns.items():
                            for pattern in pattern_list:
                                matches = re.findall(pattern, data_str, re.IGNORECASE)
                                for match in matches:
                                    if isinstance(match, tuple):
                                        match = match[0]  # Extract from capture group
                                    
                                    if match and len(match) > 3:  # Filter out very short matches
                                        harvested_data[pattern_type].append({
                                            'path': current_path,
                                            'value': match,
                                            'pattern': pattern,
                                            'depth': depth
                                        })
                        
                except Exception as e:
                    pass
                
                # Recursively search children
                children = self.client.get_children(current_path)
                for child in children:
                    child_path = f"{current_path}/{child}" if current_path != "/" else f"/{child}"
                    _harvest_recursive(child_path, depth + 1)
                    
            except NoAuthException:
                pass
            except NoNodeException:
                pass
            except Exception as e:
                pass
        
        _harvest_recursive(path)
        
        # Display results
        total_found = 0
        for pattern_type, items in harvested_data.items():
            if items:
                print(f"\n🔍 {pattern_type.upper().replace('_', ' ')} ({len(items)} found):")
                for i, item in enumerate(items[:10], 1):  # Show first 10 of each type
                    print(f"   {i}. {item['path']}")
                    print(f"      Value: {item['value'][:50]}{'...' if len(item['value']) > 50 else ''}")
                    print(f"      Depth: {item['depth']}")
                if len(items) > 10:
                    print(f"   ... and {len(items) - 10} more")
                total_found += len(items)
        
        if total_found == 0:
            print("❌ No credentials or sensitive data found")
        else:
            print(f"\n✅ Total harvested items: {total_found}")
        
        return harvested_data
    
    def analyze_configurations(self, path="/", max_depth=5):
        """
        Analyze configuration patterns and extract service endpoints, IPs, and domains
        
        Args:
            path (str): Starting path to analyze from
            max_depth (int): Maximum recursion depth
        """
        import re
        import json
        
        print(f"\n🔧 Analyzing configurations from {path}")
        print("=" * 60)
        
        analysis_results = {
            'services': {},
            'endpoints': [],
            'databases': [],
            'external_services': [],
            'internal_services': [],
            'configuration_files': [],
            'environment_variables': [],
            'ports': [],
            'protocols': []
        }
        
        # Common service patterns
        service_patterns = {
            'kafka': [r'kafka', r'broker', r'topic'],
            'hadoop': [r'hadoop', r'hdfs', r'yarn', r'mapreduce'],
            'elasticsearch': [r'elasticsearch', r'elastic', r'kibana', r'logstash'],
            'spark': [r'spark', r'spark-submit', r'spark-shell'],
            'zookeeper': [r'zookeeper', r'zk'],
            'redis': [r'redis', r'redisson'],
            'mysql': [r'mysql', r'mariadb'],
            'postgresql': [r'postgres', r'postgresql', r'psql'],
            'mongodb': [r'mongo', r'mongodb'],
            'rabbitmq': [r'rabbitmq', r'amqp'],
            'nginx': [r'nginx'],
            'apache': [r'apache', r'httpd'],
            'tomcat': [r'tomcat', r'catalina'],
            'jenkins': [r'jenkins'],
            'kubernetes': [r'kubernetes', r'k8s', r'kube'],
            'docker': [r'docker', r'container'],
            'consul': [r'consul'],
            'etcd': [r'etcd'],
            'vault': [r'vault']
        }
        
        # Configuration file patterns
        config_patterns = [
            r'\.(yml|yaml|json|properties|conf|config|ini|xml|toml)$',
            r'application\.(yml|yaml|properties)',
            r'logback\.xml',
            r'log4j\.properties',
            r'\.env',
            r'config\.(js|ts|py|java)'
        ]
        
        def _analyze_recursive(current_path, depth=0):
            if depth > max_depth:
                return
            
            try:
                # Check if path exists
                if not self.client.exists(current_path):
                    return
                
                # Analyze node name
                node_name = current_path.split('/')[-1] if current_path != "/" else "/"
                
                # Check for configuration files
                for pattern in config_patterns:
                    if re.search(pattern, node_name, re.IGNORECASE):
                        analysis_results['configuration_files'].append({
                            'path': current_path,
                            'type': pattern,
                            'depth': depth
                        })
                        break
                
                # Get node data
                try:
                    data, stat = self.client.get(current_path)
                    if data:
                        data_str = data.decode('utf-8', errors='replace')
                        
                        # Analyze for services
                        for service_name, patterns in service_patterns.items():
                            for pattern in patterns:
                                if re.search(pattern, data_str, re.IGNORECASE):
                                    if service_name not in analysis_results['services']:
                                        analysis_results['services'][service_name] = []
                                    analysis_results['services'][service_name].append({
                                        'path': current_path,
                                        'depth': depth,
                                        'context': data_str[:200] + '...' if len(data_str) > 200 else data_str
                                    })
                                    break
                        
                        # Extract endpoints
                        endpoint_patterns = [
                            r'https?://[^\s"\']+',
                            r'ws://[^\s"\']+',
                            r'wss://[^\s"\']+',
                            r'ftp://[^\s"\']+',
                            r'tcp://[^\s"\']+',
                            r'udp://[^\s"\']+'
                        ]
                        
                        for pattern in endpoint_patterns:
                            matches = re.findall(pattern, data_str, re.IGNORECASE)
                            for match in matches:
                                analysis_results['endpoints'].append({
                                    'url': match,
                                    'path': current_path,
                                    'depth': depth
                                })
                        
                        # Extract database connections
                        db_patterns = [
                            r'jdbc:[^"\s]+',
                            r'mongodb://[^"\s]+',
                            r'redis://[^"\s]+',
                            r'postgresql://[^"\s]+',
                            r'mysql://[^"\s]+'
                        ]
                        
                        for pattern in db_patterns:
                            matches = re.findall(pattern, data_str, re.IGNORECASE)
                            for match in matches:
                                analysis_results['databases'].append({
                                    'connection': match,
                                    'path': current_path,
                                    'depth': depth
                                })
                        
                        # Extract IP addresses
                        ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
                        ips = re.findall(ip_pattern, data_str)
                        for ip in ips:
                            if ip not in ['127.0.0.1', 'localhost', '0.0.0.0']:
                                analysis_results['external_services'].append({
                                    'ip': ip,
                                    'path': current_path,
                                    'depth': depth
                                })
                        
                        # Extract ports
                        port_pattern = r':(\d{1,5})\b'
                        ports = re.findall(port_pattern, data_str)
                        for port in ports:
                            if port not in analysis_results['ports']:
                                analysis_results['ports'].append(port)
                        
                        # Extract environment variables
                        env_pattern = r'\$\{([^}]+)\}'
                        env_vars = re.findall(env_pattern, data_str)
                        for env_var in env_vars:
                            if env_var not in analysis_results['environment_variables']:
                                analysis_results['environment_variables'].append(env_var)
                        
                        # Try to parse as JSON/YAML for deeper analysis
                        try:
                            if data_str.strip().startswith('{'):
                                json_data = json.loads(data_str)
                                self._analyze_json_config(json_data, current_path, depth, analysis_results)
                        except:
                            pass
                        
                except Exception as e:
                    pass
                
                # Recursively analyze children
                children = self.client.get_children(current_path)
                for child in children:
                    child_path = f"{current_path}/{child}" if current_path != "/" else f"/{child}"
                    _analyze_recursive(child_path, depth + 1)
                    
            except NoAuthException:
                pass
            except NoNodeException:
                pass
            except Exception as e:
                pass
        
        _analyze_recursive(path)
        
        # Display results
        print(f"\n📊 Configuration Analysis Results:")
        
        if analysis_results['services']:
            print(f"\n🔧 Services Found:")
            for service, instances in analysis_results['services'].items():
                print(f"   • {service.upper()}: {len(instances)} instances")
                for instance in instances[:3]:  # Show first 3
                    print(f"     - {instance['path']}")
        
        if analysis_results['endpoints']:
            print(f"\n🌐 Endpoints ({len(analysis_results['endpoints'])} found):")
            for endpoint in analysis_results['endpoints'][:10]:  # Show first 10
                print(f"   • {endpoint['url']} (from {endpoint['path']})")
        
        if analysis_results['databases']:
            print(f"\n🗄️  Database Connections ({len(analysis_results['databases'])} found):")
            for db in analysis_results['databases'][:5]:  # Show first 5
                print(f"   • {db['connection']} (from {db['path']})")
        
        if analysis_results['configuration_files']:
            print(f"\n📄 Configuration Files ({len(analysis_results['configuration_files'])} found):")
            for config in analysis_results['configuration_files'][:10]:  # Show first 10
                print(f"   • {config['path']} ({config['type']})")
        
        if analysis_results['ports']:
            print(f"\n🔌 Ports Found: {', '.join(sorted(analysis_results['ports']))}")
        
        if analysis_results['environment_variables']:
            print(f"\n🔧 Environment Variables ({len(analysis_results['environment_variables'])} found):")
            for env_var in analysis_results['environment_variables'][:10]:  # Show first 10
                print(f"   • ${env_var}")
        
        return analysis_results
    
    def _analyze_json_config(self, json_data, path, depth, analysis_results):
        """Helper method to analyze JSON configuration data"""
        if isinstance(json_data, dict):
            for key, value in json_data.items():
                if isinstance(value, str):
                    # Check for URLs in string values
                    if 'http' in value.lower() or '://' in value:
                        analysis_results['endpoints'].append({
                            'url': value,
                            'path': path,
                            'depth': depth,
                            'key': key
                        })
                elif isinstance(value, dict):
                    self._analyze_json_config(value, path, depth, analysis_results)
    
    def deep_scan(self, path="/", max_depth=10):
        """
        Perform deep recursive scanning with increased depth and comprehensive coverage
        
        Args:
            path (str): Starting path to scan from
            max_depth (int): Maximum recursion depth (default: 10 for deep scan)
        """
        import re
        
        print(f"\n🔍 Performing Deep Scan from {path} (max depth: {max_depth})")
        print("=" * 60)
        
        scan_results = {
            'total_nodes': 0,
            'accessible_nodes': 0,
            'data_nodes': 0,
            'empty_nodes': 0,
            'large_nodes': [],
            'interesting_paths': [],
            'error_nodes': [],
            'acl_summary': {},
            'data_summary': {
                'total_size': 0,
                'largest_node': None,
                'average_size': 0
            }
        }
        
        def _deep_scan_recursive(current_path, depth=0):
            if depth > max_depth:
                return
            
            try:
                # Check if path exists
                if not self.client.exists(current_path):
                    return
                
                scan_results['total_nodes'] += 1
                scan_results['accessible_nodes'] += 1
                
                # Get node data
                try:
                    data, stat = self.client.get(current_path)
                    data_size = len(data) if data else 0
                    
                    if data_size > 0:
                        scan_results['data_nodes'] += 1
                        scan_results['data_summary']['total_size'] += data_size
                        
                        # Track large nodes
                        if data_size > 1024:  # Nodes larger than 1KB
                            scan_results['large_nodes'].append({
                                'path': current_path,
                                'size': data_size,
                                'depth': depth
                            })
                        
                        # Track largest node
                        if not scan_results['data_summary']['largest_node'] or \
                           data_size > scan_results['data_summary']['largest_node']['size']:
                            scan_results['data_summary']['largest_node'] = {
                                'path': current_path,
                                'size': data_size
                            }
                    else:
                        scan_results['empty_nodes'] += 1
                    
                    # Check for interesting paths
                    interesting_patterns = [
                        r'config', r'settings', r'properties', r'secrets',
                        r'password', r'credential', r'token', r'key',
                        r'database', r'connection', r'endpoint', r'url',
                        r'admin', r'root', r'user', r'auth',
                        r'api', r'service', r'microservice',
                        r'prod', r'production', r'dev', r'development',
                        r'test', r'staging', r'qa'
                    ]
                    
                    for pattern in interesting_patterns:
                        if re.search(pattern, current_path, re.IGNORECASE):
                            scan_results['interesting_paths'].append({
                                'path': current_path,
                                'pattern': pattern,
                                'depth': depth,
                                'size': data_size
                            })
                            break
                    
                except Exception as e:
                    scan_results['error_nodes'].append({
                        'path': current_path,
                        'error': str(e),
                        'depth': depth
                    })
                
                # Get ACLs
                try:
                    acls = self.client.get_acls(current_path)[0]
                    if acls:
                        acl_str = str(acls)
                        if acl_str not in scan_results['acl_summary']:
                            scan_results['acl_summary'][acl_str] = []
                        scan_results['acl_summary'][acl_str].append(current_path)
                except Exception as e:
                    pass
                
                # Recursively scan children
                children = self.client.get_children(current_path)
                for child in children:
                    child_path = f"{current_path}/{child}" if current_path != "/" else f"/{child}"
                    _deep_scan_recursive(child_path, depth + 1)
                    
            except NoAuthException:
                scan_results['error_nodes'].append({
                    'path': current_path,
                    'error': 'NoAuthException - Access denied',
                    'depth': depth
                })
            except NoNodeException:
                pass
            except Exception as e:
                scan_results['error_nodes'].append({
                    'path': current_path,
                    'error': str(e),
                    'depth': depth
                })
        
        _deep_scan_recursive(path)
        
        # Calculate averages
        if scan_results['data_nodes'] > 0:
            scan_results['data_summary']['average_size'] = scan_results['data_summary']['total_size'] / scan_results['data_nodes']
        
        # Display results
        print(f"\n📊 Deep Scan Results:")
        print(f"   Total nodes discovered: {scan_results['total_nodes']}")
        print(f"   Accessible nodes: {scan_results['accessible_nodes']}")
        print(f"   Nodes with data: {scan_results['data_nodes']}")
        print(f"   Empty nodes: {scan_results['empty_nodes']}")
        print(f"   Error nodes: {len(scan_results['error_nodes'])}")
        
        print(f"\n📈 Data Summary:")
        print(f"   Total data size: {scan_results['data_summary']['total_size']} bytes")
        if scan_results['data_summary']['largest_node']:
            print(f"   Largest node: {scan_results['data_summary']['largest_node']['path']} ({scan_results['data_summary']['largest_node']['size']} bytes)")
        print(f"   Average node size: {scan_results['data_summary']['average_size']:.1f} bytes")
        
        if scan_results['large_nodes']:
            print(f"\n📦 Large Nodes (>1KB):")
            for node in sorted(scan_results['large_nodes'], key=lambda x: x['size'], reverse=True)[:10]:
                print(f"   • {node['path']} ({node['size']} bytes, depth: {node['depth']})")
        
        if scan_results['interesting_paths']:
            print(f"\n🎯 Interesting Paths:")
            for path_info in scan_results['interesting_paths'][:15]:
                print(f"   • {path_info['path']} (matches: {path_info['pattern']}, size: {path_info['size']} bytes)")
        
        if scan_results['acl_summary']:
            print(f"\n🔐 ACL Patterns:")
            for acl_pattern, paths in scan_results['acl_summary'].items():
                print(f"   • {acl_pattern[:50]}{'...' if len(acl_pattern) > 50 else ''} ({len(paths)} nodes)")
        
        if scan_results['error_nodes']:
            print(f"\n❌ Error Nodes:")
            for error_node in scan_results['error_nodes'][:10]:
                print(f"   • {error_node['path']}: {error_node['error']}")
        
        return scan_results
    
    def cleanup_test_artifacts(self):
        """Clean up any test artifacts that might have been left behind"""
        print("\n🧹 Cleaning up any remaining test artifacts...")
        
        # Clean up any test nodes that might have been created
        test_patterns = [
            "/test_privilege_escalation_",
            "/test_node_",
            "/auth_test_",
            "/dos_test_"
        ]
        
        cleaned_count = 0
        for pattern in test_patterns:
            try:
                # Search for nodes matching the pattern
                if self.client.exists("/"):
                    children = self.client.get_children("/")
                    for child in children:
                        if pattern in child:
                            try:
                                test_path = f"/{child}"
                                self.client.delete(test_path)
                                print(f"   ✅ Cleaned up: {test_path}")
                                cleaned_count += 1
                            except Exception as e:
                                print(f"   ❌ Failed to clean up {test_path}: {e}")
            except Exception as e:
                pass
        
        if cleaned_count == 0:
            print("   ✅ No test artifacts found to clean up")
        else:
            print(f"   ✅ Cleaned up {cleaned_count} test artifacts")
    
    def run_comprehensive_audit(self):
        """Run comprehensive security audit"""
        print("\n🚀 Starting Comprehensive Security Audit...")
        
        # Basic connection and info
        self.get_server_info()
        
        # Security tests
        self.test_authentication_bypass()
        self.enumerate_acls()
        self.test_data_exposure()
        self.test_privilege_escalation()
        self.test_information_disclosure()
        
        # Generate report
        self.generate_audit_report()
    
    def generate_audit_report(self):
        """Generate comprehensive audit report"""
        print("\n" + "="*60)
        print("🔒 ZOOKEEPER SECURITY AUDIT REPORT")
        print("="*60)
        
        # Connection Information
        print(f"\n📡 CONNECTION INFORMATION:")
        print(f"   Server: {self.audit_results['connection_info'].get('hosts', 'Unknown')}")
        print(f"   Version: {self.audit_results['connection_info'].get('version', 'Unknown')}")
        print(f"   State: {self.audit_results['connection_info'].get('state', 'Unknown')}")
        
        # Vulnerabilities
        if self.audit_results['vulnerabilities']:
            print(f"\n🚨 VULNERABILITIES FOUND ({len(self.audit_results['vulnerabilities'])}):")
            for vuln in self.audit_results['vulnerabilities']:
                print(f"   [{vuln['severity']}] {vuln['type']}")
                if 'location' in vuln:
                    print(f"       Location: {vuln['location']}")
                if 'scheme' in vuln:
                    print(f"       Auth: {vuln['scheme']}:{vuln['credentials']}")
        else:
            print(f"\n✅ No critical vulnerabilities found")
        
        # Security Findings
        if self.audit_results['security_findings']:
            print(f"\n⚠️  SECURITY FINDINGS ({len(self.audit_results['security_findings'])}):")
            for finding in self.audit_results['security_findings']:
                print(f"   [{finding['severity']}] {finding['type']}")
                if 'path' in finding:
                    print(f"       Path: {finding['path']}")
        
        # Data Exposure
        if self.audit_results['data_exposure']:
            print(f"\n📊 DATA EXPOSURE ({len(self.audit_results['data_exposure'])}):")
            for exposure in self.audit_results['data_exposure']:
                print(f"   [{exposure['severity']}] {exposure['path']}")
                print(f"       Pattern: {exposure['pattern']}")
                print(f"       Preview: {exposure['data_preview']}")
        
        # Access Control Summary
        if self.audit_results['access_control']:
            print(f"\n🔐 ACCESS CONTROL SUMMARY:")
            for path, acls in self.audit_results['access_control'].items():
                print(f"   {path}: {len(acls)} ACLs")
        
        print("\n" + "="*60)
        print("Audit completed successfully!")
        print("="*60)


def parse_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description="ZooKeeper Security Auditor - Comprehensive security testing tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python ZookeeperClient.py                           # Basic connection test
  python ZookeeperClient.py --audit                   # Run comprehensive security audit
  python ZookeeperClient.py --server zk1.example.com:2181 --audit  # Audit specific server
  python ZookeeperClient.py --auth-bypass             # Test authentication bypass
  python ZookeeperClient.py --enumerate-acls          # Enumerate ACLs
  python ZookeeperClient.py --data-exposure           # Test for data exposure
  python ZookeeperClient.py --read-path /config       # Read all data from /config path
  
  # Data Discovery & Analysis:
  python ZookeeperClient.py --search-pattern "database|password|secret"  # Search for patterns
  python ZookeeperClient.py --export-data zk_data.json                   # Export all data to JSON
  python ZookeeperClient.py --harvest-creds                              # Extract credentials and tokens
  python ZookeeperClient.py --analyze-configs                            # Analyze configuration patterns
  python ZookeeperClient.py --deep-scan                                  # Deep comprehensive scanning
  
  # TLS/SSL Examples:
  python ZookeeperClient.py --tls --server zk1.example.com:2281  # TLS connection
  python ZookeeperClient.py --tls --cert-file client.pem --key-file client.key --server zk1.example.com:2281  # TLS with client cert
  python ZookeeperClient.py --tls --ca-file ca.pem --server zk1.example.com:2281  # TLS with CA cert
  python ZookeeperClient.py --tls --no-verify-ssl --server zk1.example.com:2281  # TLS without cert verification
        """
    )
    
    parser.add_argument(
        '--server', '-s',
        default='localhost:2181',
        help='ZooKeeper server:port (default: localhost:2181)'
    )
    
    parser.add_argument(
        '--audit', '-a',
        action='store_true',
        help='Run comprehensive security audit'
    )
    
    parser.add_argument(
        '--auth-bypass', '-b',
        action='store_true',
        help='Test authentication bypass vulnerabilities'
    )
    
    parser.add_argument(
        '--enumerate-acls', '-e',
        action='store_true',
        help='Enumerate ACLs on nodes'
    )
    
    parser.add_argument(
        '--data-exposure', '-d',
        action='store_true',
        help='Test for sensitive data exposure'
    )
    
    parser.add_argument(
        '--privilege-escalation', '-p',
        action='store_true',
        help='Test privilege escalation opportunities'
    )
    
    parser.add_argument(
        '--info-disclosure', '-i',
        action='store_true',
        help='Test information disclosure vulnerabilities'
    )
    
    parser.add_argument(
        '--read-path',
        metavar='PATH',
        help='Recursively read all data from specified path (e.g., /config)'
    )
    
    parser.add_argument(
        '--timeout',
        type=int,
        default=10,
        help='Connection timeout in seconds (default: 10)'
    )
    
    # TLS/SSL Options
    parser.add_argument(
        '--tls',
        action='store_true',
        help='Enable TLS/SSL connection'
    )
    
    parser.add_argument(
        '--cert-file',
        metavar='FILE',
        help='Path to client certificate file (PEM format)'
    )
    
    parser.add_argument(
        '--key-file',
        metavar='FILE',
        help='Path to client private key file (PEM format)'
    )
    
    parser.add_argument(
        '--ca-file',
        metavar='FILE',
        help='Path to CA certificate file (PEM format)'
    )
    
    parser.add_argument(
        '--no-verify-ssl',
        action='store_true',
        help='Disable SSL certificate verification (not recommended for production)'
    )
    
    # Data Discovery & Analysis Options
    parser.add_argument(
        '--search-pattern',
        metavar='PATTERN',
        help='Search for specific patterns in node names and data (e.g., "database|password|secret")'
    )
    
    parser.add_argument(
        '--export-data',
        metavar='FILE',
        help='Export all discovered data to specified file (JSON format)'
    )
    
    parser.add_argument(
        '--harvest-creds',
        action='store_true',
        help='Extract and display credentials, tokens, and keys from discovered data'
    )
    
    parser.add_argument(
        '--analyze-configs',
        action='store_true',
        help='Analyze configuration patterns and extract service endpoints, IPs, and domains'
    )
    
    parser.add_argument(
        '--deep-scan',
        action='store_true',
        help='Perform deep recursive scanning with increased depth and comprehensive coverage'
    )
    
    return parser.parse_args()


def main():
    """Main function for ZooKeeper security auditing"""
    print("=== ZooKeeper Security Auditor ===")
    
    # Parse command line arguments
    args = parse_arguments()
    
    # Create auditor with TLS configuration
    auditor = ZookeeperSecurityAuditor(
        hosts=args.server,
        timeout=args.timeout,
        use_tls=args.tls,
        cert_file=args.cert_file,
        key_file=args.key_file,
        ca_file=args.ca_file,
        verify_ssl=not args.no_verify_ssl
    )
    
    try:
        # Connect to ZooKeeper
        if auditor.connect():
            # Get basic server information
            auditor.get_server_info()
            
            # Run specific security tests based on flags
            if args.auth_bypass:
                auditor.test_authentication_bypass()
            
            if args.enumerate_acls:
                auditor.enumerate_acls()
            
            if args.data_exposure:
                auditor.test_data_exposure()
            
            if args.privilege_escalation:
                auditor.test_privilege_escalation()
            
            if args.info_disclosure:
                auditor.test_information_disclosure()
            
            # Run path reading if requested
            if args.read_path:
                auditor.read_path_recursively(args.read_path)
            
            # Run new data discovery features
            if args.search_pattern:
                auditor.search_pattern_recursive(args.search_pattern)
            
            if args.export_data:
                auditor.export_data_recursive(args.export_data)
            
            if args.harvest_creds:
                auditor.harvest_credentials()
            
            if args.analyze_configs:
                auditor.analyze_configurations()
            
            if args.deep_scan:
                auditor.deep_scan()
            
            # Run comprehensive audit if requested
            if args.audit:
                auditor.run_comprehensive_audit()
            elif not any([args.auth_bypass, args.enumerate_acls, args.data_exposure, 
                         args.privilege_escalation, args.info_disclosure, args.read_path,
                         args.search_pattern, args.export_data, args.harvest_creds,
                         args.analyze_configs, args.deep_scan]):
                print("\n✅ ZooKeeper connection validated!")
                print("   Use --audit for comprehensive security testing")
                print("   Use --help for specific test options")
            
            # Clean up test artifacts
            auditor.cleanup_test_artifacts()
            
        else:
            print("\n❌ Failed to connect to ZooKeeper")
            sys.exit(1)
            
    except KeyboardInterrupt:
        print("\nInterrupted by user")
    finally:
        # Always disconnect
        auditor.disconnect()


if __name__ == "__main__":
    main() 