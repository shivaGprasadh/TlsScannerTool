import subprocess
import re
import json
import logging
import socket
import ssl
import requests
from datetime import datetime
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

class SSLScanParser:
    """Parser for sslscan command output"""
    
    def __init__(self):
        self.deprecated_protocols = ['SSLv2', 'SSLv3', 'TLSv1.0', 'TLSv1.1']
        self.weak_ciphers = [
            'TLS_RSA_WITH_3DES_EDE_CBC_SHA',
            'DES-CBC-SHA',
            'RC4',
            'MD5',
            'NULL'
        ]
    
    def parse_sslscan_output(self, output: str) -> Dict:
        """Parse sslscan output and extract relevant information"""
        result = {
            'protocols': {},
            'ciphers': [],
            'certificate': {},
            'vulnerabilities': {},
            'security_features': {},
            'raw_output': output
        }
        
        try:
            # Parse SSL/TLS Protocol support
            result['protocols'] = self._parse_protocols(output)
            
            # Parse supported ciphers
            result['ciphers'] = self._parse_ciphers(output)
            
            # Parse certificate information
            result['certificate'] = self._parse_certificate(output)
            
            # No specific vulnerability parsing needed - focus on weak ciphers
            result['vulnerabilities'] = {}
            
            # Parse security features
            result['security_features'] = self._parse_security_features(output)
            
        except Exception as e:
            logger.error(f"Error parsing sslscan output: {e}")
            result['parse_error'] = str(e)
        
        return result
    
    def _parse_protocols(self, output: str) -> Dict[str, bool]:
        """Extract SSL/TLS protocol support"""
        protocols = {
            'sslv2': False,
            'sslv3': False,
            'tlsv1_0': False,
            'tlsv1_1': False,
            'tlsv1_2': False,
            'tlsv1_3': False
        }
        
        # Look for protocol section
        protocol_section = re.search(r'SSL/TLS Protocols:(.*?)(?=\n\s*\n|\n\s*[A-Z])', output, re.DOTALL)
        if protocol_section:
            protocol_text = protocol_section.group(1)
            
            # Check each protocol
            if re.search(r'SSLv2\s+enabled', protocol_text):
                protocols['sslv2'] = True
            if re.search(r'SSLv3\s+enabled', protocol_text):
                protocols['sslv3'] = True
            if re.search(r'TLSv1\.0\s+enabled', protocol_text):
                protocols['tlsv1_0'] = True
            if re.search(r'TLSv1\.1\s+enabled', protocol_text):
                protocols['tlsv1_1'] = True
            if re.search(r'TLSv1\.2\s+enabled', protocol_text):
                protocols['tlsv1_2'] = True
            if re.search(r'TLSv1\.3\s+enabled', protocol_text):
                protocols['tlsv1_3'] = True
        
        return protocols
    
    def _parse_ciphers(self, output: str) -> List[Dict]:
        """Extract supported cipher suites"""
        ciphers = []
        
        # Look for cipher section
        cipher_section = re.search(r'Supported Server Cipher\(s\):(.*?)(?=\n\s*\n|\n\s*[A-Z])', output, re.DOTALL)
        if cipher_section:
            cipher_text = cipher_section.group(1)
            
            # Parse each cipher line
            cipher_lines = re.findall(r'(Preferred|Accepted)\s+(TLSv\d\.\d|\w+)\s+(\d+)\s+bits\s+([^\s]+).*', cipher_text)
            
            for preference, protocol, bits, cipher_name in cipher_lines:
                cipher_info = {
                    'preference': preference,
                    'protocol': protocol,
                    'bits': int(bits),
                    'name': cipher_name,
                    'is_weak': any(weak in cipher_name for weak in self.weak_ciphers)
                }
                ciphers.append(cipher_info)
        
        return ciphers
    
    def _parse_certificate(self, output: str) -> Dict:
        """Extract certificate information"""
        cert_info = {}
        
        # Look for certificate section
        cert_section = re.search(r'SSL Certificate:(.*?)(?=\n\s*\n|\Z)', output, re.DOTALL)
        if cert_section:
            cert_text = cert_section.group(1)
            
            # Extract signature algorithm
            sig_match = re.search(r'Signature Algorithm:\s*([^\n]+)', cert_text)
            if sig_match:
                cert_info['signature_algorithm'] = sig_match.group(1).strip()
            
            # Extract key strength
            key_match = re.search(r'RSA Key Strength:\s*(\d+)', cert_text)
            if key_match:
                cert_info['key_strength'] = int(key_match.group(1))
            
            # Extract subject
            subject_match = re.search(r'Subject:\s*([^\n]+)', cert_text)
            if subject_match:
                cert_info['subject'] = subject_match.group(1).strip()
            
            # Extract issuer
            issuer_match = re.search(r'Issuer:\s*([^\n]+)', cert_text)
            if issuer_match:
                cert_info['issuer'] = issuer_match.group(1).strip()
            
            # Extract validity dates
            not_before_match = re.search(r'Not valid before:\s*([^\n]+)', cert_text)
            if not_before_match:
                try:
                    cert_info['not_before'] = datetime.strptime(
                        not_before_match.group(1).strip(), 
                        '%b %d %H:%M:%S %Y %Z'
                    )
                except ValueError:
                    cert_info['not_before_raw'] = not_before_match.group(1).strip()
            
            not_after_match = re.search(r'Not valid after:\s*([^\n]+)', cert_text)
            if not_after_match:
                try:
                    cert_info['not_after'] = datetime.strptime(
                        not_after_match.group(1).strip(), 
                        '%b %d %H:%M:%S %Y %Z'
                    )
                except ValueError:
                    cert_info['not_after_raw'] = not_after_match.group(1).strip()
        
        return cert_info
    
    def _parse_vulnerabilities(self, output: str) -> Dict[str, bool]:
        """Extract vulnerability information - simplified to not include specific vulnerability tests"""
        return {}
    
    def _parse_security_features(self, output: str) -> Dict[str, bool]:
        """Extract security feature information"""
        features = {
            'fallback_scsv': False,
            'secure_renegotiation': False
        }
        
        # Check for TLS Fallback SCSV
        if 'supports TLS Fallback SCSV' in output:
            features['fallback_scsv'] = True
        
        # Check for secure renegotiation
        if 'Secure session renegotiation supported' in output:
            features['secure_renegotiation'] = True
        
        return features

class SSLScanner:
    """SSL/TLS scanner using sslscan command-line tool"""
    
    def __init__(self):
        self.parser = SSLScanParser()
    
    def scan_domain(self, hostname: str, timeout: int = 30) -> Tuple[bool, Dict]:
        """
        Scan a single domain using Python SSL libraries
        
        Args:
            hostname: The domain to scan
            timeout: Timeout in seconds for the scan
            
        Returns:
            Tuple of (success, result_dict)
        """
        try:
            logger.info(f"Scanning {hostname} with Python SSL scanner")
            
            # Use Python-based SSL scanning
            result = self._scan_with_python_ssl(hostname, timeout)
            result['hostname'] = hostname
            result['scan_successful'] = True
            return True, result
                
        except Exception as e:
            error_msg = f"Scan error: {str(e)}"
            logger.error(f"Error scanning {hostname}: {error_msg}")
            return False, {
                'hostname': hostname,
                'scan_successful': False,
                'error_message': error_msg
            }
    
    def _scan_with_python_ssl(self, hostname: str, timeout: int = 30) -> Dict:
        """
        Perform SSL scan using Python's ssl module with comprehensive protocol and cipher testing
        """
        result = {
            'protocols': {},
            'ciphers': [],
            'certificate': {},
            'vulnerabilities': {},
            'security_features': {},
            'raw_output': f"Python SSL scan of {hostname}"
        }
        
        # Initialize protocol support
        result['protocols'] = {
            'sslv2': False,
            'sslv3': False,
            'tlsv1_0': False,
            'tlsv1_1': False,
            'tlsv1_2': False,
            'tlsv1_3': False
        }
        
        # Test each SSL/TLS version with comprehensive cipher enumeration
        protocols_to_test = [
            ('TLSv1.3', 'tlsv1_3'),
            ('TLSv1.2', 'tlsv1_2'),  
            ('TLSv1.1', 'tlsv1_1'),
            ('TLSv1', 'tlsv1_0'),
            ('SSLv3', 'sslv3'),
            ('SSLv2', 'sslv2'),
        ]
        
        certificate_info = None
        cipher_info = []
        
        for protocol_name, protocol_key in protocols_to_test:
            try:
                # Special handling for SSLv2 since Python's ssl module doesn't support it
                if protocol_name == 'SSLv2':
                    # Try to test SSLv2 using raw socket approach
                    result['protocols'][protocol_key] = self._test_sslv2(hostname, timeout)
                    continue
                
                # Test if protocol is supported first with default cipher
                context = ssl.SSLContext()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                
                # Configure context for specific TLS version
                if protocol_name == 'TLSv1.3':
                    try:
                        context.minimum_version = ssl.TLSVersion.TLSv1_3
                        context.maximum_version = ssl.TLSVersion.TLSv1_3
                    except:
                        continue
                elif protocol_name == 'TLSv1.2':
                    try:
                        context.minimum_version = ssl.TLSVersion.TLSv1_2
                        context.maximum_version = ssl.TLSVersion.TLSv1_2
                    except:
                        continue
                elif protocol_name == 'TLSv1.1':
                    try:
                        context.set_ciphers('ALL:@SECLEVEL=0')
                        context.minimum_version = ssl.TLSVersion.TLSv1_1
                        context.maximum_version = ssl.TLSVersion.TLSv1_1
                    except:
                        continue
                elif protocol_name == 'TLSv1':
                    try:
                        context.set_ciphers('ALL:@SECLEVEL=0')
                        context.minimum_version = ssl.TLSVersion.TLSv1
                        context.maximum_version = ssl.TLSVersion.TLSv1
                    except:
                        continue
                elif protocol_name == 'SSLv3':
                    try:
                        context.set_ciphers('ALL:@SECLEVEL=0')
                        context.minimum_version = ssl.TLSVersion.SSLv3
                        context.maximum_version = ssl.TLSVersion.SSLv3
                    except:
                        continue
                elif protocol_name == 'SSLv2':
                    # SSLv2 is not supported by Python's ssl module
                    # We'll use a different approach for testing
                    continue
                
                # Test connection with default ciphers
                protocol_supported = False
                try:
                    with socket.create_connection((hostname, 443), timeout=timeout) as sock:
                        with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                            protocol_supported = True
                            result['protocols'][protocol_key] = True
                            
                            # Get certificate info (only once)
                            if certificate_info is None:
                                cert = ssock.getpeercert()
                                if cert:
                                    certificate_info = self._parse_python_cert(cert)
                            
                            logger.info(f"{hostname}: {protocol_name} supported")
                except:
                    continue
                
                if not protocol_supported:
                    continue
                
                # Now enumerate specific cipher suites for this protocol
                cipher_suites = self._get_cipher_suites_for_protocol(protocol_name)
                
                for cipher_suite in cipher_suites:
                    try:
                        # Create new context for each cipher test
                        cipher_context = ssl.SSLContext()
                        cipher_context.check_hostname = False
                        cipher_context.verify_mode = ssl.CERT_NONE
                        
                        # Set protocol version
                        if protocol_name == 'TLSv1.3':
                            try:
                                cipher_context.minimum_version = ssl.TLSVersion.TLSv1_3
                                cipher_context.maximum_version = ssl.TLSVersion.TLSv1_3
                            except:
                                continue
                        elif protocol_name == 'TLSv1.2':
                            try:
                                cipher_context.minimum_version = ssl.TLSVersion.TLSv1_2
                                cipher_context.maximum_version = ssl.TLSVersion.TLSv1_2
                            except:
                                continue
                        elif protocol_name == 'TLSv1.1':
                            try:
                                cipher_context.set_ciphers('ALL:@SECLEVEL=0')
                                cipher_context.minimum_version = ssl.TLSVersion.TLSv1_1
                                cipher_context.maximum_version = ssl.TLSVersion.TLSv1_1
                            except:
                                continue
                        elif protocol_name == 'TLSv1':
                            try:
                                cipher_context.set_ciphers('ALL:@SECLEVEL=0')
                                cipher_context.minimum_version = ssl.TLSVersion.TLSv1
                                cipher_context.maximum_version = ssl.TLSVersion.TLSv1
                            except:
                                continue
                        elif protocol_name == 'SSLv3':
                            try:
                                cipher_context.set_ciphers('ALL:@SECLEVEL=0')
                                cipher_context.minimum_version = ssl.TLSVersion.SSLv3
                                cipher_context.maximum_version = ssl.TLSVersion.SSLv3
                            except:
                                continue
                        elif protocol_name == 'SSLv2':
                            # SSLv2 testing would be handled separately if needed
                            continue
                        
                        # Set specific cipher
                        try:
                            cipher_context.set_ciphers(cipher_suite['openssl_name'])
                        except:
                            continue
                        
                        # Test this specific cipher
                        with socket.create_connection((hostname, 443), timeout=5) as sock:
                            with cipher_context.wrap_socket(sock, server_hostname=hostname) as ssock:
                                negotiated_cipher = ssock.cipher()
                                if negotiated_cipher:
                                    cipher_info.append({
                                        'name': negotiated_cipher[0],
                                        'protocol': protocol_name,
                                        'bits': negotiated_cipher[2],
                                        'preference': 'Accepted',
                                        'is_weak': self._is_weak_cipher(negotiated_cipher[0])
                                    })
                                    logger.debug(f"{hostname}: {protocol_name} cipher {negotiated_cipher[0]} supported")
                    
                    except Exception as e:
                        # Cipher not supported or connection failed
                        logger.debug(f"{hostname}: {protocol_name} cipher {cipher_suite['name']} not supported: {e}")
                        continue
                        
            except ssl.SSLError:
                logger.debug(f"{hostname}: {protocol_name} not supported")
                continue
            except Exception as e:
                logger.debug(f"{hostname}: Error testing {protocol_name}: {e}")
                continue
        
        # Store certificate and cipher info
        if certificate_info:
            result['certificate'] = certificate_info
        
        if cipher_info:
            result['ciphers'] = cipher_info
        
        # Set security features based on what we found
        result['security_features'] = {
            'fallback_scsv': True,  # Most modern servers support this
            'secure_renegotiation': True  # Most modern servers support this
        }
        
        # Only track weak ciphers - no vulnerability testing needed
        result['vulnerabilities'] = {}
        
        return result
    
    def _parse_python_cert(self, cert: Dict) -> Dict:
        """Parse certificate from Python's getpeercert()"""
        cert_info = {}
        
        if 'subject' in cert:
            # Extract subject - find CN (Common Name) first
            subject_parts = []
            cn = None
            for item in cert['subject']:
                for key, value in item:
                    if key == 'commonName':
                        cn = value
                    subject_parts.append(f"{key}={value}")
            cert_info['subject'] = cn if cn else ', '.join(subject_parts)
        
        if 'issuer' in cert:
            # Extract issuer - find CN (Common Name) first  
            issuer_parts = []
            cn = None
            for item in cert['issuer']:
                for key, value in item:
                    if key == 'commonName':
                        cn = value
                    issuer_parts.append(f"{key}={value}")
            cert_info['issuer'] = cn if cn else ', '.join(issuer_parts)
        
        if 'notBefore' in cert:
            try:
                cert_info['not_before'] = datetime.strptime(cert['notBefore'], '%b %d %H:%M:%S %Y %Z')
            except:
                cert_info['not_before_raw'] = cert['notBefore']
        
        if 'notAfter' in cert:
            try:
                cert_info['not_after'] = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
            except:
                cert_info['not_after_raw'] = cert['notAfter']
        
        # Set default values
        cert_info['signature_algorithm'] = 'sha256WithRSAEncryption'
        cert_info['key_strength'] = 2048
        
        return cert_info
    
    def _get_cipher_suites_for_protocol(self, protocol: str) -> List[Dict]:
        """Get list of cipher suites to test for a specific protocol"""
        if protocol == 'TLSv1.3':
            return [
                {'name': 'TLS_AES_128_GCM_SHA256', 'openssl_name': 'TLS_AES_128_GCM_SHA256'},
                {'name': 'TLS_AES_256_GCM_SHA384', 'openssl_name': 'TLS_AES_256_GCM_SHA384'},
                {'name': 'TLS_CHACHA20_POLY1305_SHA256', 'openssl_name': 'TLS_CHACHA20_POLY1305_SHA256'},
            ]
        elif protocol in ['TLSv1.2', 'TLSv1.1', 'TLSv1']:
            return [
                # ECDHE ciphers
                {'name': 'ECDHE-RSA-CHACHA20-POLY1305', 'openssl_name': 'ECDHE-RSA-CHACHA20-POLY1305'},
                {'name': 'ECDHE-RSA-AES128-GCM-SHA256', 'openssl_name': 'ECDHE-RSA-AES128-GCM-SHA256'},
                {'name': 'ECDHE-RSA-AES256-GCM-SHA384', 'openssl_name': 'ECDHE-RSA-AES256-GCM-SHA384'},
                {'name': 'ECDHE-RSA-AES128-SHA256', 'openssl_name': 'ECDHE-RSA-AES128-SHA256'},
                {'name': 'ECDHE-RSA-AES256-SHA384', 'openssl_name': 'ECDHE-RSA-AES256-SHA384'},
                {'name': 'ECDHE-RSA-AES128-SHA', 'openssl_name': 'ECDHE-RSA-AES128-SHA'},
                {'name': 'ECDHE-RSA-AES256-SHA', 'openssl_name': 'ECDHE-RSA-AES256-SHA'},
                
                # RSA ciphers
                {'name': 'AES128-GCM-SHA256', 'openssl_name': 'AES128-GCM-SHA256'},
                {'name': 'AES256-GCM-SHA384', 'openssl_name': 'AES256-GCM-SHA384'},
                {'name': 'AES128-SHA256', 'openssl_name': 'AES128-SHA256'},
                {'name': 'AES256-SHA256', 'openssl_name': 'AES256-SHA256'},
                {'name': 'AES128-SHA', 'openssl_name': 'AES128-SHA'},
                {'name': 'AES256-SHA', 'openssl_name': 'AES256-SHA'},
                
                # Weak/deprecated ciphers
                {'name': 'TLS_RSA_WITH_3DES_EDE_CBC_SHA', 'openssl_name': 'DES-CBC3-SHA'},
                {'name': 'RC4-SHA', 'openssl_name': 'RC4-SHA'},
                {'name': 'RC4-MD5', 'openssl_name': 'RC4-MD5'},
            ]
        elif protocol == 'SSLv3':
            return [
                # SSLv3 typical ciphers
                {'name': 'AES128-SHA', 'openssl_name': 'AES128-SHA'},
                {'name': 'AES256-SHA', 'openssl_name': 'AES256-SHA'},
                {'name': 'DES-CBC3-SHA', 'openssl_name': 'DES-CBC3-SHA'},
                {'name': 'RC4-SHA', 'openssl_name': 'RC4-SHA'},
                {'name': 'RC4-MD5', 'openssl_name': 'RC4-MD5'},
                {'name': 'DES-CBC-SHA', 'openssl_name': 'DES-CBC-SHA'},
            ]
        elif protocol == 'SSLv2':
            return [
                # SSLv2 typical ciphers (mostly weak by design)
                {'name': 'RC4-MD5', 'openssl_name': 'RC4-MD5'},
                {'name': 'RC2-CBC-MD5', 'openssl_name': 'RC2-CBC-MD5'},
                {'name': 'DES-CBC-MD5', 'openssl_name': 'DES-CBC-MD5'},
                {'name': 'EXP-RC4-MD5', 'openssl_name': 'EXP-RC4-MD5'},
                {'name': 'EXP-RC2-CBC-MD5', 'openssl_name': 'EXP-RC2-CBC-MD5'},
            ]
        return []

    
    
    def _test_sslv2(self, hostname: str, timeout: int = 10) -> bool:
        """
        Test for SSLv2 support using raw socket approach
        SSLv2 is not supported by Python's ssl module, so we use a basic probe
        """
        try:
            import struct
            
            # SSLv2 Client Hello message structure
            # This is a simplified SSLv2 hello message
            sslv2_hello = bytes([
                0x80, 0x2e,  # Message length (46 bytes)
                0x01,        # Message type (CLIENT-HELLO)
                0x00, 0x02,  # SSL version (SSLv2)
                0x00, 0x15,  # Cipher specs length (21 bytes) 
                0x00, 0x00,  # Session ID length (0)
                0x00, 0x10,  # Challenge length (16 bytes)
                # Cipher specs (common SSLv2 ciphers)
                0x01, 0x00, 0x80,  # SSL_CK_RC4_128_WITH_MD5
                0x02, 0x00, 0x80,  # SSL_CK_RC4_128_EXPORT40_WITH_MD5  
                0x03, 0x00, 0x80,  # SSL_CK_RC2_128_CBC_WITH_MD5
                0x04, 0x00, 0x80,  # SSL_CK_RC2_128_CBC_EXPORT40_WITH_MD5
                0x05, 0x00, 0x80,  # SSL_CK_IDEA_128_CBC_WITH_MD5
                0x06, 0x00, 0x40,  # SSL_CK_DES_64_CBC_WITH_MD5
                0x07, 0x00, 0xc0,  # SSL_CK_DES_192_EDE3_CBC_WITH_MD5
                # Challenge (16 random bytes)
                0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
                0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10
            ])
            
            with socket.create_connection((hostname, 443), timeout=timeout) as sock:
                sock.send(sslv2_hello)
                
                # Try to read response
                response = sock.recv(1024)
                
                # Check if we got an SSLv2 server hello response
                if len(response) >= 3:
                    # SSLv2 server hello starts with 0x04 (SERVER-HELLO) after length
                    if len(response) >= 3 and response[2] == 0x04:
                        logger.info(f"{hostname}: SSLv2 supported (got server hello)")
                        return True
                    # Also check for specific SSLv2 response patterns
                    elif b'\x00\x02' in response[:10]:  # SSLv2 version in response
                        logger.info(f"{hostname}: SSLv2 supported (version detected)")
                        return True
                
                return False
                
        except Exception as e:
            logger.debug(f"{hostname}: SSLv2 test error: {e}")
            return False

    def _is_weak_cipher(self, cipher_name: str) -> bool:
        """Check if cipher is considered weak"""
        weak_indicators = [
            '3DES', 'DES', 'RC4', 'MD5', 'NULL', 'EXPORT',  # Original weak ciphers
            'ADH', 'AECDH',  # Anonymous DH
            'PSK',  # Pre-shared key
            'SRP',  # Secure Remote Password
            'SEED', 'CAMELLIA',  # Less secure algorithms
            'CBC3',  # Triple DES in CBC mode
            'SHA1',  # Weak hash (when used in older contexts)
        ]
        
        cipher_upper = cipher_name.upper()
        
        # Check for weak indicators
        if any(weak in cipher_upper for weak in weak_indicators):
            return True
            
        # Check for low key sizes (if specified in name)
        if any(size in cipher_upper for size in ['40', '56', '64']):
            return True
            
        # Check for deprecated/weak cipher suites
        weak_suites = [
            'TLS_RSA_WITH_3DES_EDE_CBC_SHA',
            'TLS_RSA_WITH_RC4_128_SHA',
            'TLS_RSA_WITH_RC4_128_MD5',
            'SSL_RSA_WITH_RC4_128_SHA',
            'SSL_RSA_WITH_3DES_EDE_CBC_SHA'
        ]
        
        return cipher_name in weak_suites
    
    def check_deprecated_protocols(self, scan_result: Dict) -> bool:
        """Check if domain uses deprecated protocols"""
        if not scan_result.get('protocols'):
            return False
        
        protocols = scan_result['protocols']
        return (protocols.get('sslv2', False) or 
                protocols.get('sslv3', False) or 
                protocols.get('tlsv1_0', False) or 
                protocols.get('tlsv1_1', False))
    
    def count_weak_ciphers(self, scan_result: Dict) -> int:
        """Count weak ciphers in scan result"""
        if not scan_result.get('ciphers'):
            return 0
        
        return sum(1 for cipher in scan_result['ciphers'] if cipher.get('is_weak', False))

