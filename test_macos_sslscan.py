
#!/usr/bin/env python3
"""
Test script to verify the SSL scanner works with macOS sslscan output format
"""

from ssl_scanner import SSLScanParser

# Sample macOS sslscan output (based on your example)
MACOS_SSLSCAN_OUTPUT = """Version: 2.1.6
OpenSSL 3.5.0 8 Apr 2025

Connected to 34.111.72.99

Testing SSL server dashboardapi.uat.experience.com on port 443 using SNI name dashboardapi.uat.experience.com

  SSL/TLS Protocols:
SSLv2     disabled
SSLv3     disabled
TLSv1.0   disabled
TLSv1.1   disabled
TLSv1.2   enabled
TLSv1.3   enabled

  TLS Fallback SCSV:
Server supports TLS Fallback SCSV

  TLS renegotiation:
Session renegotiation not supported

  TLS Compression:
OpenSSL version does not support compression
Rebuild with zlib1g-dev package for zlib support

  Heartbleed:
TLSv1.3 not vulnerable to heartbleed
TLSv1.2 not vulnerable to heartbleed

  Supported Server Cipher(s):
Preferred TLSv1.3  128 bits  TLS_AES_128_GCM_SHA256        Curve 25519 DHE 253
Accepted  TLSv1.3  256 bits  TLS_AES_256_GCM_SHA384        Curve 25519 DHE 253
Accepted  TLSv1.3  256 bits  TLS_CHACHA20_POLY1305_SHA256  Curve 25519 DHE 253
Preferred TLSv1.2  256 bits  ECDHE-RSA-CHACHA20-POLY1305   Curve 25519 DHE 253
Accepted  TLSv1.2  128 bits  ECDHE-RSA-AES128-GCM-SHA256   Curve 25519 DHE 253
Accepted  TLSv1.2  256 bits  ECDHE-RSA-AES256-GCM-SHA384   Curve 25519 DHE 253

  Server Key Exchange Group(s):
TLSv1.3  128 bits  secp256r1 (NIST P-256)
TLSv1.3  128 bits  x25519
TLSv1.2  128 bits  secp256r1 (NIST P-256)
TLSv1.2  128 bits  x25519

  SSL Certificate:
Signature Algorithm: sha256WithRSAEncryption
RSA Key Strength:    2048

Subject:  dashboardapi.uat.experience.com
Altnames: DNS:dashboardapi.uat.experience.com
Issuer:   WR3

Not valid before: Mar 30 23:35:37 2025 GMT
Not valid after:  Jun 29 00:30:31 2025 GMT"""

def test_macos_parsing():
    """Test parsing of macOS sslscan output"""
    parser = SSLScanParser()
    result = parser.parse_sslscan_output(MACOS_SSLSCAN_OUTPUT)
    
    print("=== PARSING TEST RESULTS ===")
    print(f"Protocols: {result['protocols']}")
    print(f"Expected: SSLv2=False, SSLv3=False, TLSv1.0=False, TLSv1.1=False, TLSv1.2=True, TLSv1.3=True")
    print()
    
    print(f"Number of ciphers found: {len(result['ciphers'])}")
    print("Ciphers:")
    for cipher in result['ciphers']:
        print(f"  - {cipher['preference']} {cipher['protocol']} {cipher['bits']} bits {cipher['name']}")
    print()
    
    print(f"Certificate info: {result['certificate']}")
    print()
    
    print(f"Security features: {result['security_features']}")
    print()
    
    # Verify expected results
    expected_protocols = {
        'sslv2': False,
        'sslv3': False,
        'tlsv1_0': False,
        'tlsv1_1': False,
        'tlsv1_2': True,
        'tlsv1_3': True
    }
    
    print("=== VERIFICATION ===")
    protocols_match = result['protocols'] == expected_protocols
    print(f"Protocols parsing correct: {protocols_match}")
    
    expected_cipher_count = 6  # Based on the sample output
    cipher_count_correct = len(result['ciphers']) == expected_cipher_count
    print(f"Cipher count correct ({expected_cipher_count}): {cipher_count_correct}")
    
    expected_fallback_scsv = True
    fallback_correct = result['security_features']['fallback_scsv'] == expected_fallback_scsv
    print(f"TLS Fallback SCSV parsing correct: {fallback_correct}")
    
    expected_renegotiation = False  # "not supported" in the sample
    renegotiation_correct = result['security_features']['secure_renegotiation'] == expected_renegotiation
    print(f"Renegotiation parsing correct: {renegotiation_correct}")
    
    # Check certificate parsing
    cert_has_subject = 'subject' in result['certificate']
    cert_has_issuer = 'issuer' in result['certificate']
    cert_has_signature = 'signature_algorithm' in result['certificate']
    cert_has_key_strength = 'key_strength' in result['certificate']
    
    print(f"Certificate subject parsed: {cert_has_subject}")
    print(f"Certificate issuer parsed: {cert_has_issuer}")
    print(f"Certificate signature algorithm parsed: {cert_has_signature}")
    print(f"Certificate key strength parsed: {cert_has_key_strength}")
    
    all_correct = (protocols_match and cipher_count_correct and 
                   fallback_correct and renegotiation_correct and
                   cert_has_subject and cert_has_issuer)
    
    print(f"\n=== OVERALL RESULT ===")
    print(f"All parsing tests passed: {all_correct}")
    
    if not all_correct:
        print("\nIssues found - please check the parsing logic")
    else:
        print("\nParser is working correctly with macOS sslscan format!")

if __name__ == "__main__":
    test_macos_parsing()
