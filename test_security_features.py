
#!/usr/bin/env python3
"""
Test script to validate security features parsing
"""

from ssl_scanner import SSLScanParser

# Sample sslscan output with security features
SECURITY_FEATURES_OUTPUT = """Version: 2.1.6
OpenSSL 3.5.0 8 Apr 2025

Connected to 34.111.127.113

Testing SSL server dashboardapi.devtest.experience.com on port 443 using SNI name dashboardapi.devtest.experience.com

  SSL/TLS Protocols:
SSLv2     disabled
SSLv3     disabled
TLSv1.0   enabled
TLSv1.1   enabled
TLSv1.2   enabled
TLSv1.3   enabled

  TLS Fallback SCSV:
Server supports TLS Fallback SCSV

  TLS renegotiation:
Secure session renegotiation supported

  TLS Compression:
OpenSSL version does not support compression
Rebuild with zlib1g-dev package for zlib support

  Heartbleed:
TLSv1.3 not vulnerable to heartbleed
TLSv1.2 not vulnerable to heartbleed
TLSv1.1 not vulnerable to heartbleed
TLSv1.0 not vulnerable to heartbleed

  Supported Server Cipher(s):
Preferred TLSv1.3  128 bits  TLS_AES_128_GCM_SHA256        Curve 25519 DHE 253
Accepted  TLSv1.3  256 bits  TLS_AES_256_GCM_SHA384        Curve 25519 DHE 253
Accepted  TLSv1.3  256 bits  TLS_CHACHA20_POLY1305_SHA256  Curve 25519 DHE 253

  SSL Certificate:
Signature Algorithm: sha256WithRSAEncryption
RSA Key Strength:    2048

Subject:  dashboardapi.devtest.experience.com
Altnames: DNS:dashboardapi.devtest.experience.com
Issuer:   WR3

Not valid before: Apr 11 19:47:35 2025 GMT
Not valid after:  Jul 10 20:41:49 2025 GMT
"""

def test_security_features_parsing():
    """Test parsing of security features"""
    parser = SSLScanParser()
    result = parser.parse_sslscan_output(SECURITY_FEATURES_OUTPUT)

    print("=== SECURITY FEATURES PARSING TEST ===")
    print(f"Security features found: {result['security_features']}")
    print()

    # Expected values based on the output
    expected_fallback_scsv = True  # "Server supports TLS Fallback SCSV"
    expected_renegotiation = True  # "Secure session renegotiation supported"

    print("=== VALIDATION ===")
    
    # Check TLS Fallback SCSV
    fallback_correct = result['security_features']['fallback_scsv'] == expected_fallback_scsv
    print(f"TLS Fallback SCSV parsing correct: {fallback_correct}")
    print(f"  Expected: {expected_fallback_scsv}")
    print(f"  Actual: {result['security_features']['fallback_scsv']}")
    
    # Check renegotiation
    renegotiation_correct = result['security_features']['secure_renegotiation'] == expected_renegotiation
    print(f"Secure renegotiation parsing correct: {renegotiation_correct}")
    print(f"  Expected: {expected_renegotiation}")
    print(f"  Actual: {result['security_features']['secure_renegotiation']}")

    print()
    all_correct = fallback_correct and renegotiation_correct
    print(f"=== OVERALL RESULT ===")
    print(f"All security features parsed correctly: {all_correct}")

    if not all_correct:
        print("\nIssues found - security features parsing needs adjustment")
    else:
        print("\nSecurity features parsing is working correctly!")

if __name__ == "__main__":
    test_security_features_parsing()
