
#!/usr/bin/env python3
"""
Test script to verify the SSL scanner works with the cms.devtest.experience.com output
"""

from ssl_scanner import SSLScanParser

# Sample macOS sslscan output for cms.devtest.experience.com
CMS_SSLSCAN_OUTPUT = """Version: 2.1.6
OpenSSL 3.5.0 8 Apr 2025

Connected to 34.150.136.14

Testing SSL server cms.devtest.experience.com on port 443 using SNI name cms.devtest.experience.com

  SSL/TLS Protocols:
SSLv2     disabled
SSLv3     disabled
TLSv1.0   disabled
TLSv1.1   disabled
TLSv1.2   disabled
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

  Supported Server Cipher(s):
Preferred TLSv1.3  256 bits  TLS_AES_256_GCM_SHA384        Curve P-384 DHE 384
Accepted  TLSv1.3  256 bits  TLS_CHACHA20_POLY1305_SHA256  Curve P-384 DHE 384
Accepted  TLSv1.3  128 bits  TLS_AES_128_GCM_SHA256        Curve P-384 DHE 384

  Server Key Exchange Group(s):
TLSv1.3  192 bits  secp384r1 (NIST P-384)

  SSL Certificate:
Signature Algorithm: sha256WithRSAEncryption
RSA Key Strength:    2048

Subject:  cms.devtest.experience.com
Altnames: DNS:cms.devtest.experience.com
Issuer:   R11

Not valid before: Apr  1 06:01:41 2025 GMT
Not valid after:  Jun 30 06:01:40 2025 GMT
"""

def test_cms_parsing():
    """Test parsing of CMS sslscan output"""
    parser = SSLScanParser()
    result = parser.parse_sslscan_output(CMS_SSLSCAN_OUTPUT)

    print("=== CMS PARSING TEST RESULTS ===")
    print(f"Protocols: {result['protocols']}")
    print(f"Expected: SSLv2=False, SSLv3=False, TLSv1.0=False, TLSv1.1=False, TLSv1.2=False, TLSv1.3=True")
    print()

    print(f"Number of ciphers found: {len(result['ciphers'])}")
    print("Ciphers:")
    for cipher in result['ciphers']:
        print(f"  - {cipher['preference']} {cipher['protocol']} {cipher['bits']} bits {cipher['name']}")
        if 'additional_info' in cipher and cipher['additional_info']:
            print(f"    Additional info: {cipher['additional_info']}")
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
        'tlsv1_2': False,
        'tlsv1_3': True
    }

    print("=== VERIFICATION ===")
    protocols_match = result['protocols'] == expected_protocols
    print(f"Protocols parsing correct: {protocols_match}")

    expected_cipher_count = 3  # Based on the CMS output
    cipher_count_correct = len(result['ciphers']) == expected_cipher_count
    print(f"Cipher count correct ({expected_cipher_count}): {cipher_count_correct}")

    # Check specific ciphers
    expected_ciphers = [
        'TLS_AES_256_GCM_SHA384',
        'TLS_CHACHA20_POLY1305_SHA256', 
        'TLS_AES_128_GCM_SHA256'
    ]
    
    found_ciphers = [cipher['name'] for cipher in result['ciphers']]
    all_ciphers_found = all(cipher in found_ciphers for cipher in expected_ciphers)
    print(f"All expected ciphers found: {all_ciphers_found}")
    
    if not all_ciphers_found:
        print(f"Expected: {expected_ciphers}")
        print(f"Found: {found_ciphers}")

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

    all_correct = (protocols_match and cipher_count_correct and all_ciphers_found and
                   fallback_correct and renegotiation_correct and
                   cert_has_subject and cert_has_issuer)

    print(f"\n=== OVERALL RESULT ===")
    print(f"All parsing tests passed: {all_correct}")

    if not all_correct:
        print("\nIssues found - please check the parsing logic")
    else:
        print("\nParser is working correctly with CMS sslscan format!")

if __name__ == "__main__":
    test_cms_parsing()
