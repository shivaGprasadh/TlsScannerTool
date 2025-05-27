
#!/usr/bin/env python3
"""
Debug script to test sslscan parsing on macOS
Run this script to see what sslscan outputs and how it's being parsed
"""

import subprocess
import sys
from ssl_scanner import SSLScanParser

def debug_sslscan(hostname):
    """Debug sslscan output parsing"""
    try:
        # Run sslscan command
        cmd = ['sslscan', '--no-colour', hostname]
        print(f"Running: {' '.join(cmd)}")
        
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=30,
            check=False
        )
        
        if result.returncode != 0:
            print(f"sslscan failed with return code {result.returncode}")
            print(f"stderr: {result.stderr}")
            return
        
        output = result.stdout
        print(f"\n=== RAW SSLSCAN OUTPUT ===")
        print(output)
        print(f"\n=== OUTPUT LENGTH: {len(output)} characters ===")
        
        # Parse with our parser
        parser = SSLScanParser()
        parsed_result = parser.parse_sslscan_output(output)
        
        print(f"\n=== PARSED RESULTS ===")
        print(f"Protocols: {parsed_result['protocols']}")
        print(f"Number of ciphers: {len(parsed_result['ciphers'])}")
        print(f"Certificate: {parsed_result['certificate']}")
        print(f"Security features: {parsed_result['security_features']}")
        
        if parsed_result['ciphers']:
            print(f"\nFirst few ciphers:")
            for cipher in parsed_result['ciphers'][:5]:
                print(f"  - {cipher}")
        
    except FileNotFoundError:
        print("sslscan command not found. Please install sslscan:")
        print("  brew install sslscan")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python debug_sslscan.py <hostname>")
        print("Example: python debug_sslscan.py google.com")
        sys.exit(1)
    
    hostname = sys.argv[1]
    debug_sslscan(hostname)
