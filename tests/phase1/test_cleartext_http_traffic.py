#!/usr/bin/env python3
"""
Phase 1 Test: Cleartext HTTP Traffic Detection

Tests detection of cleartext HTTP traffic on port 80/TCP.
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

import pandas as pd
from src.moe import check_encryption


def create_packet_dataframe(port=80, protocol='tcp'):
    """Create test packet DataFrame."""
    packet_sizes = [200, 300, 250]
    directions = [1, 0, 1]
    n_packets = len(packet_sizes)
    
    return pd.DataFrame({
        'packet_size': packet_sizes,
        'direction': directions,
        'dst_port': [port] * n_packets,
        'src_port': [54321] * n_packets,
        'protocol': [protocol] * n_packets,
    })


def create_http_packet_bytes():
    """Create realistic HTTP packet bytes."""
    return b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"


def main():
    """Run the test."""
    print("=" * 80)
    print("Phase 1 Test: Cleartext HTTP Traffic Detection")
    print("=" * 80)
    print()
    
    # Create test data
    packet_data = create_packet_dataframe(port=80, protocol='tcp')
    packet_bytes = create_http_packet_bytes()
    
    print("Test Input:")
    print(f"  Port: 80")
    print(f"  Protocol: TCP")
    print(f"  Packet bytes: {packet_bytes[:30]}...")
    print()
    
    # Run encryption detection
    print("Running encryption detection...")
    is_encrypted, protocol_type = check_encryption(
        packet_data,
        port=80,
        protocol='tcp',
        packet_bytes=packet_bytes
    )
    
    print()
    print("Results:")
    print(f"  Encrypted: {is_encrypted}")
    print(f"  Protocol Type: {protocol_type}")
    print()
    
    # Assertions
    print("Assertions:")
    try:
        assert is_encrypted == False, f"Expected encrypted=False, got {is_encrypted}"
        print("  ✓ HTTP traffic correctly detected as not encrypted")
        print()
        print("=" * 80)
        print("TEST PASSED ✓")
        print("=" * 80)
        return 0
    except AssertionError as e:
        print(f"  ✗ FAILED: {e}")
        print()
        print("=" * 80)
        print("TEST FAILED ✗")
        print("=" * 80)
        return 1


if __name__ == '__main__':
    sys.exit(main())

