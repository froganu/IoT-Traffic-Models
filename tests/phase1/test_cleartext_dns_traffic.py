#!/usr/bin/env python3
"""
Phase 1 Test: Cleartext DNS Traffic Detection

Tests detection of cleartext DNS traffic on port 53/UDP.
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

import pandas as pd
from src.moe import check_encryption


def create_packet_dataframe(port=53, protocol='udp'):
    """Create test packet DataFrame."""
    packet_sizes = [100, 120, 110]
    directions = [1, 0, 1]
    n_packets = len(packet_sizes)
    
    return pd.DataFrame({
        'packet_size': packet_sizes,
        'direction': directions,
        'dst_port': [port] * n_packets,
        'src_port': [54321] * n_packets,
        'protocol': [protocol] * n_packets,
    })


def create_dns_packet_bytes():
    """Create realistic DNS packet bytes."""
    return bytes([
        0x12, 0x34,  # Transaction ID
        0x01, 0x00,  # Flags
        0x00, 0x01,  # QDCOUNT
        0x00, 0x00,  # ANCOUNT
        0x00, 0x00,  # NSCOUNT
        0x00, 0x00,  # ARCOUNT
        0x03, ord('w'), ord('w'), ord('w'),
        0x07, ord('e'), ord('x'), ord('a'), ord('m'), ord('p'), ord('l'), ord('e'),
        0x03, ord('c'), ord('o'), ord('m'),
        0x00,
        0x00, 0x01,  # QTYPE
        0x00, 0x01   # QCLASS
    ])


def main():
    """Run the test."""
    print("=" * 80)
    print("Phase 1 Test: Cleartext DNS Traffic Detection")
    print("=" * 80)
    print()
    
    # Create test data
    packet_data = create_packet_dataframe(port=53, protocol='udp')
    packet_bytes = create_dns_packet_bytes()
    
    print("Test Input:")
    print(f"  Port: 53")
    print(f"  Protocol: UDP")
    print(f"  Packet bytes length: {len(packet_bytes)} bytes")
    print()
    
    # Run encryption detection
    print("Running encryption detection...")
    is_encrypted, protocol_type = check_encryption(
        packet_data,
        port=53,
        protocol='udp',
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
        assert protocol_type is None, f"Expected protocol_type=None, got {protocol_type}"
        print("  ✓ DNS traffic correctly detected as not encrypted")
        print("  ✓ Protocol type correctly identified as None (cleartext)")
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

