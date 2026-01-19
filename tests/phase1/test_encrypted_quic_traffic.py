#!/usr/bin/env python3
"""
Phase 1 Test: Encrypted QUIC Traffic Detection

Tests detection of encrypted QUIC traffic on port 443/UDP.
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

import pandas as pd
from src.moe import check_encryption


def create_packet_dataframe(port=443, protocol='udp'):
    """Create test packet DataFrame."""
    packet_sizes = [500, 600, 550]
    directions = [1, 0, 1]
    n_packets = len(packet_sizes)
    
    return pd.DataFrame({
        'packet_size': packet_sizes,
        'direction': directions,
        'dst_port': [port] * n_packets,
        'src_port': [54321] * n_packets,
        'protocol': [protocol] * n_packets,
    })


def create_quic_packet_bytes():
    """Create realistic QUIC packet bytes."""
    return bytes([
        0xC0,  # Long header + fixed bit
        0x00, 0x00, 0x00, 0x01,  # Version: QUIC v1
        0x08,  # DCID length
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08  # DCID
    ])


def main():
    """Run the test."""
    print("=" * 80)
    print("Phase 1 Test: Encrypted QUIC Traffic Detection")
    print("=" * 80)
    print()
    
    # Create test data
    packet_data = create_packet_dataframe(port=443, protocol='udp')
    packet_bytes = create_quic_packet_bytes()
    
    print("Test Input:")
    print(f"  Port: 443")
    print(f"  Protocol: UDP")
    print(f"  Packet bytes length: {len(packet_bytes)} bytes")
    print()
    
    # Run encryption detection
    print("Running encryption detection...")
    is_encrypted, protocol_type = check_encryption(
        packet_data,
        port=443,
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
        assert is_encrypted == True, f"Expected encrypted=True, got {is_encrypted}"
        print("  ✓ QUIC traffic correctly detected as encrypted")
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

