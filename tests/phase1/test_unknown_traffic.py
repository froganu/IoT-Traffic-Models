#!/usr/bin/env python3
"""
Phase 1 Test: Unknown Traffic Handling

Tests handling of unknown traffic on non-standard port.
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

import pandas as pd
from src.moe import check_encryption


def create_packet_dataframe(port=12345, protocol='tcp'):
    """Create test packet DataFrame."""
    packet_sizes = [150, 200, 180]
    directions = [1, 0, 1]
    n_packets = len(packet_sizes)
    
    return pd.DataFrame({
        'packet_size': packet_sizes,
        'direction': directions,
        'dst_port': [port] * n_packets,
        'src_port': [54321] * n_packets,
        'protocol': [protocol] * n_packets,
    })


def main():
    """Run the test."""
    print("=" * 80)
    print("Phase 1 Test: Unknown Traffic Handling")
    print("=" * 80)
    print()
    
    # Create test data
    packet_data = create_packet_dataframe(port=12345, protocol='tcp')
    
    print("Test Input:")
    print(f"  Port: 12345 (non-standard)")
    print(f"  Protocol: TCP")
    print(f"  No packet bytes provided")
    print()
    
    # Run encryption detection
    print("Running encryption detection...")
    is_encrypted, protocol_type = check_encryption(
        packet_data,
        port=12345,
        protocol='tcp'
    )
    
    print()
    print("Results:")
    print(f"  Encrypted: {is_encrypted}")
    print(f"  Protocol Type: {protocol_type}")
    print()
    
    # Assertions
    print("Assertions:")
    try:
        assert is_encrypted == False, f"Expected encrypted=False (default), got {is_encrypted}"
        print("  ✓ Unknown traffic correctly defaulted to not encrypted")
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

