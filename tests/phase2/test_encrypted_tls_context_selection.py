#!/usr/bin/env python3
"""
Phase 2 Test: Context Selection for Encrypted TLS Traffic

Tests context selection (model selection) for encrypted TLS traffic.
Runs Phase 1 (encryption detection) first, then Phase 2 (context selection).
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

import pandas as pd
from src.moe import check_encryption, select_context


def create_packet_dataframe(port=443, protocol='tcp'):
    """Create test packet DataFrame."""
    packet_sizes = [500, 600, 550, 450, 500]
    directions = [1, 0, 1, 0, 1]
    n_packets = len(packet_sizes)
    
    data = {
        'packet_size': packet_sizes,
        'direction': directions,
        'dst_port': [port] * n_packets,
        'src_port': [54321] * n_packets,
        'protocol': [protocol] * n_packets,
    }
    
    # Add TLS features
    if port == 443 and protocol == 'tcp':
        for i in range(min(10, n_packets)):
            tls_b_values = []
            tls_dir_values = []
            for j in range(n_packets):
                if j == i:
                    tls_b_values.append(packet_sizes[j])
                    tls_dir_values.append(directions[j])
                else:
                    tls_b_values.append(0)
                    tls_dir_values.append(0)
            data[f'tls_b_{i}'] = tls_b_values
            data[f'tls_dir_{i}'] = tls_dir_values
    
    return pd.DataFrame(data)


def create_tls_packet_bytes():
    """Create realistic TLS packet bytes."""
    return bytes([
        0x16,  # Content Type: Handshake
        0x03, 0x03,  # Version: TLS 1.2
        0x00, 0x05,  # Length: 5 bytes
        0x01,  # Handshake Type: ClientHello
        0x00, 0x00, 0x01, 0x00  # Partial handshake message
    ])


def main():
    """Run the test."""
    print("=" * 80)
    print("Phase 2 Test: Context Selection for Encrypted TLS Traffic")
    print("=" * 80)
    print()
    
    # Phase 1: Encryption detection
    print("Phase 1: Running encryption detection...")
    packet_data = create_packet_dataframe(port=443, protocol='tcp')
    packet_bytes = create_tls_packet_bytes()
    
    is_encrypted, protocol_type = check_encryption(
        packet_data,
        port=443,
        protocol='tcp',
        packet_bytes=packet_bytes
    )
    
    print(f"  Encrypted: {is_encrypted}")
    print(f"  Protocol Type: {protocol_type}")
    print()
    
    # Phase 2: Context selection
    print("Phase 2: Running context selection...")
    context = select_context(packet_data, is_encrypted, protocol_type)
    
    print(f"  Selected Context: {context}")
    print()
    
    # Assertions
    print("Assertions:")
    try:
        assert is_encrypted == True, f"Expected encrypted=True, got {is_encrypted}"
        assert protocol_type == 'tls', f"Expected protocol_type='tls', got {protocol_type}"
        assert context == 'tls', f"Expected context='tls', got {context}"
        print("  ✓ Encryption correctly detected")
        print("  ✓ TLS protocol correctly identified")
        print(f"  ✓ TLS context correctly selected: {context}")
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

