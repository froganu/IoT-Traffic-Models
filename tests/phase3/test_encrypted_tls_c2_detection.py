#!/usr/bin/env python3
"""
Phase 3 Test: C2 Detection for Encrypted TLS Traffic

Tests full pipeline: encryption detection → context selection → C2 prediction.
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

import pandas as pd
from src.moe import detect_c2


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
    print("Phase 3 Test: C2 Detection for Encrypted TLS Traffic")
    print("=" * 80)
    print()
    
    # Full pipeline test
    print("Running full pipeline (Phase 1 → Phase 2 → Phase 3)...")
    packet_data = create_packet_dataframe(port=443, protocol='tcp')
    packet_bytes = create_tls_packet_bytes()
    
    result = detect_c2(
        packet_data,
        port=443,
        protocol='tcp',
        packet_bytes=packet_bytes
    )
    
    print()
    print("Results:")
    print(f"  Encrypted: {result.get('is_encrypted')}")
    print(f"  Protocol Type: {result.get('protocol_type')}")
    print(f"  Model Used: {result.get('model_used')}")
    print(f"  Is C2: {result.get('is_c2')}")
    print(f"  Probability: {result.get('probability')}")
    print()
    
    # Assertions
    print("Assertions:")
    try:
        assert result is not None, "Should return a result"
        assert 'is_encrypted' in result, "Should have encryption status"
        assert 'model_used' in result, "Should have model selection"
        assert 'is_c2' in result, "Should have C2 prediction"
        
        # Phase 1 check
        assert result['is_encrypted'] == True, "Should detect encryption"
        assert result['protocol_type'] == 'tls', "Should detect TLS"
        
        # Phase 2 check
        assert result['model_used'] == 'tls_model', "Should select TLS model"
        
        # Phase 3 check (prediction may be None if models not loaded)
        assert 'is_c2' in result, "Should have C2 prediction field"
        
        print("  ✓ Phase 1: Encryption correctly detected")
        print("  ✓ Phase 2: TLS model correctly selected")
        print("  ✓ Phase 3: C2 prediction field present")
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

