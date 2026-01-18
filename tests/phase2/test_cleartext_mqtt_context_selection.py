#!/usr/bin/env python3
"""
Phase 2 Test: Context Selection for Cleartext MQTT Traffic

Tests context selection (model selection) for cleartext MQTT traffic.
Runs Phase 1 (encryption detection) first, then Phase 2 (context selection).
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

import pandas as pd
from src.moe import check_encryption, select_ai_model


def create_packet_dataframe(port=1883, protocol='tcp'):
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


def main():
    """Run the test."""
    print("=" * 80)
    print("Phase 2 Test: Context Selection for Cleartext MQTT Traffic")
    print("=" * 80)
    print()
    
    # Phase 1: Encryption detection
    print("Phase 1: Running encryption detection...")
    packet_data = create_packet_dataframe(port=1883, protocol='tcp')
    
    is_encrypted, protocol_type = check_encryption(
        packet_data,
        port=1883,
        protocol='tcp'
    )
    
    print(f"  Encrypted: {is_encrypted}")
    print(f"  Protocol Type: {protocol_type}")
    print()
    
    # Phase 2: Context selection
    print("Phase 2: Running context selection...")
    model_name = select_ai_model(packet_data, is_encrypted, protocol_type)
    
    print(f"  Selected Model: {model_name}")
    print()
    
    # Assertions
    print("Assertions:")
    try:
        assert is_encrypted == False, f"Expected encrypted=False, got {is_encrypted}"
        assert model_name == 'mqtt_model', f"Expected model='mqtt_model', got {model_name}"
        print("  ✓ Encryption correctly detected as not encrypted")
        print("  ✓ MQTT model correctly selected")
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

