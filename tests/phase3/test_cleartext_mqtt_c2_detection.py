#!/usr/bin/env python3
"""
Phase 3 Test: C2 Detection for Cleartext MQTT Traffic

Tests full pipeline: encryption detection → context selection → C2 prediction.
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

import pandas as pd
from src.moe import detect_c2


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
    print("Phase 3 Test: C2 Detection for Cleartext MQTT Traffic")
    print("=" * 80)
    print()
    
    # Full pipeline test
    print("Running full pipeline (Phase 1 → Phase 2 → Phase 3)...")
    packet_data = create_packet_dataframe(port=1883, protocol='tcp')
    
    result = detect_c2(
        packet_data,
        port=1883,
        protocol='tcp'
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
        assert result['is_encrypted'] == False, "Should detect as not encrypted"
        assert result['model_used'] == 'mqtt_model', "Should select MQTT model"
        assert 'is_c2' in result, "Should have C2 prediction"
        
        print("  ✓ Phase 1: Correctly detected as not encrypted")
        print("  ✓ Phase 2: MQTT model correctly selected")
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

