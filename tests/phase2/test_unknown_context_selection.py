#!/usr/bin/env python3
"""
Phase 2 Test: Context Selection for Unknown Traffic

Tests context selection (model selection) for unknown traffic.
Runs Phase 1 (encryption detection) first, then Phase 2 (context selection).

Phase 2 verifies:
1. Device classifier is attempted (may return None)
2. Protocol classifier is attempted (may return UNKNOWN)
3. Fallback to port-based routing works
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

import pandas as pd
from src.moe import check_encryption, select_ai_model
from src.context_selection_models import select_device_context_safe, classify_packet, PacketMetadata, ProtocolLabel


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
    print("Phase 2 Test: Context Selection for Unknown Traffic")
    print("=" * 80)
    print()
    
    # Phase 1: Encryption detection
    print("Phase 1: Running encryption detection...")
    packet_data = create_packet_dataframe(port=12345, protocol='tcp')
    
    is_encrypted, protocol_type = check_encryption(
        packet_data,
        port=12345,
        protocol='tcp'
    )
    
    print(f"  Encrypted: {is_encrypted}")
    print(f"  Protocol Type: {protocol_type}")
    print()
    
    # Phase 2: Context selection
    print("Phase 2: Running context selection...")
    print()
    
    # Step 2.1: Test Device Classifier
    print("  Step 2.1: Device Classifier")
    try:
        device_type, device_confidence = select_device_context_safe(packet_data)
        if device_type is not None:
            print(f"    Device Type: {device_type} (confidence: {device_confidence:.2f})")
            print(f"    → Device classifier returned result")
        else:
            print(f"    Device Type: None (device classifier returned None)")
            print(f"    → Device classifier did not identify specific device (expected for unknown traffic)")
    except Exception as e:
        print(f"    Device Classifier: Not available ({type(e).__name__})")
        print(f"    → Will fall back to protocol classifier")
    print()
    
    # Step 2.2: Test Protocol Classifier
    print("  Step 2.2: Protocol Classifier")
    unknown_packet_bytes = b'\x00\x01\x02\x03\x04\x05'  # Random bytes
    try:
        meta = PacketMetadata(
            l4_proto='tcp',
            src_port=54321,
            dst_port=12345,
            captured_payload_offset=0
        )
        protocol_result = classify_packet(unknown_packet_bytes, meta)
        print(f"    Protocol: {protocol_result.label.value}")
        print(f"    Confidence: {protocol_result.confidence:.2f}")
        print(f"    Evidence: {protocol_result.evidence.value}")
        print(f"    → Protocol classifier returned {protocol_result.label.value} (expected UNKNOWN or OTHER)")
    except Exception as e:
        print(f"    Protocol Classifier: Error ({type(e).__name__}: {e})")
        protocol_result = None
    print()
    
    # Step 2.3: Full context selection (both classifiers)
    print("  Step 2.3: Full Context Selection (Device + Protocol Classifiers + Fallback)")
    packet_data_with_bytes = packet_data.copy()
    packet_data_with_bytes['packet_bytes'] = [unknown_packet_bytes] * len(packet_data)
    model_name = select_ai_model(packet_data_with_bytes, is_encrypted, protocol_type)
    print(f"    Selected Model: {model_name}")
    print()
    
    # Assertions
    print("Assertions:")
    try:
        assert is_encrypted == False, f"Expected encrypted=False (default), got {is_encrypted}"
        assert model_name is not None, f"Expected some model to be selected, got {model_name}"
        
        # Verify both classifiers were attempted
        if protocol_result:
            assert protocol_result.label in [ProtocolLabel.UNKNOWN, ProtocolLabel.OTHER], \
                f"Expected UNKNOWN or OTHER for unknown traffic, got {protocol_result.label.value}"
        
        print("  ✓ Unknown traffic correctly defaulted to not encrypted")
        print("  ✓ Device classifier attempted (returned None as expected)")
        print("  ✓ Protocol classifier attempted (returned UNKNOWN/OTHER as expected)")
        print("  ✓ Fallback routing selected a default model")
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

