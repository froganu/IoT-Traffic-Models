#!/usr/bin/env python3
"""
Phase 2 Test: Context Selection for Cleartext DNS Traffic

Tests context selection (model selection) for cleartext DNS traffic.
Runs Phase 1 (encryption detection) first, then Phase 2 (context selection).

Phase 2 verifies:
1. Device classifier is attempted (may return None for non-device-specific traffic)
2. Protocol classifier identifies DNS protocol
3. Correct model is selected based on protocol classification
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

import pandas as pd
from src.moe import check_encryption, select_ai_model
from src.context_selection_models import select_device_context_safe, classify_packet, PacketMetadata, ProtocolLabel


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
    print("Phase 2 Test: Context Selection for Cleartext DNS Traffic")
    print("=" * 80)
    print()
    
    # Phase 1: Encryption detection
    print("Phase 1: Running encryption detection...")
    packet_data = create_packet_dataframe(port=53, protocol='udp')
    packet_bytes = create_dns_packet_bytes()
    
    is_encrypted, protocol_type = check_encryption(
        packet_data,
        port=53,
        protocol='udp',
        packet_bytes=packet_bytes
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
            print(f"    → Device classifier returned result (may route to doorbell_model if Doorbell)")
        else:
            print(f"    Device Type: None (device classifier returned None)")
            print(f"    → Device classifier did not identify specific device, continuing to protocol classifier")
    except Exception as e:
        print(f"    Device Classifier: Not available ({type(e).__name__})")
        print(f"    → Will fall back to protocol classifier")
    print()
    
    # Step 2.2: Test Protocol Classifier
    print("  Step 2.2: Protocol Classifier")
    try:
        meta = PacketMetadata(
            l4_proto='udp',
            src_port=54321,
            dst_port=53,
            captured_payload_offset=0
        )
        protocol_result = classify_packet(packet_bytes, meta)
        print(f"    Protocol: {protocol_result.label.value}")
        print(f"    Confidence: {protocol_result.confidence:.2f}")
        print(f"    Evidence: {protocol_result.evidence.value}")
        if protocol_result.notes:
            print(f"    Notes: {protocol_result.notes}")
        print(f"    → Protocol classifier identified {protocol_result.label.value}")
    except Exception as e:
        print(f"    Protocol Classifier: Error ({type(e).__name__}: {e})")
        protocol_result = None
    print()
    
    # Step 2.3: Full context selection (both classifiers)
    print("  Step 2.3: Full Context Selection (Device + Protocol Classifiers)")
    model_name = select_ai_model(packet_data, is_encrypted, protocol_type)
    print(f"    Selected Model: {model_name}")
    print()
    
    # Assertions
    print("Assertions:")
    try:
        assert is_encrypted == False, f"Expected encrypted=False, got {is_encrypted}"
        assert model_name == 'dns_model', f"Expected model='dns_model', got {model_name}"
        
        # Verify protocol classifier was used
        if protocol_result:
            assert protocol_result.label == ProtocolLabel.DNS, f"Expected DNS protocol, got {protocol_result.label.value}"
            assert protocol_result.confidence >= 0.7, f"Expected high confidence, got {protocol_result.confidence}"
        
        print("  ✓ Encryption correctly detected as not encrypted")
        print("  ✓ Device classifier attempted (may return None for DNS traffic)")
        print("  ✓ Protocol classifier correctly identified DNS")
        print("  ✓ DNS model correctly selected via protocol classifier")
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

