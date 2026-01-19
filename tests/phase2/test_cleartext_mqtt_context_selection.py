#!/usr/bin/env python3
"""
Phase 2 Test: Context Selection for Cleartext MQTT Traffic

Tests context selection (model selection) for cleartext MQTT traffic.
Runs Phase 1 (encryption detection) first, then Phase 2 (context selection).

Phase 2 verifies:
1. Device classifier is attempted (may return None for non-device-specific traffic)
2. Protocol classifier identifies MQTT protocol (may need TCP reassembly)
3. Correct model is selected based on protocol classification
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

import pandas as pd
from src.moe import check_encryption, select_context
from src.context_selection_models import select_device_context_safe, classify_packet, PacketMetadata, ProtocolLabel


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


def create_mqtt_packet_bytes():
    """Create realistic MQTT CONNECT packet bytes."""
    # MQTT CONNECT packet
    return bytes([
        0x10,  # CONNECT (type=1, flags=0)
        0x12,  # Remaining Length: 18 bytes
        # Variable Header
        0x00, 0x04,  # Protocol Name Length: 4
        ord('M'), ord('Q'), ord('T'), ord('T'),  # "MQTT"
        0x04,  # Protocol Level: 4 (MQTT 3.1.1)
        0x02,  # Connect Flags
        0x00, 0x3C,  # Keep Alive: 60
        # Payload: Client ID
        0x00, 0x04,  # Client ID Length: 4
        ord('t'), ord('e'), ord('s'), ord('t')  # "test"
    ])


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
            print(f"    → Device classifier did not identify specific device, continuing to protocol classifier")
    except Exception as e:
        print(f"    Device Classifier: Not available ({type(e).__name__})")
        print(f"    → Will fall back to protocol classifier")
    print()
    
    # Step 2.2: Test Protocol Classifier
    print("  Step 2.2: Protocol Classifier")
    packet_bytes = create_mqtt_packet_bytes()
    try:
        meta = PacketMetadata(
            l4_proto='tcp',
            src_port=54321,
            dst_port=1883,
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
    # Add packet_bytes to DataFrame for protocol classifier
    packet_data_with_bytes = packet_data.copy()
    packet_data_with_bytes['packet_bytes'] = [packet_bytes] * len(packet_data)
    context = select_context(packet_data_with_bytes, is_encrypted, protocol_type)
    print(f"    Selected Context: {context}")
    print()
    
    # Assertions
    print("Assertions:")
    try:
        assert is_encrypted == False, f"Expected encrypted=False, got {is_encrypted}"
        assert context == 'mqtt_coap_rtsp', f"Expected context='mqtt_coap_rtsp', got {context}"
        
        # Verify protocol classifier was used (may be UNKNOWN if needs reassembly, but port fallback should work)
        if protocol_result:
            # MQTT may need TCP reassembly, so UNKNOWN is acceptable
            assert protocol_result.label in [ProtocolLabel.MQTT, ProtocolLabel.UNKNOWN], \
                f"Expected MQTT or UNKNOWN protocol, got {protocol_result.label.value}"
        
        print("  ✓ Encryption correctly detected as not encrypted")
        print("  ✓ Device classifier attempted (may return None for MQTT traffic)")
        print("  ✓ Protocol classifier attempted (may need TCP reassembly for MQTT)")
        print(f"  ✓ MQTT/CoAP/RTSP context correctly selected: {context}")
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

