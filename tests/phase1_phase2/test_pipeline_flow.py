#!/usr/bin/env python3
"""
Phase 1 + Phase 2 Pipeline Flow Test

Tests the complete pipeline flow:
1. Phase 1: Encryption Detection
2. Phase 2: Context Selection (Device Classifier + Protocol Classifier)

Verifies the full flow works correctly for different traffic types.
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

import pandas as pd
from src.moe import check_encryption, select_ai_model
from src.context_selection_models import (
    select_device_context_safe,
    classify_packet,
    PacketMetadata,
    ProtocolLabel
)


def create_dns_packet_bytes():
    """Create DNS query packet."""
    return bytes([
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x03, ord('w'), ord('w'), ord('w'),
        0x07, ord('e'), ord('x'), ord('a'), ord('m'), ord('p'), ord('l'), ord('e'),
        0x03, ord('c'), ord('o'), ord('m'), 0x00, 0x00, 0x01, 0x00, 0x01
    ])


def create_tls_packet_bytes():
    """Create TLS handshake packet."""
    return bytes([
        0x16,  # Content Type: Handshake
        0x03, 0x03,  # Version: TLS 1.2
        0x00, 0x05,  # Length: 5 bytes
        0x01,  # Handshake Type: ClientHello
        0x00, 0x00, 0x01, 0x00  # Partial handshake message
    ])


def create_mqtt_packet_bytes():
    """Create MQTT CONNECT packet."""
    return bytes([
        0x10, 0x12,  # CONNECT, Remaining Length
        0x00, 0x04, ord('M'), ord('Q'), ord('T'), ord('T'),  # Protocol Name
        0x04, 0x02, 0x00, 0x3C,  # Protocol Level, Flags, Keep Alive
        0x00, 0x04, ord('t'), ord('e'), ord('s'), ord('t')  # Client ID
    ])


def create_coap_packet_bytes():
    """Create CoAP GET request."""
    return bytes([
        0x40,  # Version=1, Type=0, TKL=0
        0x01,  # Code: 0.01 (GET)
        0x12, 0x34,  # Message ID
    ])


def test_pipeline_flow(test_name, packet_data, packet_bytes, port, protocol, 
                       expected_encrypted, expected_protocol_type, expected_model):
    """
    Test the complete pipeline flow (Phase 1 → Phase 2).
    
    Args:
        test_name: Name of the test case
        packet_data: DataFrame with packet features
        packet_bytes: Raw packet bytes
        port: Destination port
        protocol: L4 protocol (tcp/udp)
        expected_encrypted: Expected encryption status
        expected_protocol_type: Expected protocol type from Phase 1
        expected_model: Expected model name from Phase 2
    """
    print(f"\n{'=' * 80}")
    print(f"Test: {test_name}")
    print(f"{'=' * 80}")
    print()
    
    # Phase 1: Encryption Detection
    print("Phase 1: Encryption Detection")
    print("-" * 80)
    is_encrypted, protocol_type = check_encryption(
        packet_data,
        port=port,
        protocol=protocol,
        packet_bytes=packet_bytes
    )
    print(f"  Encrypted: {is_encrypted} (expected: {expected_encrypted})")
    print(f"  Protocol Type: {protocol_type} (expected: {expected_protocol_type})")
    
    # Verify Phase 1
    phase1_passed = (is_encrypted == expected_encrypted and 
                     protocol_type == expected_protocol_type)
    if phase1_passed:
        print("  ✓ Phase 1 PASSED")
    else:
        print(f"  ✗ Phase 1 FAILED: Expected encrypted={expected_encrypted}, protocol_type={expected_protocol_type}")
    print()
    
    # Phase 2: Context Selection
    print("Phase 2: Context Selection")
    print("-" * 80)
    
    # Step 2.1: Device Classifier
    print("  Step 2.1: Device Classifier")
    device_result = None
    try:
        device_type, device_confidence = select_device_context_safe(packet_data)
        if device_type is not None:
            print(f"    Device Type: {device_type} (confidence: {device_confidence:.2f})")
            device_result = (device_type, device_confidence)
        else:
            print(f"    Device Type: None (no specific device identified)")
    except Exception as e:
        print(f"    Device Classifier: Not available ({type(e).__name__})")
    print()
    
    # Step 2.2: Protocol Classifier (only for non-encrypted)
    protocol_result = None
    if not is_encrypted:
        print("  Step 2.2: Protocol Classifier")
        try:
            meta = PacketMetadata(
                l4_proto=protocol,
                src_port=packet_data['src_port'].iloc[0] if 'src_port' in packet_data.columns else 54321,
                dst_port=port,
                captured_payload_offset=0
            )
            protocol_result = classify_packet(packet_bytes, meta)
            print(f"    Protocol: {protocol_result.label.value}")
            print(f"    Confidence: {protocol_result.confidence:.2f}")
            print(f"    Evidence: {protocol_result.evidence.value}")
        except Exception as e:
            print(f"    Protocol Classifier: Error ({type(e).__name__}: {e})")
        print()
    else:
        print("  Step 2.2: Protocol Classifier (SKIPPED - encrypted traffic)")
        print()
    
    # Step 2.3: Full Context Selection
    print("  Step 2.3: Full Context Selection")
    # Add packet_bytes to DataFrame if available
    packet_data_with_bytes = packet_data.copy()
    if packet_bytes:
        packet_data_with_bytes['packet_bytes'] = [packet_bytes] * len(packet_data)
    
    model_name = select_ai_model(packet_data_with_bytes, is_encrypted, protocol_type)
    print(f"    Selected Model: {model_name} (expected: {expected_model})")
    print()
    
    # Verify Phase 2
    phase2_passed = (model_name == expected_model)
    if phase2_passed:
        print("  ✓ Phase 2 PASSED")
    else:
        print(f"  ✗ Phase 2 FAILED: Expected model={expected_model}, got {model_name}")
    print()
    
    # Overall result
    overall_passed = phase1_passed and phase2_passed
    if overall_passed:
        print(f"✓ {test_name}: PASSED")
    else:
        print(f"✗ {test_name}: FAILED")
    
    return {
        'test_name': test_name,
        'phase1_passed': phase1_passed,
        'phase2_passed': phase2_passed,
        'overall_passed': overall_passed,
        'device_result': device_result,
        'protocol_result': protocol_result,
        'model_name': model_name
    }


def main():
    """Run all pipeline flow tests."""
    print("=" * 80)
    print("Phase 1 + Phase 2 Pipeline Flow Tests")
    print("=" * 80)
    print()
    print("Testing complete pipeline flow:")
    print("  1. Phase 1: Encryption Detection")
    print("  2. Phase 2: Context Selection (Device Classifier + Protocol Classifier)")
    print()
    
    results = []
    
    # Test 1: Encrypted TLS Traffic
    print("\n" + "=" * 80)
    tls_data = pd.DataFrame({
        'packet_size': [500, 600, 550],
        'direction': [1, 0, 1],
        'dst_port': [443] * 3,
        'src_port': [54321] * 3,
        'protocol': ['tcp'] * 3,
    })
    tls_bytes = create_tls_packet_bytes()
    result1 = test_pipeline_flow(
        "Encrypted TLS Traffic",
        tls_data,
        tls_bytes,
        port=443,
        protocol='tcp',
        expected_encrypted=True,
        expected_protocol_type='tls',
        expected_model='tls_model'
    )
    results.append(result1)
    
    # Test 2: Cleartext DNS Traffic
    print("\n" + "=" * 80)
    dns_data = pd.DataFrame({
        'packet_size': [100, 120, 110],
        'direction': [1, 0, 1],
        'dst_port': [53] * 3,
        'src_port': [54321] * 3,
        'protocol': ['udp'] * 3,
    })
    dns_bytes = create_dns_packet_bytes()
    result2 = test_pipeline_flow(
        "Cleartext DNS Traffic",
        dns_data,
        dns_bytes,
        port=53,
        protocol='udp',
        expected_encrypted=False,
        expected_protocol_type=None,
        expected_model='dns_model'
    )
    results.append(result2)
    
    # Test 3: Cleartext MQTT Traffic
    print("\n" + "=" * 80)
    mqtt_data = pd.DataFrame({
        'packet_size': [200, 300, 250],
        'direction': [1, 0, 1],
        'dst_port': [1883] * 3,
        'src_port': [54321] * 3,
        'protocol': ['tcp'] * 3,
    })
    mqtt_bytes = create_mqtt_packet_bytes()
    result3 = test_pipeline_flow(
        "Cleartext MQTT Traffic",
        mqtt_data,
        mqtt_bytes,
        port=1883,
        protocol='tcp',
        expected_encrypted=False,
        expected_protocol_type=None,
        expected_model='mqtt_model'
    )
    results.append(result3)
    
    # Test 4: Cleartext CoAP Traffic
    print("\n" + "=" * 80)
    coap_data = pd.DataFrame({
        'packet_size': [50, 60, 55],
        'direction': [1, 0, 1],
        'dst_port': [5683] * 3,
        'src_port': [54321] * 3,
        'protocol': ['udp'] * 3,
    })
    coap_bytes = create_coap_packet_bytes()
    result4 = test_pipeline_flow(
        "Cleartext CoAP Traffic",
        coap_data,
        coap_bytes,
        port=5683,
        protocol='udp',
        expected_encrypted=False,
        expected_protocol_type=None,
        expected_model='mqtt_coap_rtsp_model'
    )
    results.append(result4)
    
    # Test 5: Unknown Traffic
    print("\n" + "=" * 80)
    unknown_data = pd.DataFrame({
        'packet_size': [150, 200, 180],
        'direction': [1, 0, 1],
        'dst_port': [12345] * 3,
        'src_port': [54321] * 3,
        'protocol': ['tcp'] * 3,
    })
    unknown_bytes = b'\x00\x01\x02\x03\x04\x05'
    result5 = test_pipeline_flow(
        "Unknown Traffic",
        unknown_data,
        unknown_bytes,
        port=12345,
        protocol='tcp',
        expected_encrypted=False,
        expected_protocol_type=None,
        expected_model='mqtt_coap_rtsp_model'  # Default fallback
    )
    results.append(result5)
    
    # Summary
    print("\n" + "=" * 80)
    print("PIPELINE FLOW TEST SUMMARY")
    print("=" * 80)
    print()
    
    phase1_passed = sum(1 for r in results if r['phase1_passed'])
    phase2_passed = sum(1 for r in results if r['phase2_passed'])
    overall_passed = sum(1 for r in results if r['overall_passed'])
    total = len(results)
    
    print(f"Phase 1 (Encryption Detection): {phase1_passed}/{total} tests passed")
    print(f"Phase 2 (Context Selection): {phase2_passed}/{total} tests passed")
    print(f"Overall Pipeline Flow: {overall_passed}/{total} tests passed")
    print()
    
    print("Detailed Results:")
    for r in results:
        status = "PASSED ✓" if r['overall_passed'] else "FAILED ✗"
        print(f"  {r['test_name']:30s} {status}")
    print()
    
    if overall_passed == total:
        print("=" * 80)
        print("ALL PIPELINE FLOW TESTS PASSED ✓")
        print("=" * 80)
        return 0
    else:
        print("=" * 80)
        print(f"SOME TESTS FAILED ({total - overall_passed}/{total})")
        print("=" * 80)
        return 1


if __name__ == '__main__':
    sys.exit(main())

