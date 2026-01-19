#!/usr/bin/env python3
"""
Unit tests for CoAP v1 protocol detection.
"""

import sys
from pathlib import Path
# Add project root to path
project_root = Path(__file__).parent.parent.parent.parent.parent
sys.path.insert(0, str(project_root))

from src.context_selection_models.protocol_classifier.signatures import detect_coap
from src.context_selection_models.protocol_classifier.classifier import classify_packet
from src.context_selection_models.protocol_classifier.types import PacketMetadata, ProtocolLabel


def create_coap_get_packet():
    """Create a valid CoAP v1 GET request."""
    # CoAP Header:
    # Version=1, Type=0 (CON), TKL=0, Code=0.01 (GET), Message ID=0x1234
    return bytes([
        0x40,  # Version=1, Type=0, TKL=0
        0x01,  # Code: 0.01 (GET)
        0x12, 0x34,  # Message ID
        # Options would follow, but header is enough for detection
    ])


def create_coap_response_packet():
    """Create a valid CoAP v1 response."""
    # Version=1, Type=2 (ACK), TKL=0, Code=2.05 (Content), Message ID=0x1234
    return bytes([
        0x60,  # Version=1, Type=2, TKL=0
        0x45,  # Code: 2.05 (Content)
        0x12, 0x34,  # Message ID
    ])


def main():
    """Run CoAP tests."""
    print("=" * 80)
    print("CoAP Protocol Detection Tests")
    print("=" * 80)
    print()
    
    tests_passed = 0
    tests_failed = 0
    
    # Test 1: CoAP GET Request
    print("Test 1: CoAP GET Request")
    coap_get = create_coap_get_packet()
    is_coap, conf, ev, notes = detect_coap(coap_get)
    print(f"  Detected: {is_coap}, Confidence: {conf:.2f}, Evidence: {ev.value}")
    if is_coap and conf >= 0.85:
        print("  ✓ PASSED")
        tests_passed += 1
    else:
        print(f"  ✗ FAILED: Expected CoAP detection")
        tests_failed += 1
    print()
    
    # Test 2: CoAP Response
    print("Test 2: CoAP Response")
    coap_resp = create_coap_response_packet()
    is_coap, conf, ev, notes = detect_coap(coap_resp)
    print(f"  Detected: {is_coap}, Confidence: {conf:.2f}, Evidence: {ev.value}")
    if is_coap and conf >= 0.85:
        print("  ✓ PASSED")
        tests_passed += 1
    else:
        print(f"  ✗ FAILED: Expected CoAP detection")
        tests_failed += 1
    print()
    
    # Test 3: Too short
    print("Test 3: Too Short Payload")
    short_payload = bytes([0x40, 0x01])  # Only 2 bytes
    is_coap, conf, ev, notes = detect_coap(short_payload)
    print(f"  Detected: {is_coap}, Confidence: {conf:.2f}")
    if not is_coap:
        print("  ✓ PASSED (correctly rejected)")
        tests_passed += 1
    else:
        print(f"  ✗ FAILED: Should reject payload < 4 bytes")
        tests_failed += 1
    print()
    
    # Test 4: Invalid version
    print("Test 4: Invalid Version")
    invalid_version = bytes([
        0x00,  # Version=0 (invalid)
        0x01,
        0x12, 0x34
    ])
    is_coap, conf, ev, notes = detect_coap(invalid_version)
    print(f"  Detected: {is_coap}, Confidence: {conf:.2f}")
    if not is_coap:
        print("  ✓ PASSED (correctly rejected)")
        tests_passed += 1
    else:
        print(f"  ✗ FAILED: Should reject invalid version")
        tests_failed += 1
    print()
    
    # Test 5: Full classifier integration
    print("Test 5: Full Classifier Integration (UDP)")
    meta = PacketMetadata(
        l4_proto="udp",
        src_port=54321,
        dst_port=5683,
        captured_payload_offset=0
    )
    result = classify_packet(coap_get, meta)
    print(f"  Label: {result.label.value}, Confidence: {result.confidence:.2f}")
    if result.label == ProtocolLabel.COAP and result.confidence >= 0.85:
        print("  ✓ PASSED")
        tests_passed += 1
    else:
        print(f"  ✗ FAILED: Expected COAP label")
        tests_failed += 1
    print()
    
    # Summary
    print("=" * 80)
    print(f"CoAP Tests: {tests_passed} passed, {tests_failed} failed")
    print("=" * 80)
    
    return 0 if tests_failed == 0 else 1


if __name__ == '__main__':
    sys.exit(main())

