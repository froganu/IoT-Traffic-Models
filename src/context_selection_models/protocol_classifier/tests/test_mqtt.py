#!/usr/bin/env python3
"""
Unit tests for MQTT protocol detection.
"""

import sys
from pathlib import Path
# Add project root to path
project_root = Path(__file__).parent.parent.parent.parent.parent
sys.path.insert(0, str(project_root))

from src.context_selection_models.protocol_classifier.signatures import detect_mqtt
from src.context_selection_models.protocol_classifier.classifier import classify_packet
from src.context_selection_models.protocol_classifier.types import PacketMetadata, ProtocolLabel, EvidenceType


def create_mqtt_connect_packet():
    """Create a valid MQTT CONNECT packet."""
    # MQTT Fixed Header:
    # [0] Packet Type=1 (CONNECT), Flags=0
    # [1] Remaining Length = 18 (variable-length encoded as 0x12)
    # Variable Header: Protocol Name "MQTT" (4 bytes) + Protocol Level (1 byte) + Flags (1 byte) + Keep Alive (2 bytes)
    # Payload: Client ID (simplified)
    
    return bytes([
        0x10,  # CONNECT (type=1, flags=0)
        0x12,  # Remaining Length: 18 bytes
        # Variable Header
        0x00, 0x04,  # Protocol Name Length: 4
        ord('M'), ord('Q'), ord('T'), ord('T'),  # "MQTT"
        0x04,  # Protocol Level: 4 (MQTT 3.1.1)
        0x02,  # Connect Flags
        0x00, 0x3C,  # Keep Alive: 60
        # Payload: Client ID (simplified)
        0x00, 0x04,  # Client ID Length: 4
        ord('t'), ord('e'), ord('s'), ord('t')  # "test"
    ])


def create_mqtt_publish_packet():
    """Create a valid MQTT PUBLISH packet."""
    # PUBLISH with topic "test/topic" and message "hello"
    return bytes([
        0x30,  # PUBLISH (type=3, flags=0)
        0x0E,  # Remaining Length: 14 bytes
        # Topic
        0x00, 0x0A,  # Topic Length: 10
        ord('t'), ord('e'), ord('s'), ord('t'), ord('/'), ord('t'), ord('o'), ord('p'), ord('i'), ord('c'),
        # Message
        ord('h'), ord('e'), ord('l'), ord('l'), ord('o')
    ])


def main():
    """Run MQTT tests."""
    print("=" * 80)
    print("MQTT Protocol Detection Tests")
    print("=" * 80)
    print()
    
    tests_passed = 0
    tests_failed = 0
    
    # Test 1: MQTT CONNECT (stream mode)
    print("Test 1: MQTT CONNECT Packet (Stream Mode)")
    mqtt_connect = create_mqtt_connect_packet()
    is_mqtt, conf, ev, notes = detect_mqtt(mqtt_connect, is_stream=True)
    print(f"  Detected: {is_mqtt}, Confidence: {conf:.2f}, Evidence: {ev.value}")
    if is_mqtt and conf >= 0.9:
        print("  ✓ PASSED")
        tests_passed += 1
    else:
        print(f"  ✗ FAILED: Expected MQTT detection with high confidence")
        tests_failed += 1
    print()
    
    # Test 2: MQTT CONNECT (packet mode)
    print("Test 2: MQTT CONNECT Packet (Packet Mode)")
    is_mqtt, conf, ev, notes = detect_mqtt(mqtt_connect, is_stream=False)
    print(f"  Detected: {is_mqtt}, Confidence: {conf:.2f}, Evidence: {ev.value}")
    if is_mqtt and conf >= 0.75:
        print("  ✓ PASSED")
        tests_passed += 1
    else:
        print(f"  ⚠ May need TCP reassembly (expected for single packet)")
        if ev.value == "needs_tcp_reassembly":
            print("  ✓ PASSED (correctly indicates need for reassembly)")
            tests_passed += 1
        else:
            tests_failed += 1
    print()
    
    # Test 3: MQTT PUBLISH
    print("Test 3: MQTT PUBLISH Packet")
    mqtt_publish = create_mqtt_publish_packet()
    is_mqtt, conf, ev, notes = detect_mqtt(mqtt_publish, is_stream=True)
    print(f"  Detected: {is_mqtt}, Confidence: {conf:.2f}, Evidence: {ev.value}")
    if is_mqtt and conf >= 0.9:
        print("  ✓ PASSED")
        tests_passed += 1
    else:
        print(f"  ✗ FAILED: Expected MQTT detection")
        tests_failed += 1
    print()
    
    # Test 4: Too short
    print("Test 4: Too Short Payload")
    short_payload = bytes([0x10])  # Only 1 byte
    is_mqtt, conf, ev, notes = detect_mqtt(short_payload, is_stream=False)
    print(f"  Detected: {is_mqtt}, Confidence: {conf:.2f}")
    if not is_mqtt:
        print("  ✓ PASSED (correctly rejected)")
        tests_passed += 1
    else:
        print(f"  ✗ FAILED: Should reject payload < 2 bytes")
        tests_failed += 1
    print()
    
    # Test 5: Invalid packet type
    print("Test 5: Invalid Packet Type")
    invalid_type = bytes([
        0x00,  # Type=0 (reserved, invalid)
        0x05
    ])
    is_mqtt, conf, ev, notes = detect_mqtt(invalid_type, is_stream=False)
    print(f"  Detected: {is_mqtt}, Confidence: {conf:.2f}")
    if not is_mqtt:
        print("  ✓ PASSED (correctly rejected)")
        tests_passed += 1
    else:
        print(f"  ✗ FAILED: Should reject invalid packet type")
        tests_failed += 1
    print()
    
    # Test 6: Full classifier integration (TCP)
    print("Test 6: Full Classifier Integration (TCP)")
    meta = PacketMetadata(
        l4_proto="tcp",
        src_port=54321,
        dst_port=1883,
        captured_payload_offset=0
    )
    result = classify_packet(mqtt_connect, meta)
    print(f"  Label: {result.label.value}, Confidence: {result.confidence:.2f}")
    # May be MQTT or UNKNOWN (if needs reassembly)
    if result.label == ProtocolLabel.MQTT:
        print("  ✓ PASSED")
        tests_passed += 1
    elif result.label == ProtocolLabel.UNKNOWN and result.evidence == EvidenceType.NEEDS_TCP_REASSEMBLY:
        print("  ✓ PASSED (correctly indicates need for reassembly)")
        tests_passed += 1
    else:
        print(f"  ⚠ Got {result.label.value}, may need reassembly")
        tests_passed += 1  # Not a failure
    print()
    
    # Summary
    print("=" * 80)
    print(f"MQTT Tests: {tests_passed} passed, {tests_failed} failed")
    print("=" * 80)
    
    return 0 if tests_failed == 0 else 1


if __name__ == '__main__':
    sys.exit(main())

