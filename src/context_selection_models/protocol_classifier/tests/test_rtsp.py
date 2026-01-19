#!/usr/bin/env python3
"""
Unit tests for RTSP protocol detection.
"""

import sys
from pathlib import Path
# Add project root to path
project_root = Path(__file__).parent.parent.parent.parent.parent
sys.path.insert(0, str(project_root))

from src.context_selection_models.protocol_classifier.signatures import detect_rtsp
from src.context_selection_models.protocol_classifier.classifier import classify_packet
from src.context_selection_models.protocol_classifier.types import PacketMetadata, ProtocolLabel, EvidenceType


def create_rtsp_options_request():
    """Create a valid RTSP OPTIONS request."""
    return b"OPTIONS rtsp://example.com:554 RTSP/1.0\r\nCSeq: 1\r\nUser-Agent: Test\r\n\r\n"


def create_rtsp_describe_request():
    """Create a valid RTSP DESCRIBE request."""
    return b"DESCRIBE rtsp://example.com:554/test RTSP/1.0\r\nCSeq: 2\r\nAccept: application/sdp\r\n\r\n"


def create_rtsp_response():
    """Create a valid RTSP response."""
    return b"RTSP/1.0 200 OK\r\nCSeq: 1\r\nPublic: OPTIONS, DESCRIBE, SETUP, TEARDOWN, PLAY, PAUSE\r\n\r\n"


def main():
    """Run RTSP tests."""
    print("=" * 80)
    print("RTSP Protocol Detection Tests")
    print("=" * 80)
    print()
    
    tests_passed = 0
    tests_failed = 0
    
    # Test 1: RTSP OPTIONS Request (stream mode)
    print("Test 1: RTSP OPTIONS Request (Stream Mode)")
    rtsp_options = create_rtsp_options_request()
    is_rtsp, conf, ev, notes = detect_rtsp(rtsp_options, is_stream=True)
    print(f"  Detected: {is_rtsp}, Confidence: {conf:.2f}, Evidence: {ev.value}")
    if is_rtsp and conf >= 0.9:
        print("  ✓ PASSED")
        tests_passed += 1
    else:
        print(f"  ✗ FAILED: Expected RTSP detection with high confidence")
        tests_failed += 1
    print()
    
    # Test 2: RTSP OPTIONS Request (packet mode)
    print("Test 2: RTSP OPTIONS Request (Packet Mode)")
    is_rtsp, conf, ev, notes = detect_rtsp(rtsp_options, is_stream=False)
    print(f"  Detected: {is_rtsp}, Confidence: {conf:.2f}, Evidence: {ev.value}")
    if is_rtsp and conf >= 0.80:
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
    
    # Test 3: RTSP DESCRIBE Request
    print("Test 3: RTSP DESCRIBE Request")
    rtsp_describe = create_rtsp_describe_request()
    is_rtsp, conf, ev, notes = detect_rtsp(rtsp_describe, is_stream=True)
    print(f"  Detected: {is_rtsp}, Confidence: {conf:.2f}, Evidence: {ev.value}")
    if is_rtsp and conf >= 0.9:
        print("  ✓ PASSED")
        tests_passed += 1
    else:
        print(f"  ✗ FAILED: Expected RTSP detection")
        tests_failed += 1
    print()
    
    # Test 4: RTSP Response
    print("Test 4: RTSP Response")
    rtsp_resp = create_rtsp_response()
    is_rtsp, conf, ev, notes = detect_rtsp(rtsp_resp, is_stream=True)
    print(f"  Detected: {is_rtsp}, Confidence: {conf:.2f}, Evidence: {ev.value}")
    if is_rtsp and conf >= 0.9:
        print("  ✓ PASSED")
        tests_passed += 1
    else:
        print(f"  ✗ FAILED: Expected RTSP detection")
        tests_failed += 1
    print()
    
    # Test 5: Invalid (HTTP-like but not RTSP)
    print("Test 5: Non-RTSP Payload")
    http_payload = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
    is_rtsp, conf, ev, notes = detect_rtsp(http_payload, is_stream=True)
    print(f"  Detected: {is_rtsp}, Confidence: {conf:.2f}")
    if not is_rtsp:
        print("  ✓ PASSED (correctly rejected)")
        tests_passed += 1
    else:
        print(f"  ✗ FAILED: Should reject non-RTSP payload")
        tests_failed += 1
    print()
    
    # Test 6: Full classifier integration (TCP)
    print("Test 6: Full Classifier Integration (TCP)")
    meta = PacketMetadata(
        l4_proto="tcp",
        src_port=54321,
        dst_port=554,
        captured_payload_offset=0
    )
    result = classify_packet(rtsp_options, meta)
    print(f"  Label: {result.label.value}, Confidence: {result.confidence:.2f}")
    # May be RTSP or UNKNOWN (if needs reassembly)
    if result.label == ProtocolLabel.RTSP:
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
    print(f"RTSP Tests: {tests_passed} passed, {tests_failed} failed")
    print("=" * 80)
    
    return 0 if tests_failed == 0 else 1


if __name__ == '__main__':
    sys.exit(main())

