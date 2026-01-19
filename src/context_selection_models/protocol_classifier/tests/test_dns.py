#!/usr/bin/env python3
"""
Unit tests for DNS protocol detection.
"""

import sys
from pathlib import Path
# Add project root to path
project_root = Path(__file__).parent.parent.parent.parent.parent
sys.path.insert(0, str(project_root))

from src.context_selection_models.protocol_classifier.signatures import detect_dns
from src.context_selection_models.protocol_classifier.classifier import classify_packet
from src.context_selection_models.protocol_classifier.types import PacketMetadata, ProtocolLabel, EvidenceType


def create_dns_query_packet():
    """Create a valid DNS query packet."""
    return bytes([
        0x12, 0x34,  # Transaction ID
        0x01, 0x00,  # Flags: QR=0 (query), Opcode=0
        0x00, 0x01,  # QDCOUNT: 1 question
        0x00, 0x00,  # ANCOUNT: 0 answers
        0x00, 0x00,  # NSCOUNT: 0 authority
        0x00, 0x00,  # ARCOUNT: 0 additional
        # Question section
        0x03, ord('w'), ord('w'), ord('w'),  # "www"
        0x07, ord('e'), ord('x'), ord('a'), ord('m'), ord('p'), ord('l'), ord('e'),  # "example"
        0x03, ord('c'), ord('o'), ord('m'),  # "com"
        0x00,  # End of QNAME
        0x00, 0x01,  # QTYPE: A record
        0x00, 0x01   # QCLASS: IN
    ])


def create_dns_response_packet():
    """Create a valid DNS response packet."""
    return bytes([
        0x12, 0x34,  # Transaction ID
        0x81, 0x80,  # Flags: QR=1 (response), AA=1, RD=1, RA=1
        0x00, 0x01,  # QDCOUNT: 1 question
        0x00, 0x01,  # ANCOUNT: 1 answer
        0x00, 0x00,  # NSCOUNT: 0 authority
        0x00, 0x00,  # ARCOUNT: 0 additional
        # Question section (same as query)
        0x03, ord('w'), ord('w'), ord('w'),
        0x07, ord('e'), ord('x'), ord('a'), ord('m'), ord('p'), ord('l'), ord('e'),
        0x03, ord('c'), ord('o'), ord('m'),
        0x00,
        0x00, 0x01,  # QTYPE
        0x00, 0x01,  # QCLASS
        # Answer section (simplified)
        0xC0, 0x0C,  # Name pointer
        0x00, 0x01,  # Type: A
        0x00, 0x01,  # Class: IN
        0x00, 0x00, 0x00, 0x3C,  # TTL: 60
        0x00, 0x04,  # Data length: 4
        0x7F, 0x00, 0x00, 0x01  # IP: 127.0.0.1
    ])


def main():
    """Run DNS tests."""
    print("=" * 80)
    print("DNS Protocol Detection Tests")
    print("=" * 80)
    print()
    
    tests_passed = 0
    tests_failed = 0
    
    # Test 1: DNS Query
    print("Test 1: DNS Query Packet")
    dns_query = create_dns_query_packet()
    is_dns, conf, ev, notes = detect_dns(dns_query)
    print(f"  Detected: {is_dns}, Confidence: {conf:.2f}, Evidence: {ev.value}")
    if is_dns and conf >= 0.9:
        print("  ✓ PASSED")
        tests_passed += 1
    else:
        print(f"  ✗ FAILED: Expected DNS detection with high confidence")
        tests_failed += 1
    print()
    
    # Test 2: DNS Response
    print("Test 2: DNS Response Packet")
    dns_response = create_dns_response_packet()
    is_dns, conf, ev, notes = detect_dns(dns_response)
    print(f"  Detected: {is_dns}, Confidence: {conf:.2f}, Evidence: {ev.value}")
    if is_dns and conf >= 0.9:
        print("  ✓ PASSED")
        tests_passed += 1
    else:
        print(f"  ✗ FAILED: Expected DNS detection with high confidence")
        tests_failed += 1
    print()
    
    # Test 3: Too short
    print("Test 3: Too Short Payload")
    short_payload = bytes([0x12, 0x34, 0x01, 0x00])  # Only 4 bytes
    is_dns, conf, ev, notes = detect_dns(short_payload)
    print(f"  Detected: {is_dns}, Confidence: {conf:.2f}, Evidence: {ev.value}")
    if not is_dns:
        print("  ✓ PASSED (correctly rejected)")
        tests_passed += 1
    else:
        print(f"  ✗ FAILED: Should reject payload < 12 bytes")
        tests_failed += 1
    print()
    
    # Test 4: Full classifier integration
    print("Test 4: Full Classifier Integration (UDP)")
    meta = PacketMetadata(
        l4_proto="udp",
        src_port=54321,
        dst_port=53,
        captured_payload_offset=0
    )
    result = classify_packet(dns_query, meta)
    print(f"  Label: {result.label.value}, Confidence: {result.confidence:.2f}")
    if result.label == ProtocolLabel.DNS and result.confidence >= 0.9:
        print("  ✓ PASSED")
        tests_passed += 1
    else:
        print(f"  ✗ FAILED: Expected DNS label")
        tests_failed += 1
    print()
    
    # Summary
    print("=" * 80)
    print(f"DNS Tests: {tests_passed} passed, {tests_failed} failed")
    print("=" * 80)
    
    return 0 if tests_failed == 0 else 1


if __name__ == '__main__':
    sys.exit(main())

