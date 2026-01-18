"""
Smoke tests for encryption detector.
"""

import unittest
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from src.encryption_detector.detector import EncryptionDetector, analyze_packet
from src.encryption_detector.pcap_reader import Flow, Packet


class TestDetectorSmoke(unittest.TestCase):
    """Smoke tests for detector functionality."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.detector = EncryptionDetector()
    
    def test_tls_packet_detection(self):
        """Test TLS packet detection."""
        # TLS ClientHello record
        tls_packet = bytes([
            0x16,  # Handshake
            0x03, 0x03,  # TLS 1.2
            0x00, 0x05,  # Length
            0x01,  # ClientHello
            0x00, 0x00, 0x01, 0x00
        ])
        
        result = analyze_packet(tls_packet, port=443, protocol='tcp')
        self.assertTrue(result.encrypted, "TLS packet should be detected as encrypted")
        self.assertEqual(result.encrypted_family.value, 'tls')
        self.assertGreater(result.confidence, 0.9)
    
    def test_dns_packet_detection(self):
        """Test DNS packet detection."""
        # DNS query
        dns_packet = bytes([
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
        
        result = analyze_packet(dns_packet, port=53, protocol='udp')
        self.assertFalse(result.encrypted, "DNS packet should be detected as cleartext")
        self.assertEqual(result.state.value, 'cleartext')
        self.assertGreater(result.confidence, 0.9)
    
    def test_http_packet_detection(self):
        """Test HTTP packet detection."""
        http_packet = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n"
        
        result = analyze_packet(http_packet, port=80, protocol='tcp')
        self.assertFalse(result.encrypted, "HTTP packet should be detected as cleartext")
        self.assertEqual(result.state.value, 'cleartext')
    
    def test_port_heuristic(self):
        """Test port-based heuristics."""
        # Unknown protocol on port 443
        unknown_packet = bytes([0x00, 0x01, 0x02, 0x03, 0x04])
        
        result = analyze_packet(unknown_packet, port=443, protocol='tcp')
        # Should use port heuristic
        self.assertTrue(result.encrypted, "Port 443 should suggest encryption")
        self.assertEqual(result.evidence.value, 'port_heuristic')
        self.assertGreater(result.confidence, 0.6)
        self.assertLess(result.confidence, 0.9)  # Lower than framing-based
    
    def test_unknown_packet(self):
        """Test unknown packet handling."""
        # Random bytes
        unknown_packet = bytes([0x12, 0x34, 0x56, 0x78])
        
        result = analyze_packet(unknown_packet, port=12345, protocol='tcp')
        # Should be unknown
        self.assertEqual(result.state.value, 'unknown')
        self.assertEqual(result.evidence.value, 'insufficient')
        self.assertLessEqual(result.confidence, 0.5)
    
    def test_flow_detection(self):
        """Test flow-level detection."""
        # Create a simple flow with TLS packet
        flow = Flow(
            flow_id='test-flow-1',
            src_ip='192.168.1.1',
            src_port=54321,
            dst_ip='10.0.0.1',
            dst_port=443,
            protocol='tcp'
        )
        
        # Add TLS packet
        tls_packet = Packet(
            timestamp=1000.0,
            src_ip='192.168.1.1',
            src_port=54321,
            dst_ip='10.0.0.1',
            dst_port=443,
            protocol='tcp',
            payload=bytes([
                0x16, 0x03, 0x03, 0x00, 0x05,
                0x01, 0x00, 0x00, 0x01, 0x00
            ]),
            payload_length=10,
            packet_length=100
        )
        
        flow.add_packet(tls_packet)
        
        result = self.detector.detect_flow(flow)
        self.assertTrue(result.encrypted, "TLS flow should be detected as encrypted")
        self.assertEqual(result.encrypted_family.value, 'tls')
        self.assertGreater(result.confidence, 0.9)
        self.assertEqual(result.flow_id, 'test-flow-1')


if __name__ == '__main__':
    unittest.main()

