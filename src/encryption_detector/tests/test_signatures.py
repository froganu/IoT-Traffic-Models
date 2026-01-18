"""
Unit tests for protocol signature detection.
"""

import unittest
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from src.encryption_detector.signatures import (
    detect_tls_record,
    detect_tls_handshake,
    detect_dtls_record,
    detect_quic_header,
    detect_dns,
    detect_http,
    detect_mqtt,
    detect_coap,
    detect_rtsp
)


class TestTLSSignatures(unittest.TestCase):
    """Test TLS signature detection."""
    
    def test_tls_record_valid(self):
        """Test valid TLS record detection."""
        # TLS ClientHello record (simplified)
        # Content Type: 0x16 (Handshake)
        # Version: 0x03 0x03 (TLS 1.2)
        # Length: 0x00 0x05
        tls_record = bytes([0x16, 0x03, 0x03, 0x00, 0x05, 0x01, 0x00, 0x00, 0x01, 0x00])
        
        detected, error = detect_tls_record(tls_record)
        self.assertTrue(detected, f"TLS record not detected: {error}")
    
    def test_tls_record_invalid_content_type(self):
        """Test invalid TLS content type."""
        invalid_record = bytes([0x20, 0x03, 0x03, 0x00, 0x05])
        detected, error = detect_tls_record(invalid_record)
        self.assertFalse(detected)
    
    def test_tls_record_too_short(self):
        """Test TLS record with insufficient length."""
        short_record = bytes([0x16, 0x03, 0x03])
        detected, error = detect_tls_record(short_record)
        self.assertFalse(detected)
    
    def test_tls_handshake(self):
        """Test TLS handshake detection."""
        # TLS Handshake record with ClientHello
        tls_handshake = bytes([
            0x16,  # Handshake
            0x03, 0x03,  # TLS 1.2
            0x00, 0x05,  # Length
            0x01,  # ClientHello
            0x00, 0x00, 0x01, 0x00
        ])
        
        detected, error = detect_tls_handshake(tls_handshake)
        self.assertTrue(detected, f"TLS handshake not detected: {error}")


class TestDTLSSignatures(unittest.TestCase):
    """Test DTLS signature detection."""
    
    def test_dtls_record_valid(self):
        """Test valid DTLS record detection."""
        # DTLS record header
        # Content Type: 0x16 (Handshake)
        # Version: 0xFE 0xFD (DTLS 1.2)
        # Epoch: 0x00 0x00
        # Sequence: 0x00 0x00 0x00 0x00 0x00 0x00
        # Length: 0x00 0x05
        dtls_record = bytes([
            0x16,  # Content Type
            0xFE, 0xFD,  # Version
            0x00, 0x00,  # Epoch
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  # Sequence
            0x00, 0x05  # Length
        ])
        
        detected, error = detect_dtls_record(dtls_record)
        self.assertTrue(detected, f"DTLS record not detected: {error}")


class TestQUICSignatures(unittest.TestCase):
    """Test QUIC signature detection."""
    
    def test_quic_long_header(self):
        """Test QUIC long header detection."""
        # QUIC long header
        # Bit 7 = 1 (long header)
        # Bit 6 = 1 (fixed bit)
        # Version: 0x00 0x00 0x00 0x01 (QUIC v1)
        # DCID length: 0x08
        quic_header = bytes([
            0xC0,  # Long header + fixed bit
            0x00, 0x00, 0x00, 0x01,  # Version
            0x08,  # DCID length
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08  # DCID
        ])
        
        detected, error = detect_quic_header(quic_header)
        self.assertTrue(detected, f"QUIC header not detected: {error}")


class TestCleartextSignatures(unittest.TestCase):
    """Test cleartext protocol signatures."""
    
    def test_dns_query(self):
        """Test DNS query detection."""
        # DNS query header + question
        dns_query = bytes([
            0x12, 0x34,  # Transaction ID
            0x01, 0x00,  # Flags (query)
            0x00, 0x01,  # QDCOUNT = 1
            0x00, 0x00,  # ANCOUNT = 0
            0x00, 0x00,  # NSCOUNT = 0
            0x00, 0x00,  # ARCOUNT = 0
            0x03, ord('w'), ord('w'), ord('w'),  # www
            0x07, ord('e'), ord('x'), ord('a'), ord('m'), ord('p'), ord('l'), ord('e'),  # example
            0x03, ord('c'), ord('o'), ord('m'),  # com
            0x00,  # End of name
            0x00, 0x01,  # QTYPE = A
            0x00, 0x01   # QCLASS = IN
        ])
        
        detected, error = detect_dns(dns_query)
        self.assertTrue(detected, f"DNS not detected: {error}")
    
    def test_http_request(self):
        """Test HTTP request detection."""
        http_request = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n"
        detected, error = detect_http(http_request)
        self.assertTrue(detected, f"HTTP not detected: {error}")
    
    def test_http_response(self):
        """Test HTTP response detection."""
        http_response = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n"
        detected, error = detect_http(http_response)
        self.assertTrue(detected, f"HTTP not detected: {error}")
    
    def test_mqtt_connect(self):
        """Test MQTT CONNECT packet detection."""
        # MQTT CONNECT packet
        # Message type: 0x10 (CONNECT)
        # Remaining length: 0x0E
        mqtt_packet = bytes([
            0x10,  # CONNECT
            0x0E,  # Remaining length
            0x00, 0x04,  # Protocol name length
            ord('M'), ord('Q'), ord('T'), ord('T'),  # Protocol name
            0x04,  # Protocol level
            0x02,  # Connect flags
            0x00, 0x3C,  # Keep alive
            0x00, 0x04,  # Client ID length
            ord('t'), ord('e'), ord('s'), ord('t')  # Client ID
        ])
        
        detected, error = detect_mqtt(mqtt_packet)
        self.assertTrue(detected, f"MQTT not detected: {error}")
    
    def test_coap_request(self):
        """Test CoAP request detection."""
        # CoAP CON request
        # Version: 01, Type: 00 (CON), Token length: 0
        # Code: 0.01 (GET)
        coap_packet = bytes([
            0x40,  # Version=01, Type=00, TKL=0
            0x01,  # Code: 0.01 (GET)
            0x12, 0x34,  # Message ID
        ])
        
        detected, error = detect_coap(coap_packet)
        self.assertTrue(detected, f"CoAP not detected: {error}")
    
    def test_rtsp_request(self):
        """Test RTSP request detection."""
        rtsp_request = b"OPTIONS rtsp://example.com RTSP/1.0\r\nCSeq: 1\r\n\r\n"
        detected, error = detect_rtsp(rtsp_request)
        self.assertTrue(detected, f"RTSP not detected: {error}")


if __name__ == '__main__':
    unittest.main()

