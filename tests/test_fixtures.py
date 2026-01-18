"""
Test fixtures and utilities for pipeline testing.

Provides reusable test data and helper functions.
"""

import pandas as pd
import numpy as np
from typing import List, Dict, Any, Optional
import struct


class TestFixtures:
    """Collection of test fixtures for pipeline testing."""
    
    @staticmethod
    def create_tls_packet_bytes(handshake_type: int = 0x01) -> bytes:
        """
        Create synthetic TLS packet bytes.
        
        Args:
            handshake_type: Handshake message type (0x01=ClientHello, 0x02=ServerHello)
        
        Returns:
            Bytes representing TLS packet
        """
        # TLS Handshake record
        return bytes([
            0x16,  # Content Type: Handshake
            0x03, 0x03,  # Version: TLS 1.2
            0x00, 0x05,  # Length
            handshake_type,  # Handshake type
            0x00, 0x00, 0x01, 0x00  # Handshake message
        ])
    
    @staticmethod
    def create_dtls_packet_bytes() -> bytes:
        """Create synthetic DTLS packet bytes."""
        return bytes([
            0x16,  # Content Type: Handshake
            0xFE, 0xFD,  # Version: DTLS 1.2
            0x00, 0x00,  # Epoch
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  # Sequence
            0x00, 0x05  # Length
        ])
    
    @staticmethod
    def create_quic_packet_bytes() -> bytes:
        """Create synthetic QUIC packet bytes."""
        return bytes([
            0xC0,  # Long header + fixed bit
            0x00, 0x00, 0x00, 0x01,  # Version: QUIC v1
            0x08,  # DCID length
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08  # DCID
        ])
    
    @staticmethod
    def create_dns_packet_bytes(domain: str = "example.com") -> bytes:
        """
        Create synthetic DNS packet bytes.
        
        Args:
            domain: Domain name to query
        
        Returns:
            Bytes representing DNS query
        """
        # Simple DNS query
        parts = domain.split('.')
        dns_bytes = bytearray([
            0x12, 0x34,  # Transaction ID
            0x01, 0x00,  # Flags (query)
            0x00, 0x01,  # QDCOUNT = 1
            0x00, 0x00,  # ANCOUNT = 0
            0x00, 0x00,  # NSCOUNT = 0
            0x00, 0x00,  # ARCOUNT = 0
        ])
        
        # Add domain name
        for part in parts:
            dns_bytes.append(len(part))
            dns_bytes.extend(part.encode('ascii'))
        dns_bytes.append(0)  # End of name
        
        # Add QTYPE and QCLASS
        dns_bytes.extend([0x00, 0x01, 0x00, 0x01])  # A record, IN class
        
        return bytes(dns_bytes)
    
    @staticmethod
    def create_http_packet_bytes(method: str = "GET", path: str = "/") -> bytes:
        """
        Create synthetic HTTP packet bytes.
        
        Args:
            method: HTTP method
            path: Request path
        
        Returns:
            Bytes representing HTTP request
        """
        http_request = f"{method} {path} HTTP/1.1\r\nHost: example.com\r\n\r\n"
        return http_request.encode('ascii')
    
    @staticmethod
    def create_mqtt_packet_bytes() -> bytes:
        """Create synthetic MQTT packet bytes."""
        return bytes([
            0x10,  # CONNECT message type
            0x0E,  # Remaining length
            0x00, 0x04,  # Protocol name length
            ord('M'), ord('Q'), ord('T'), ord('T'),  # Protocol name
            0x04,  # Protocol level
            0x02,  # Connect flags
            0x00, 0x3C,  # Keep alive
            0x00, 0x04,  # Client ID length
            ord('t'), ord('e'), ord('s'), ord('t')  # Client ID
        ])
    
    @staticmethod
    def create_coap_packet_bytes() -> bytes:
        """Create synthetic CoAP packet bytes."""
        return bytes([
            0x40,  # Version=01, Type=00, TKL=0
            0x01,  # Code: 0.01 (GET)
            0x12, 0x34,  # Message ID
        ])
    
    @staticmethod
    def create_rtsp_packet_bytes() -> bytes:
        """Create synthetic RTSP packet bytes."""
        return b"OPTIONS rtsp://example.com RTSP/1.0\r\nCSeq: 1\r\n\r\n"
    
    @staticmethod
    def create_packet_dataframe(
        n_packets: int = 5,
        port: int = 443,
        protocol: str = 'tcp',
        include_tls_features: bool = False
    ) -> pd.DataFrame:
        """
        Create a packet DataFrame for testing.
        
        Args:
            n_packets: Number of packets
            port: Destination port
            protocol: Protocol (tcp/udp)
            include_tls_features: Whether to include TLS-specific features
        
        Returns:
            DataFrame with packet features
        """
        np.random.seed(42)  # For reproducibility
        
        data = {
            'packet_size': np.random.randint(100, 1500, n_packets),
            'direction': np.random.randint(0, 2, n_packets),
            'dst_port': [port] * n_packets,
            'src_port': np.random.randint(49152, 65535, n_packets),
            'protocol': [protocol] * n_packets,
            'timestamp': np.arange(n_packets) * 0.1,
        }
        
        # Add TLS features if requested
        if include_tls_features and protocol == 'tcp' and port == 443:
            for i in range(min(10, n_packets)):
                data[f'tls_b_{i}'] = [data['packet_size'][i] if i < n_packets else 0]
                data[f'tls_dir_{i}'] = [data['direction'][i] if i < n_packets else 0]
        
        return pd.DataFrame(data)
    
    @staticmethod
    def create_flow_scenario(
        scenario_type: str,
        n_packets: int = 5
    ) -> Dict[str, Any]:
        """
        Create a complete flow scenario for testing.
        
        Args:
            scenario_type: Type of scenario (tls, dns, http, mqtt, coap, rtsp, unknown)
            n_packets: Number of packets in flow
        
        Returns:
            Dictionary with packet_data, packet_bytes, port, protocol, expected results
        """
        scenarios = {
            'tls': {
                'port': 443,
                'protocol': 'tcp',
                'packet_bytes': TestFixtures.create_tls_packet_bytes(),
                'expected_encrypted': True,
                'expected_protocol': 'tls',
                'expected_model': 'tls_model'
            },
            'dns': {
                'port': 53,
                'protocol': 'udp',
                'packet_bytes': TestFixtures.create_dns_packet_bytes(),
                'expected_encrypted': False,
                'expected_protocol': None,
                'expected_model': 'dns_model'
            },
            'http': {
                'port': 80,
                'protocol': 'tcp',
                'packet_bytes': TestFixtures.create_http_packet_bytes(),
                'expected_encrypted': False,
                'expected_protocol': None,
                'expected_model': 'default_model'  # May need HTTP-specific model
            },
            'mqtt': {
                'port': 1883,
                'protocol': 'tcp',
                'packet_bytes': TestFixtures.create_mqtt_packet_bytes(),
                'expected_encrypted': False,
                'expected_protocol': None,
                'expected_model': 'mqtt_model'
            },
            'coap': {
                'port': 5683,
                'protocol': 'udp',
                'packet_bytes': TestFixtures.create_coap_packet_bytes(),
                'expected_encrypted': False,
                'expected_protocol': None,
                'expected_model': 'mqtt_coap_rtsp_model'  # Or coap_model
            },
            'rtsp': {
                'port': 554,
                'protocol': 'tcp',
                'packet_bytes': TestFixtures.create_rtsp_packet_bytes(),
                'expected_encrypted': False,
                'expected_protocol': None,
                'expected_model': 'mqtt_coap_rtsp_model'  # Or rtsp_model
            },
            'unknown': {
                'port': 12345,
                'protocol': 'tcp',
                'packet_bytes': bytes([0x12, 0x34, 0x56, 0x78]),
                'expected_encrypted': False,
                'expected_protocol': None,
                'expected_model': 'default_model'
            }
        }
        
        if scenario_type not in scenarios:
            raise ValueError(f"Unknown scenario type: {scenario_type}")
        
        scenario = scenarios[scenario_type].copy()
        scenario['packet_data'] = TestFixtures.create_packet_dataframe(
            n_packets=n_packets,
            port=scenario['port'],
            protocol=scenario['protocol'],
            include_tls_features=(scenario_type == 'tls')
        )
        
        return scenario


class TestDataGenerator:
    """Generate test data for different scenarios."""
    
    @staticmethod
    def generate_batch_scenarios(
        scenario_types: List[str],
        n_packets_per_scenario: int = 5
    ) -> List[Dict[str, Any]]:
        """
        Generate batch of test scenarios.
        
        Args:
            scenario_types: List of scenario types
            n_packets_per_scenario: Number of packets per scenario
        
        Returns:
            List of scenario dictionaries
        """
        return [
            TestFixtures.create_flow_scenario(scenario_type, n_packets_per_scenario)
            for scenario_type in scenario_types
        ]

