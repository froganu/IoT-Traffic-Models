"""
Encryption Detector Module for MoE IoT C2 Detection

Deterministic packet-level encryption classifier that outputs per-flow encryption
labels with evidence and confidence. Works with full-payload and truncated PCAPs.
"""

from .detector import analyze_pcap, analyze_packet, FlowResult, PacketResult
from .pcap_reader import PCAPReader, Flow
from .signatures import (
    detect_tls_record,
    detect_dtls_record,
    detect_quic_header,
    detect_dns,
    detect_http,
    detect_mqtt,
    detect_coap,
    detect_rtsp
)

__version__ = "0.1.0"
__all__ = [
    'analyze_pcap',
    'analyze_packet',
    'FlowResult',
    'PacketResult',
    'PCAPReader',
    'Flow',
    'detect_tls_record',
    'detect_dtls_record',
    'detect_quic_header',
    'detect_dns',
    'detect_http',
    'detect_mqtt',
    'detect_coap',
    'detect_rtsp',
]
