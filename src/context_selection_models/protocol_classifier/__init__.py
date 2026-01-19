"""
Protocol Classifier for Cleartext Traffic

Deterministic protocol classification for DNS, MQTT, CoAP, and RTSP.
Used in Phase 2 (Context Selection) of the MoE pipeline for non-encrypted traffic.
"""

from .classifier import classify_packet, classify_pcap
from .types import (
    PacketClassification,
    FlowClassification,
    ProtocolLabel,
    EvidenceType,
    PacketMetadata
)

__version__ = "0.1.0"
__all__ = [
    'classify_packet',
    'classify_pcap',
    'PacketClassification',
    'FlowClassification',
    'ProtocolLabel',
    'EvidenceType',
    'PacketMetadata',
]

