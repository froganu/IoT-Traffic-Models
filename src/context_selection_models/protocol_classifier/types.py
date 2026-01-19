"""
Type definitions for protocol classifier.
"""

from dataclasses import dataclass
from enum import Enum
from typing import Optional


class ProtocolLabel(Enum):
    """Protocol classification labels."""
    DNS = "DNS"
    MQTT = "MQTT"
    COAP = "COAP"
    RTSP = "RTSP"
    OTHER = "OTHER"
    UNKNOWN = "UNKNOWN"


class EvidenceType(Enum):
    """Types of evidence for protocol classification."""
    DNS_HEADER = "dns_header"
    COAP_HEADER = "coap_header"
    MQTT_FIXED_HEADER = "mqtt_fixed_header"
    MQTT_CONNECT_PACKET = "mqtt_connect_packet"
    RTSP_REQUEST_LINE = "rtsp_request_line"
    RTSP_RESPONSE_LINE = "rtsp_response_line"
    DPI_PARSE = "dpi_parse"
    PORT_HINT = "port_hint"
    INSUFFICIENT = "insufficient"
    NEEDS_TCP_REASSEMBLY = "needs_tcp_reassembly"


@dataclass
class PacketMetadata:
    """Metadata for a single packet."""
    l4_proto: str  # "tcp" or "udp"
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    captured_payload_offset: int = 0  # Offset to L4 payload in packet_bytes


@dataclass
class PacketClassification:
    """Classification result for a single packet."""
    label: ProtocolLabel
    confidence: float  # 0.0-1.0
    evidence: EvidenceType
    notes: Optional[str] = None


@dataclass
class FlowClassification:
    """Classification result for a flow."""
    flow_id: str
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    proto: str  # "tcp" or "udp"
    label: ProtocolLabel
    confidence: float  # 0.0-1.0
    evidence: EvidenceType
    packet_count: int
    first_seen: Optional[float] = None
    last_seen: Optional[float] = None
    bytes_seen_up: int = 0  # Bytes in src->dst direction
    bytes_seen_down: int = 0  # Bytes in dst->src direction
    notes: Optional[str] = None

