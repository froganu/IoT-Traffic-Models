"""
Main encryption detection logic.

Implements deterministic encryption classification with evidence and confidence.
"""

from typing import List, Optional, Tuple
from dataclasses import dataclass
from enum import Enum
from datetime import datetime

from .pcap_reader import Flow, Packet, read_pcap_simple
from .signatures import (
    detect_tls_record,
    detect_tls_handshake,
    detect_dtls_record,
    detect_quic_header,
    detect_dns,
    detect_http,
    detect_mqtt,
    detect_coap,
    detect_rtsp,
    EvidenceType
)
from .utils import (
    get_port_heuristic,
    analyze_payload_randomness,
    is_likely_encrypted_by_entropy,
    create_flow_key
)


class EncryptionState(Enum):
    """Encryption state classification."""
    ENCRYPTED = "encrypted"
    CLEARTEXT = "cleartext"
    UNKNOWN = "unknown"


class EncryptedFamily(Enum):
    """Type of encrypted protocol."""
    TLS = "tls"
    QUIC = "quic"
    DTLS = "dtls"
    UNKNOWN = "unknown"


@dataclass
class FlowResult:
    """Result of encryption detection for a flow."""
    # Binary decision for API
    encrypted: bool  # True=encrypted, False=not_encrypted
    
    # Internal fields for rigor
    state: EncryptionState
    encrypted_family: EncryptedFamily
    evidence: EvidenceType
    confidence: float  # 0.0-1.0
    
    # Flow identification
    flow_id: str
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    protocol: str
    
    # Statistics
    payload_bytes_captured: int
    packet_count: int
    first_seen: Optional[float]
    last_seen: Optional[float]
    payload_sufficient: bool


@dataclass
class PacketResult:
    """Result of encryption detection for a single packet."""
    encrypted: bool
    state: EncryptionState
    encrypted_family: EncryptedFamily
    evidence: EvidenceType
    confidence: float
    protocol: Optional[str] = None
    port: Optional[int] = None


class EncryptionDetector:
    """
    Deterministic encryption detector.
    
    Applies detection rules in priority order:
    1. Protocol framing (TLS/DTLS/QUIC) - highest confidence
    2. Cleartext protocol signatures (DNS/HTTP/MQTT/CoAP/RTSP)
    3. Port heuristics
    4. Entropy analysis
    5. Unknown/insufficient
    """
    
    def __init__(self):
        """Initialize detector."""
        pass
    
    def detect_flow(self, flow: Flow) -> FlowResult:
        """
        Detect encryption status for a flow.
        
        Args:
            flow: Flow object with packets
        
        Returns:
            FlowResult with detection results
        """
        if len(flow.packets) == 0:
            return self._create_unknown_result(flow, EvidenceType.INSUFFICIENT, 0.5)
        
        # Check payload sufficiency
        payload_sufficient = flow.is_payload_sufficient(min_payload_size=5)
        
        # Collect all payloads for analysis
        all_payloads = b''.join(p.payload for p in flow.packets)
        
        # Rule 1: High-confidence encrypted via protocol framing
        result = self._check_encrypted_framing(flow, payload_sufficient)
        if result:
            return result
        
        # Rule 2: High-confidence cleartext via protocol signatures
        result = self._check_cleartext_protocols(flow, payload_sufficient)
        if result:
            return result
        
        # Rule 3: Medium-confidence port heuristics
        result = self._check_port_heuristics(flow)
        if result:
            return result
        
        # Rule 4: Optional entropy analysis
        if payload_sufficient and len(all_payloads) > 0:
            result = self._check_entropy(all_payloads)
            if result:
                return result
        
        # Rule 5: Unknown/insufficient
        return self._create_unknown_result(flow, EvidenceType.INSUFFICIENT, 0.5)
    
    def _check_encrypted_framing(self, flow: Flow, payload_sufficient: bool) -> Optional[FlowResult]:
        """Check for encrypted protocol framing (TLS/DTLS/QUIC)."""
        if not payload_sufficient:
            return None
        
        # Check each packet for framing signatures
        for packet in flow.packets:
            if len(packet.payload) < 5:
                continue
            
            # Check TLS (TCP)
            if packet.protocol == 'tcp':
                # Try TLS record framing
                is_tls, error = detect_tls_record(packet.payload, strict=True)
                if is_tls:
                    # Try to detect handshake
                    is_handshake, _ = detect_tls_handshake(packet.payload)
                    evidence = EvidenceType.HANDSHAKE if is_handshake else EvidenceType.RECORD_FRAMING
                    confidence = 0.98 if is_handshake else 0.95
                    
                    return FlowResult(
                        encrypted=True,
                        state=EncryptionState.ENCRYPTED,
                        encrypted_family=EncryptedFamily.TLS,
                        evidence=evidence,
                        confidence=confidence,
                        flow_id=flow.flow_id,
                        src_ip=flow.src_ip,
                        src_port=flow.src_port,
                        dst_ip=flow.dst_ip,
                        dst_port=flow.dst_port,
                        protocol=flow.protocol,
                        payload_bytes_captured=flow.payload_bytes_captured,
                        packet_count=len(flow.packets),
                        first_seen=flow.first_seen,
                        last_seen=flow.last_seen,
                        payload_sufficient=payload_sufficient
                    )
            
            # Check DTLS (UDP)
            elif packet.protocol == 'udp':
                is_dtls, error = detect_dtls_record(packet.payload, strict=True)
                if is_dtls:
                    return FlowResult(
                        encrypted=True,
                        state=EncryptionState.ENCRYPTED,
                        encrypted_family=EncryptedFamily.DTLS,
                        evidence=EvidenceType.RECORD_FRAMING,
                        confidence=0.95,
                        flow_id=flow.flow_id,
                        src_ip=flow.src_ip,
                        src_port=flow.src_port,
                        dst_ip=flow.dst_ip,
                        dst_port=flow.dst_port,
                        protocol=flow.protocol,
                        payload_bytes_captured=flow.payload_bytes_captured,
                        packet_count=len(flow.packets),
                        first_seen=flow.first_seen,
                        last_seen=flow.last_seen,
                        payload_sufficient=payload_sufficient
                    )
                
                # Check QUIC (UDP)
                is_quic, error = detect_quic_header(packet.payload)
                if is_quic:
                    return FlowResult(
                        encrypted=True,
                        state=EncryptionState.ENCRYPTED,
                        encrypted_family=EncryptedFamily.QUIC,
                        evidence=EvidenceType.RECORD_FRAMING,
                        confidence=0.90,
                        flow_id=flow.flow_id,
                        src_ip=flow.src_ip,
                        src_port=flow.src_port,
                        dst_ip=flow.dst_ip,
                        dst_port=flow.dst_port,
                        protocol=flow.protocol,
                        payload_bytes_captured=flow.payload_bytes_captured,
                        packet_count=len(flow.packets),
                        first_seen=flow.first_seen,
                        last_seen=flow.last_seen,
                        payload_sufficient=payload_sufficient
                    )
        
        return None
    
    def _check_cleartext_protocols(self, flow: Flow, payload_sufficient: bool) -> Optional[FlowResult]:
        """Check for cleartext protocol signatures."""
        if not payload_sufficient:
            return None
        
        # Check each packet for cleartext signatures
        for packet in flow.packets:
            if len(packet.payload) == 0:
                continue
            
            # DNS (UDP or TCP)
            if packet.protocol in ['udp', 'tcp']:
                is_dns, _ = detect_dns(packet.payload)
                if is_dns:
                    return self._create_cleartext_result(flow, EvidenceType.DPI_PROTO, 0.95, payload_sufficient)
            
            # HTTP (TCP)
            if packet.protocol == 'tcp':
                is_http, _ = detect_http(packet.payload)
                if is_http:
                    return self._create_cleartext_result(flow, EvidenceType.DPI_PROTO, 0.95, payload_sufficient)
                
                is_mqtt, _ = detect_mqtt(packet.payload)
                if is_mqtt:
                    return self._create_cleartext_result(flow, EvidenceType.DPI_PROTO, 0.90, payload_sufficient)
                
                is_rtsp, _ = detect_rtsp(packet.payload)
                if is_rtsp:
                    return self._create_cleartext_result(flow, EvidenceType.DPI_PROTO, 0.90, payload_sufficient)
            
            # CoAP (UDP)
            if packet.protocol == 'udp':
                is_coap, _ = detect_coap(packet.payload)
                if is_coap:
                    return self._create_cleartext_result(flow, EvidenceType.DPI_PROTO, 0.90, payload_sufficient)
        
        return None
    
    def _check_port_heuristics(self, flow: Flow) -> Optional[FlowResult]:
        """Check port-based heuristics."""
        # Use destination port (or source port if dst is ephemeral)
        port = flow.dst_port
        if port >= 49152:  # Ephemeral port range, try source
            port = flow.src_port
        
        is_encrypted, confidence = get_port_heuristic(port, flow.protocol)
        
        if is_encrypted is not None:
            # Map to result
            if is_encrypted:
                # For UDP/443, might be QUIC
                encrypted_family = EncryptedFamily.QUIC if (port == 443 and flow.protocol == 'udp') else EncryptedFamily.UNKNOWN
                
                return FlowResult(
                    encrypted=True,
                    state=EncryptionState.ENCRYPTED,
                    encrypted_family=encrypted_family,
                    evidence=EvidenceType.PORT_HEURISTIC,
                    confidence=confidence,
                    flow_id=flow.flow_id,
                    src_ip=flow.src_ip,
                    src_port=flow.src_port,
                    dst_ip=flow.dst_ip,
                    dst_port=flow.dst_port,
                    protocol=flow.protocol,
                    payload_bytes_captured=flow.payload_bytes_captured,
                    packet_count=len(flow.packets),
                    first_seen=flow.first_seen,
                    last_seen=flow.last_seen,
                    payload_sufficient=flow.is_payload_sufficient()
                )
            else:
                return self._create_cleartext_result(flow, EvidenceType.PORT_HEURISTIC, confidence, flow.is_payload_sufficient())
        
        return None
    
    def _check_entropy(self, payload: bytes) -> Optional[FlowResult]:
        """Check payload entropy for encryption indicators."""
        entropy, printable_ratio = analyze_payload_randomness(payload, sample_size=1024)
        
        if is_likely_encrypted_by_entropy(entropy, printable_ratio):
            # Create a minimal flow result for entropy-based detection
            # Note: This is a simplified case; in practice, you'd need flow context
            return None  # Entropy alone is weak evidence, skip for now
        
        return None
    
    def _create_cleartext_result(self, flow: Flow, evidence: EvidenceType, confidence: float, payload_sufficient: bool) -> FlowResult:
        """Create a cleartext result."""
        return FlowResult(
            encrypted=False,
            state=EncryptionState.CLEARTEXT,
            encrypted_family=EncryptedFamily.UNKNOWN,
            evidence=evidence,
            confidence=confidence,
            flow_id=flow.flow_id,
            src_ip=flow.src_ip,
            src_port=flow.src_port,
            dst_ip=flow.dst_ip,
            dst_port=flow.dst_port,
            protocol=flow.protocol,
            payload_bytes_captured=flow.payload_bytes_captured,
            packet_count=len(flow.packets),
            first_seen=flow.first_seen,
            last_seen=flow.last_seen,
            payload_sufficient=payload_sufficient
        )
    
    def _create_unknown_result(self, flow: Flow, evidence: EvidenceType, confidence: float) -> FlowResult:
        """Create an unknown result."""
        # Map unknown to not_encrypted for public API, but keep evidence=insufficient
        return FlowResult(
            encrypted=False,  # Public API: unknown -> not_encrypted
            state=EncryptionState.UNKNOWN,
            encrypted_family=EncryptedFamily.UNKNOWN,
            evidence=evidence,
            confidence=confidence,
            flow_id=flow.flow_id,
            src_ip=flow.src_ip,
            src_port=flow.src_port,
            dst_ip=flow.dst_ip,
            dst_port=flow.dst_port,
            protocol=flow.protocol,
            payload_bytes_captured=flow.payload_bytes_captured,
            packet_count=len(flow.packets),
            first_seen=flow.first_seen,
            last_seen=flow.last_seen,
            payload_sufficient=flow.is_payload_sufficient()
        )
    
    def detect_packet(self, packet_bytes: bytes, port: Optional[int] = None, protocol: Optional[str] = None) -> PacketResult:
        """
        Detect encryption for a single packet.
        
        Args:
            packet_bytes: Raw packet payload bytes
            port: Optional port number
            protocol: Optional protocol ('tcp' or 'udp')
        
        Returns:
            PacketResult
        """
        if len(packet_bytes) < 5:
            return PacketResult(
                encrypted=False,
                state=EncryptionState.UNKNOWN,
                encrypted_family=EncryptedFamily.UNKNOWN,
                evidence=EvidenceType.INSUFFICIENT,
                confidence=0.5,
                port=port,
                protocol=protocol
            )
        
        # Check TLS/DTLS/QUIC framing
        if protocol == 'tcp':
            is_tls, _ = detect_tls_record(packet_bytes, strict=False)
            if is_tls:
                return PacketResult(
                    encrypted=True,
                    state=EncryptionState.ENCRYPTED,
                    encrypted_family=EncryptedFamily.TLS,
                    evidence=EvidenceType.RECORD_FRAMING,
                    confidence=0.95,
                    port=port,
                    protocol=protocol
                )
        elif protocol == 'udp':
            is_dtls, _ = detect_dtls_record(packet_bytes, strict=False)
            if is_dtls:
                return PacketResult(
                    encrypted=True,
                    state=EncryptionState.ENCRYPTED,
                    encrypted_family=EncryptedFamily.DTLS,
                    evidence=EvidenceType.RECORD_FRAMING,
                    confidence=0.95,
                    port=port,
                    protocol=protocol
                )
            
            is_quic, _ = detect_quic_header(packet_bytes)
            if is_quic:
                return PacketResult(
                    encrypted=True,
                    state=EncryptionState.ENCRYPTED,
                    encrypted_family=EncryptedFamily.QUIC,
                    evidence=EvidenceType.RECORD_FRAMING,
                    confidence=0.90,
                    port=port,
                    protocol=protocol
                )
        
        # Check cleartext protocols
        if protocol in ['tcp', 'udp']:
            is_dns, _ = detect_dns(packet_bytes)
            if is_dns:
                return PacketResult(
                    encrypted=False,
                    state=EncryptionState.CLEARTEXT,
                    encrypted_family=EncryptedFamily.UNKNOWN,
                    evidence=EvidenceType.DPI_PROTO,
                    confidence=0.95,
                    port=port,
                    protocol=protocol
                )
        
        if protocol == 'tcp':
            is_http, _ = detect_http(packet_bytes)
            if is_http:
                return PacketResult(
                    encrypted=False,
                    state=EncryptionState.CLEARTEXT,
                    encrypted_family=EncryptedFamily.UNKNOWN,
                    evidence=EvidenceType.DPI_PROTO,
                    confidence=0.95,
                    port=port,
                    protocol=protocol
                )
        
        # Port heuristic
        if port:
            is_encrypted, confidence = get_port_heuristic(port, protocol or 'tcp')
            if is_encrypted is not None:
                return PacketResult(
                    encrypted=is_encrypted,
                    state=EncryptionState.ENCRYPTED if is_encrypted else EncryptionState.CLEARTEXT,
                    encrypted_family=EncryptedFamily.QUIC if (port == 443 and protocol == 'udp') else EncryptedFamily.UNKNOWN,
                    evidence=EvidenceType.PORT_HEURISTIC,
                    confidence=confidence,
                    port=port,
                    protocol=protocol
                )
        
        # Unknown
        return PacketResult(
            encrypted=False,
            state=EncryptionState.UNKNOWN,
            encrypted_family=EncryptedFamily.UNKNOWN,
            evidence=EvidenceType.INSUFFICIENT,
            confidence=0.5,
            port=port,
            protocol=protocol
        )


# Convenience functions
def analyze_pcap(pcap_path: str, max_packets: Optional[int] = None) -> List[FlowResult]:
    """
    Analyze PCAP file and return encryption detection results.
    
    Args:
        pcap_path: Path to PCAP file
        max_packets: Optional limit on packets to process
    
    Returns:
        List of FlowResult objects
    """
    flows = read_pcap_simple(pcap_path, max_packets=max_packets)
    detector = EncryptionDetector()
    results = [detector.detect_flow(flow) for flow in flows]
    return results


def analyze_packet(packet_bytes: bytes, port: Optional[int] = None, protocol: Optional[str] = None) -> PacketResult:
    """
    Analyze a single packet and return encryption detection result.
    
    Args:
        packet_bytes: Raw packet payload bytes
        port: Optional port number
        protocol: Optional protocol ('tcp' or 'udp')
    
    Returns:
        PacketResult object
    """
    detector = EncryptionDetector()
    return detector.detect_packet(packet_bytes, port=port, protocol=protocol)

