"""
Protocol signature detection for deterministic classification.

Implements DPI (Deep Packet Inspection) signatures for:
- DNS (UDP/TCP)
- CoAP v1 (UDP)
- MQTT (TCP)
- RTSP (TCP)
"""

from typing import Tuple, Optional
from .types import ProtocolLabel, EvidenceType


def detect_dns(payload: bytes) -> Tuple[bool, float, EvidenceType, Optional[str]]:
    """
    Detect DNS protocol signature.
    
    Args:
        payload: L4 payload bytes (UDP or TCP)
    
    Returns:
        Tuple of (detected: bool, confidence: float, evidence: EvidenceType, notes: Optional[str])
    """
    if len(payload) < 12:
        return False, 0.0, EvidenceType.INSUFFICIENT, "payload too short for DNS header"
    
    # DNS Header structure (12 bytes):
    # [0-1] Transaction ID (2 bytes)
    # [2-3] Flags (2 bytes)
    # [4-5] QDCOUNT (2 bytes)
    # [6-7] ANCOUNT (2 bytes)
    # [8-9] NSCOUNT (2 bytes)
    # [10-11] ARCOUNT (2 bytes)
    
    flags = (payload[2] << 8) | payload[3]
    qdcount = (payload[4] << 8) | payload[5]
    ancount = (payload[6] << 8) | payload[7]
    nscount = (payload[8] << 8) | payload[9]
    arcount = (payload[10] << 8) | payload[11]
    
    # Validate flags
    qr_bit = (flags >> 15) & 0x01  # Query (0) or Response (1)
    opcode = (flags >> 11) & 0x0F  # Opcode (0-15)
    
    if opcode > 5:
        return False, 0.0, EvidenceType.INSUFFICIENT, f"invalid DNS opcode: {opcode}"
    
    # Validate counts (sanity checks)
    total_count = qdcount + ancount + nscount + arcount
    if total_count > 100:
        return False, 0.0, EvidenceType.INSUFFICIENT, f"DNS counts too large: {total_count}"
    
    # For queries, QDCOUNT should be > 0
    if qr_bit == 0 and qdcount == 0:
        return False, 0.0, EvidenceType.INSUFFICIENT, "DNS query with QDCOUNT=0"
    
    # Try to parse QNAME if this is a query (optional validation)
    if qr_bit == 0 and qdcount > 0 and len(payload) >= 13:
        # QNAME starts at offset 12
        try:
            offset = 12
            label_count = 0
            max_labels = 10  # Reasonable limit
            
            while offset < len(payload) and label_count < max_labels:
                label_len = payload[offset]
                
                if label_len == 0:
                    # End of QNAME
                    break
                elif label_len > 63:
                    # Invalid label length
                    return False, 0.0, EvidenceType.INSUFFICIENT, f"invalid DNS label length: {label_len}"
                
                offset += 1 + label_len
                label_count += 1
            
            # If we got here, QNAME structure looks valid
            return True, 0.95, EvidenceType.DNS_HEADER, None
        except (IndexError, ValueError):
            # QNAME parsing failed, but header structure is valid
            pass
    
    # Header structure is valid
    return True, 0.95, EvidenceType.DNS_HEADER, None


def detect_coap(payload: bytes) -> Tuple[bool, float, EvidenceType, Optional[str]]:
    """
    Detect CoAP v1 protocol signature.
    
    Args:
        payload: UDP payload bytes
    
    Returns:
        Tuple of (detected: bool, confidence: float, evidence: EvidenceType, notes: Optional[str])
    """
    if len(payload) < 4:
        return False, 0.0, EvidenceType.INSUFFICIENT, "payload too short for CoAP header"
    
    # CoAP Header structure (4+ bytes):
    # [0] Version (2 bits) + Type (2 bits) + Token Length (4 bits)
    # [1] Code (8 bits)
    # [2-3] Message ID (16 bits)
    
    first_byte = payload[0]
    version = (first_byte >> 6) & 0x03
    type_bits = (first_byte >> 4) & 0x03
    token_length = first_byte & 0x0F
    
    code = payload[1]
    message_id = (payload[2] << 8) | payload[3]
    
    # Validate version (CoAP v1 = 01 = 1)
    if version != 1:
        return False, 0.0, EvidenceType.INSUFFICIENT, f"invalid CoAP version: {version} (expected 1)"
    
    # Validate token length (0-8 bytes)
    if token_length > 8:
        return False, 0.0, EvidenceType.INSUFFICIENT, f"invalid CoAP token length: {token_length}"
    
    # Validate type (0-3 are valid)
    if type_bits > 3:
        return False, 0.0, EvidenceType.INSUFFICIENT, f"invalid CoAP type: {type_bits}"
    
    # Validate code (0.xx, 2.xx, 4.xx, 5.xx are common)
    code_class = code >> 5
    code_detail = code & 0x1F
    
    if code_class not in [0, 2, 4, 5]:
        # Allow but lower confidence
        confidence = 0.85
    else:
        confidence = 0.95
    
    # Check if we have enough bytes for token + options
    min_length = 4 + token_length
    if len(payload) < min_length:
        # Header structure valid but incomplete
        return True, confidence - 0.05, EvidenceType.COAP_HEADER, "incomplete CoAP packet"
    
    return True, confidence, EvidenceType.COAP_HEADER, None


def parse_mqtt_remaining_length(payload: bytes, offset: int = 1) -> Tuple[Optional[int], int]:
    """
    Parse MQTT remaining length field (variable-length encoding).
    
    Args:
        payload: Payload bytes
        offset: Starting offset (after fixed header byte)
    
    Returns:
        Tuple of (remaining_length: Optional[int], bytes_consumed: int)
        Returns (None, bytes_consumed) if invalid
    """
    if offset >= len(payload):
        return None, 0
    
    multiplier = 1
    value = 0
    bytes_consumed = 0
    
    for i in range(4):  # Max 4 bytes for remaining length
        if offset + i >= len(payload):
            return None, bytes_consumed
        
        byte_val = payload[offset + i]
        value += (byte_val & 0x7F) * multiplier
        bytes_consumed += 1
        
        if (byte_val & 0x80) == 0:
            # Last byte
            break
        
        multiplier *= 128
        
        if multiplier > 128 * 128 * 128:  # Max value check
            return None, bytes_consumed
    
    # Sanity check: remaining length should be reasonable
    if value > 268435455:  # Max MQTT message size
        return None, bytes_consumed
    
    return value, bytes_consumed


def detect_mqtt(payload: bytes, is_stream: bool = False) -> Tuple[bool, float, EvidenceType, Optional[str]]:
    """
    Detect MQTT protocol signature.
    
    Args:
        payload: TCP payload bytes (packet or reassembled stream)
        is_stream: True if this is a reassembled TCP stream, False if single packet
    
    Returns:
        Tuple of (detected: bool, confidence: float, evidence: EvidenceType, notes: Optional[str])
    """
    if len(payload) < 2:
        return False, 0.0, EvidenceType.INSUFFICIENT, "payload too short for MQTT header"
    
    # MQTT Fixed Header:
    # [0] Control Packet Type (4 bits) + Flags (4 bits)
    # [1+] Remaining Length (variable-length, 1-4 bytes)
    
    first_byte = payload[0]
    packet_type = (first_byte >> 4) & 0x0F
    flags = first_byte & 0x0F
    
    # Validate packet type (1-14 are valid, 0 and 15 are reserved)
    if packet_type == 0 or packet_type == 15:
        return False, 0.0, EvidenceType.INSUFFICIENT, f"invalid MQTT packet type: {packet_type}"
    
    if packet_type < 1 or packet_type > 14:
        return False, 0.0, EvidenceType.INSUFFICIENT, f"invalid MQTT packet type: {packet_type}"
    
    # Parse remaining length
    remaining_length, bytes_consumed = parse_mqtt_remaining_length(payload, offset=1)
    
    if remaining_length is None:
        return False, 0.0, EvidenceType.INSUFFICIENT, "invalid MQTT remaining length"
    
    # Check if we have enough bytes
    fixed_header_len = 1 + bytes_consumed
    total_expected = fixed_header_len + remaining_length
    
    if len(payload) < fixed_header_len:
        return False, 0.0, EvidenceType.INSUFFICIENT, "MQTT fixed header incomplete"
    
    # For single packet, if we can't see the full message, return UNKNOWN
    if not is_stream and len(payload) < total_expected:
        return False, 0.0, EvidenceType.NEEDS_TCP_REASSEMBLY, "MQTT message incomplete, needs TCP reassembly"
    
    # Higher confidence for stream-based detection
    confidence = 0.95 if is_stream else 0.75
    
    # Try to validate CONNECT packet for higher confidence
    if packet_type == 1:  # CONNECT
        if len(payload) >= fixed_header_len + 10:  # Minimum CONNECT structure
            # Protocol name starts after fixed header + variable header (10 bytes)
            proto_name_start = fixed_header_len + 10
            if proto_name_start < len(payload):
                # Check for "MQTT" protocol name
                try:
                    proto_name_len = (payload[fixed_header_len + 8] << 8) | payload[fixed_header_len + 9]
                    if proto_name_start + proto_name_len <= len(payload):
                        proto_name = payload[proto_name_start:proto_name_start + proto_name_len]
                        if proto_name == b'MQTT':
                            confidence = 0.95 if is_stream else 0.85
                            return True, confidence, EvidenceType.MQTT_CONNECT_PACKET, None
                except (IndexError, ValueError):
                    pass
    
    # Fixed header is valid
    return True, confidence, EvidenceType.MQTT_FIXED_HEADER, None


def detect_rtsp(payload: bytes, is_stream: bool = False) -> Tuple[bool, float, EvidenceType, Optional[str]]:
    """
    Detect RTSP protocol signature.
    
    Args:
        payload: TCP payload bytes (packet or reassembled stream)
        is_stream: True if this is a reassembled TCP stream, False if single packet
    
    Returns:
        Tuple of (detected: bool, confidence: float, evidence: EvidenceType, notes: Optional[str])
    """
    if len(payload) < 4:
        return False, 0.0, EvidenceType.INSUFFICIENT, "payload too short for RTSP"
    
    # RTSP requests: METHOD SP URI SP RTSP_VERSION CRLF
    # RTSP responses: RTSP_VERSION SP STATUS_CODE SP REASON_PHRASE CRLF
    
    # Try to find request line or response line
    try:
        # Look for RTSP request methods
        rtsp_methods = [
            b'OPTIONS', b'DESCRIBE', b'SETUP', b'PLAY', b'PAUSE',
            b'TEARDOWN', b'ANNOUNCE', b'RECORD', b'GET_PARAMETER', b'SET_PARAMETER'
        ]
        
        # Check if payload starts with a method
        for method in rtsp_methods:
            if payload.startswith(method):
                # Check for space after method
                if len(payload) > len(method) and payload[len(method)] == ord(' '):
                    # Check for "rtsp://" or "*" in URI
                    uri_start = len(method) + 1
                    if uri_start < len(payload):
                        # Look for "rtsp://" or "*" in next 20 bytes
                        uri_section = payload[uri_start:uri_start + 50]
                        if b'rtsp://' in uri_section or payload[uri_start:uri_start + 1] == b'*':
                            confidence = 0.95 if is_stream else 0.85
                            return True, confidence, EvidenceType.RTSP_REQUEST_LINE, None
        
        # Check for RTSP response
        if payload.startswith(b'RTSP/1.0 '):
            confidence = 0.95 if is_stream else 0.85
            return True, confidence, EvidenceType.RTSP_RESPONSE_LINE, None
        
        # Check for RTSP version in first line
        # Look for "RTSP/1.0" or "RTSP/1.1" anywhere in first 100 bytes
        search_section = payload[:min(100, len(payload))]
        if b'RTSP/1.0' in search_section or b'RTSP/1.1' in search_section:
            # Lower confidence for partial match
            confidence = 0.80 if is_stream else 0.70
            return True, confidence, EvidenceType.RTSP_RESPONSE_LINE, "partial RTSP signature"
    
    except (IndexError, ValueError, UnicodeDecodeError):
        pass
    
    # For single packet without clear signature, suggest TCP reassembly
    if not is_stream:
        return False, 0.0, EvidenceType.NEEDS_TCP_REASSEMBLY, "RTSP signature not clear, needs TCP reassembly"
    
    return False, 0.0, EvidenceType.INSUFFICIENT, "no RTSP signature found"


def get_port_hint(port: Optional[int]) -> Tuple[Optional[ProtocolLabel], float]:
    """
    Get protocol hint from port number (low priority, only for hints).
    
    Args:
        port: Port number
    
    Returns:
        Tuple of (protocol_label: Optional[ProtocolLabel], confidence: float)
    """
    if port is None:
        return None, 0.0
    
    port_hints = {
        53: (ProtocolLabel.DNS, 0.3),      # DNS (weak hint)
        5683: (ProtocolLabel.COAP, 0.3),   # CoAP (weak hint)
        5684: (ProtocolLabel.COAP, 0.3),   # CoAP-DTLS (weak hint)
        1883: (ProtocolLabel.MQTT, 0.3),  # MQTT (weak hint)
        8883: (ProtocolLabel.MQTT, 0.3),  # MQTT-TLS (weak hint)
        554: (ProtocolLabel.RTSP, 0.3),    # RTSP (weak hint)
        8554: (ProtocolLabel.RTSP, 0.3),  # RTSP alternate (weak hint)
    }
    
    return port_hints.get(port, (None, 0.0))

