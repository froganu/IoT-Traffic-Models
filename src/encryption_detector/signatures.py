"""
Protocol signature detection for encryption classification.

Implements deterministic checks for:
- Encrypted protocols: TLS, DTLS, QUIC
- Cleartext protocols: DNS, HTTP, MQTT, CoAP, RTSP
"""

from typing import Optional, Tuple
from enum import Enum


class EvidenceType(Enum):
    """Types of evidence for encryption detection."""
    HANDSHAKE = "handshake"
    RECORD_FRAMING = "record_framing"
    DPI_PROTO = "dpi_proto"
    PORT_HEURISTIC = "port_heuristic"
    ENTROPY = "entropy"
    INSUFFICIENT = "insufficient"


def detect_tls_record(payload: bytes, strict: bool = True) -> Tuple[bool, Optional[str]]:
    """
    Detect TLS record framing in TCP payload.
    
    Args:
        payload: TCP payload bytes
        strict: If True, apply strict validation
    
    Returns:
        Tuple of (detected: bool, error_message: Optional[str])
    """
    if len(payload) < 5:
        return False, "payload too short"
    
    # TLS Record Header structure:
    # [0] Content Type (1 byte)
    # [1-2] Version (2 bytes)
    # [3-4] Length (2 bytes)
    
    content_type = payload[0]
    version_major = payload[1]
    version_minor = payload[2]
    length = (payload[3] << 8) | payload[4]
    
    # Content Type validation
    valid_content_types = {
        0x14: "ChangeCipherSpec",
        0x15: "Alert",
        0x16: "Handshake",
        0x17: "Application",
        0x18: "Heartbeat",
    }
    
    if content_type not in valid_content_types:
        return False, f"invalid content type: 0x{content_type:02x}"
    
    # Version validation (TLS 1.0-1.3)
    if version_major != 0x03:
        return False, f"invalid version major: 0x{version_major:02x}"
    
    if version_minor not in [0x00, 0x01, 0x02, 0x03]:
        return False, f"invalid version minor: 0x{version_minor:02x}"
    
    # Length validation
    if length < 1:
        return False, f"invalid length: {length}"
    
    # TLS record max length is 18432 bytes (2^14 + 2048)
    if length > 18432:
        return False, f"length too large: {length}"
    
    # Sanity check: length should not be absurdly larger than available payload
    # Allow some fragmentation, but be reasonable
    if strict:
        if length > len(payload) - 5 + 1000:  # Allow some fragmentation buffer
            return False, f"length {length} exceeds reasonable payload size {len(payload)}"
    
    return True, None


def detect_tls_handshake(payload: bytes) -> Tuple[bool, Optional[str]]:
    """
    Detect TLS handshake messages (ClientHello/ServerHello).
    
    Args:
        payload: TCP payload bytes
    
    Returns:
        Tuple of (detected: bool, error_message: Optional[str])
    """
    # First check if it's a TLS record
    is_record, error = detect_tls_record(payload)
    if not is_record:
        return False, error
    
    if len(payload) < 6:
        return False, "payload too short for handshake"
    
    # Content type should be 0x16 (Handshake)
    if payload[0] != 0x16:
        return False, "not a handshake record"
    
    # Handshake message type is at offset 5 (after 5-byte record header)
    if len(payload) < 6:
        return False, "payload too short"
    
    handshake_type = payload[5]
    
    # Handshake message types
    valid_handshake_types = {
        0x01: "ClientHello",
        0x02: "ServerHello",
        0x0b: "Certificate",
        0x0c: "ServerKeyExchange",
        0x0d: "CertificateRequest",
        0x0e: "ServerHelloDone",
        0x0f: "CertificateVerify",
        0x10: "ClientKeyExchange",
        0x14: "Finished",
    }
    
    if handshake_type in valid_handshake_types:
        return True, None
    
    return False, f"invalid handshake type: 0x{handshake_type:02x}"


def detect_dtls_record(payload: bytes, strict: bool = True) -> Tuple[bool, Optional[str]]:
    """
    Detect DTLS record framing in UDP payload.
    
    Args:
        payload: UDP payload bytes
        strict: If True, apply strict validation
    
    Returns:
        Tuple of (detected: bool, error_message: Optional[str])
    """
    if len(payload) < 13:  # DTLS record header is 13 bytes
        return False, "payload too short"
    
    # DTLS Record Header structure:
    # [0] Content Type (1 byte)
    # [1-2] Version (2 bytes)
    # [3-4] Epoch (2 bytes)
    # [5-10] Sequence Number (6 bytes)
    # [11-12] Length (2 bytes)
    
    content_type = payload[0]
    version_major = payload[1]
    version_minor = payload[2]
    epoch = (payload[3] << 8) | payload[4]
    length = (payload[11] << 8) | payload[12]
    
    # Content Type validation (same as TLS)
    valid_content_types = {0x14, 0x15, 0x16, 0x17, 0x18}
    if content_type not in valid_content_types:
        return False, f"invalid content type: 0x{content_type:02x}"
    
    # DTLS version validation (typically 0xFE 0xFD for DTLS 1.2)
    # Also accept 0xFE 0xFF for DTLS 1.0
    if version_major != 0xFE:
        return False, f"invalid DTLS version major: 0x{version_major:02x}"
    
    if version_minor not in [0xFD, 0xFF]:
        return False, f"invalid DTLS version minor: 0x{version_minor:02x}"
    
    # Length validation
    if length < 1 or length > 18432:
        return False, f"invalid length: {length}"
    
    if strict and length > len(payload) - 13 + 1000:
        return False, f"length {length} exceeds reasonable payload size {len(payload)}"
    
    return True, None


def detect_quic_header(payload: bytes) -> Tuple[bool, Optional[str]]:
    """
    Detect QUIC long-header in UDP payload.
    
    Args:
        payload: UDP payload bytes
    
    Returns:
        Tuple of (detected: bool, error_message: Optional[str])
    """
    if len(payload) < 5:
        return False, "payload too short"
    
    # QUIC long header format:
    # [0] Header Form (bit 7) + Fixed Bit (bit 6) + Packet Type (bits 0-5)
    # [1-4] Version (4 bytes)
    # Then DCID length, SCID length, etc.
    
    first_byte = payload[0]
    
    # Check if it's a long header (bit 7 = 1)
    is_long_header = (first_byte & 0x80) != 0
    
    if not is_long_header:
        return False, "not a QUIC long header"
    
    # Fixed bit (bit 6) should be 1
    fixed_bit = (first_byte & 0x40) != 0
    if not fixed_bit:
        return False, "fixed bit not set"
    
    # Version field (bytes 1-4) should be non-zero and plausible
    if len(payload) < 5:
        return False, "payload too short for version"
    
    version = int.from_bytes(payload[1:5], byteorder='big')
    
    # QUIC version 1 is 0x00000001, but other versions exist
    # Just check it's non-zero and not obviously wrong
    if version == 0:
        return False, "version is zero"
    
    # Check DCID length (byte 5)
    if len(payload) < 6:
        return False, "payload too short for DCID length"
    
    dcid_length = payload[5]
    if dcid_length > 20:  # Max CID length is 20
        return False, f"DCID length too large: {dcid_length}"
    
    # Basic sanity: DCID + SCID + rest should fit in packet
    if len(payload) < 6 + dcid_length:
        return False, "payload too short for DCID"
    
    return True, None


def detect_dns(payload: bytes) -> Tuple[bool, Optional[str]]:
    """
    Detect DNS protocol in UDP/TCP payload.
    
    Args:
        payload: UDP or TCP payload bytes
    
    Returns:
        Tuple of (detected: bool, error_message: Optional[str])
    """
    if len(payload) < 12:  # DNS header is 12 bytes minimum
        return False, "payload too short"
    
    # DNS Header structure:
    # [0-1] Transaction ID (2 bytes)
    # [2-3] Flags (2 bytes)
    # [4-5] Questions (2 bytes)
    # [6-7] Answer RRs (2 bytes)
    # [8-9] Authority RRs (2 bytes)
    # [10-11] Additional RRs (2 bytes)
    
    # Check QDCOUNT (Questions) - should be reasonable (0-65535, but typically 1-10)
    qdcount = (payload[4] << 8) | payload[5]
    if qdcount > 100:  # Sanity check
        return False, f"QDCOUNT too large: {qdcount}"
    
    # Check flags - bit 0 is QR (0=query, 1=response)
    # Bit 15 is AD (Authentic Data) - can be 0 or 1
    # Other bits have specific meanings but we'll be lenient
    
    # Try to parse first question to validate it's DNS
    if qdcount > 0 and len(payload) > 12:
        # Question starts at offset 12
        # Format: QNAME (variable length, null-terminated) + QTYPE (2 bytes) + QCLASS (2 bytes)
        offset = 12
        qname_valid = False
        
        # Check QNAME (domain name encoding)
        name_len = 0
        while offset < len(payload) and offset < 255:  # Max domain name length
            label_len = payload[offset]
            if label_len == 0:
                qname_valid = True
                offset += 1
                break
            elif 1 <= label_len <= 63:  # Valid label length
                offset += 1 + label_len
                name_len += label_len
            else:
                break
        
        if qname_valid and offset + 4 <= len(payload):
            # Check QTYPE and QCLASS
            qtype = (payload[offset] << 8) | payload[offset + 1]
            qclass = (payload[offset + 2] << 8) | payload[offset + 3]
            
            # QTYPE should be 1-65535, QCLASS typically 1 (IN) or 255 (ANY)
            if 1 <= qtype <= 65535 and (qclass == 1 or qclass == 255):
                return True, None
    
    # If we can't parse question, still accept if header looks reasonable
    # This is a lenient check
    return True, None


def detect_http(payload: bytes) -> Tuple[bool, Optional[str]]:
    """
    Detect HTTP protocol in TCP payload.
    
    Args:
        payload: TCP payload bytes
    
    Returns:
        Tuple of (detected: bool, error_message: Optional[str])
    """
    if len(payload) < 4:
        return False, "payload too short"
    
    # Try to decode as ASCII/UTF-8 for HTTP methods and version strings
    try:
        payload_str = payload[:200].decode('ascii', errors='ignore').upper()
    except:
        return False, "cannot decode as ASCII"
    
    # HTTP request methods
    http_methods = ['GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS', 'PATCH', 'TRACE', 'CONNECT']
    
    # HTTP response
    if payload_str.startswith('HTTP/'):
        # Check for HTTP version
        if 'HTTP/1.0' in payload_str or 'HTTP/1.1' in payload_str or 'HTTP/2' in payload_str:
            return True, None
    
    # HTTP request
    for method in http_methods:
        if payload_str.startswith(method + ' '):
            return True, None
    
    return False, "no HTTP signature found"


def detect_mqtt(payload: bytes) -> Tuple[bool, Optional[str]]:
    """
    Detect MQTT protocol in TCP payload.
    
    Args:
        payload: TCP payload bytes
    
    Returns:
        Tuple of (detected: bool, error_message: Optional[str])
    """
    if len(payload) < 2:
        return False, "payload too short"
    
    # MQTT Fixed Header:
    # [0] Message Type (bits 7-4) + Flags (bits 3-0)
    # [1+] Remaining Length (variable length encoding)
    
    first_byte = payload[0]
    message_type = (first_byte >> 4) & 0x0F
    
    # Valid MQTT message types: 0-15, but 0 and 15 are reserved
    if message_type == 0 or message_type == 15:
        return False, f"invalid message type: {message_type}"
    
    if message_type > 15:
        return False, f"message type out of range: {message_type}"
    
    # Parse remaining length (variable length encoding)
    if len(payload) < 2:
        return False, "payload too short for remaining length"
    
    multiplier = 1
    value = 0
    offset = 1
    
    while offset < len(payload) and offset < 5:  # Max 4 bytes for remaining length
        encoded_byte = payload[offset]
        value += (encoded_byte & 0x7F) * multiplier
        multiplier *= 128
        
        if (encoded_byte & 0x80) == 0:
            break
        offset += 1
    
    # Remaining length should be reasonable
    if value > 268435455:  # Max MQTT remaining length
        return False, f"remaining length too large: {value}"
    
    # Basic sanity: remaining length should roughly match payload size
    if value > len(payload) - offset:
        # Allow some tolerance for fragmentation
        if value > (len(payload) - offset) * 2:
            return False, f"remaining length {value} exceeds payload {len(payload) - offset}"
    
    return True, None


def detect_coap(payload: bytes) -> Tuple[bool, Optional[str]]:
    """
    Detect CoAP protocol in UDP payload.
    
    Args:
        payload: UDP payload bytes
    
    Returns:
        Tuple of (detected: bool, error_message: Optional[str])
    """
    if len(payload) < 4:
        return False, "payload too short"
    
    # CoAP Header structure:
    # [0] Version (bits 7-6) + Type (bits 5-4) + Token Length (bits 3-0)
    # [1] Code (1 byte)
    # [2-3] Message ID (2 bytes)
    
    first_byte = payload[0]
    version = (first_byte >> 6) & 0x03
    type_bits = (first_byte >> 4) & 0x03
    token_length = first_byte & 0x0F
    
    # Version should be 01 (CoAP version 1)
    if version != 0x01:
        return False, f"invalid CoAP version: {version}"
    
    # Type should be 0-3 (CON, NON, ACK, RST)
    if type_bits > 3:
        return False, f"invalid CoAP type: {type_bits}"
    
    # Token length should be 0-8
    if token_length > 8:
        return False, f"token length too large: {token_length}"
    
    # Code should be valid (0.00-5.05 for requests, 2.00-5.05 for responses)
    code = payload[1]
    code_class = (code >> 5) & 0x07
    code_detail = code & 0x1F
    
    if code_class > 5:
        return False, f"invalid code class: {code_class}"
    
    if code_detail > 31:
        return False, f"invalid code detail: {code_detail}"
    
    # Basic sanity: header + token + options/payload should fit
    header_len = 4 + token_length
    if len(payload) < header_len:
        return False, "payload too short for header + token"
    
    return True, None


def detect_rtsp(payload: bytes) -> Tuple[bool, Optional[str]]:
    """
    Detect RTSP protocol in TCP payload.
    
    Args:
        payload: TCP payload bytes
    
    Returns:
        Tuple of (detected: bool, error_message: Optional[str])
    """
    if len(payload) < 4:
        return False, "payload too short"
    
    # Try to decode as ASCII for RTSP methods
    try:
        payload_str = payload[:200].decode('ascii', errors='ignore').upper()
    except:
        return False, "cannot decode as ASCII"
    
    # RTSP request methods
    rtsp_methods = [
        'OPTIONS', 'DESCRIBE', 'ANNOUNCE', 'SETUP', 'PLAY', 'PAUSE',
        'TEARDOWN', 'GET_PARAMETER', 'SET_PARAMETER', 'REDIRECT', 'RECORD'
    ]
    
    # RTSP response
    if payload_str.startswith('RTSP/'):
        # Check for RTSP version
        if 'RTSP/1.0' in payload_str:
            return True, None
    
    # RTSP request
    for method in rtsp_methods:
        if payload_str.startswith(method + ' '):
            # Check for RTSP URL or RTSP/1.0
            if 'RTSP/' in payload_str or 'rtsp://' in payload_str.lower():
                return True, None
    
    return False, "no RTSP signature found"

