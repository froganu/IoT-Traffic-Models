"""
Utility functions for encryption detection.
"""

import math
from typing import Tuple, Optional
from dataclasses import dataclass


@dataclass
class PayloadStats:
    """Statistics about payload in a flow."""
    total_bytes: int
    packet_count: int
    avg_payload_size: float
    max_payload_size: int
    min_payload_size: int
    payload_sufficient: bool  # True if payloads are large enough for framing detection


def compute_entropy(data: bytes, sample_size: Optional[int] = None) -> float:
    """
    Compute Shannon entropy of byte data.
    
    Args:
        data: Byte data to analyze
        sample_size: Optional limit on bytes to analyze (for performance)
    
    Returns:
        Entropy value (0-8 for bytes)
    """
    if not data or len(data) == 0:
        return 0.0
    
    if sample_size and len(data) > sample_size:
        data = data[:sample_size]
    
    # Count byte frequencies
    byte_counts = {}
    for byte_val in data:
        byte_counts[byte_val] = byte_counts.get(byte_val, 0) + 1
    
    # Compute entropy
    entropy = 0.0
    data_len = len(data)
    
    for count in byte_counts.values():
        probability = count / data_len
        if probability > 0:
            entropy -= probability * math.log2(probability)
    
    return entropy


def compute_printable_ratio(data: bytes, sample_size: Optional[int] = None) -> float:
    """
    Compute ratio of printable ASCII characters.
    
    Args:
        data: Byte data to analyze
        sample_size: Optional limit on bytes to analyze
    
    Returns:
        Ratio of printable characters (0.0-1.0)
    """
    if not data or len(data) == 0:
        return 0.0
    
    if sample_size and len(data) > sample_size:
        data = data[:sample_size]
    
    printable_count = sum(1 for b in data if 32 <= b <= 126 or b in (9, 10, 13))  # Printable + tab, LF, CR
    return printable_count / len(data) if len(data) > 0 else 0.0


def analyze_payload_randomness(payload: bytes, sample_size: int = 1024) -> Tuple[float, float]:
    """
    Analyze payload randomness using entropy and printable ratio.
    
    Args:
        payload: Payload bytes to analyze
        sample_size: Maximum bytes to sample
    
    Returns:
        Tuple of (entropy, printable_ratio)
    """
    if not payload:
        return 0.0, 0.0
    
    sample = payload[:sample_size] if len(payload) > sample_size else payload
    entropy = compute_entropy(sample)
    printable_ratio = compute_printable_ratio(sample)
    
    return entropy, printable_ratio


def is_likely_encrypted_by_entropy(entropy: float, printable_ratio: float) -> bool:
    """
    Determine if payload is likely encrypted based on entropy analysis.
    
    Args:
        entropy: Shannon entropy (0-8)
        printable_ratio: Ratio of printable characters (0-1)
    
    Returns:
        True if likely encrypted
    """
    # High entropy (>7) and low printable ratio (<0.3) suggests encryption
    return entropy > 7.0 and printable_ratio < 0.3


def get_port_heuristic(port: int, protocol: str) -> Tuple[Optional[bool], float]:
    """
    Get encryption heuristic based on port and protocol.
    
    Args:
        port: Port number
        protocol: Protocol string ('tcp' or 'udp')
    
    Returns:
        Tuple of (is_encrypted: Optional[bool], confidence: float)
        None means unknown, confidence is 0.6-0.8 for heuristics
    """
    protocol_lower = protocol.lower()
    
    # High-confidence encrypted ports
    encrypted_ports = {
        (443, 'tcp'): (True, 0.85),   # HTTPS/TLS
        (443, 'udp'): (True, 0.75),   # QUIC (often on 443)
        (853, 'tcp'): (True, 0.90),   # DNS-over-TLS
        (8883, 'tcp'): (True, 0.80),  # MQTT-over-TLS
        (5684, 'udp'): (True, 0.75),  # CoAP-over-DTLS
        (22, 'tcp'): (True, 0.85),    # SSH
        (636, 'tcp'): (True, 0.85),   # LDAPS
        (989, 'tcp'): (True, 0.85),    # FTPS
        (990, 'tcp'): (True, 0.85),   # FTPS
        (992, 'tcp'): (True, 0.85),    # Telnet-over-TLS
        (993, 'tcp'): (True, 0.90),   # IMAPS
        (994, 'tcp'): (True, 0.90),   # IRCS
        (995, 'tcp'): (True, 0.90),   # POP3S
    }
    
    # High-confidence cleartext ports
    cleartext_ports = {
        (80, 'tcp'): (False, 0.90),    # HTTP
        (53, 'udp'): (False, 0.95),    # DNS
        (53, 'tcp'): (False, 0.85),   # DNS-over-TCP
        (1883, 'tcp'): (False, 0.85),  # MQTT
        (5683, 'udp'): (False, 0.85),  # CoAP
        (554, 'tcp'): (False, 0.85),   # RTSP
        (8554, 'tcp'): (False, 0.80),  # RTSP alternate
        (8080, 'tcp'): (False, 0.70),  # HTTP alternate
    }
    
    key = (port, protocol_lower)
    
    if key in encrypted_ports:
        return encrypted_ports[key]
    elif key in cleartext_ports:
        return cleartext_ports[key]
    else:
        return (None, 0.5)  # Unknown port


def create_flow_key(src_ip: str, src_port: int, dst_ip: str, dst_port: int, protocol: str) -> str:
    """
    Create a unique flow key from 5-tuple.
    
    Args:
        src_ip: Source IP
        src_port: Source port
        dst_ip: Destination IP
        dst_port: Destination port
        protocol: Protocol (tcp/udp)
    
    Returns:
        Flow key string
    """
    # Normalize: use smaller port as first for bidirectional flows
    if src_port < dst_port or (src_port == dst_port and src_ip < dst_ip):
        return f"{src_ip}:{src_port}-{dst_ip}:{dst_port}-{protocol}"
    else:
        return f"{dst_ip}:{dst_port}-{src_ip}:{src_port}-{protocol}"

