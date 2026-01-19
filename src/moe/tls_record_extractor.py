"""
TLS Record Extractor for MoE System

Extracts TLS features from packets by:
1. Grouping packets into flows
2. Reassembling TCP streams
3. Parsing TLS records
4. Extracting features from TLS records

Based on Joy extraction method: features come from TLS records (application layer),
not packets directly.
"""

import logging
import numpy as np
from typing import List, Dict, Tuple, Optional
from collections import defaultdict
import pandas as pd

logger = logging.getLogger(__name__)

# Try to import TLS parsing libraries
try:
    import scapy.all as scapy
    from scapy.layers.tls import TLS, TLSClientHello, TLSServerHello, TLSApplicationData
    HAS_SCAPY = True
except ImportError:
    HAS_SCAPY = False
    logger.warning("scapy not available. TLS record extraction will be limited.")

try:
    import pyshark
    HAS_PYSHARK = True
except ImportError:
    HAS_PYSHARK = False
    logger.warning("pyshark not available. TLS record extraction will be limited.")


class TLSRecord:
    """Represents a TLS record."""
    def __init__(self, size: int, direction: int, record_type: Optional[str] = None):
        """
        Args:
            size: TLS record size in bytes
            direction: 0 = client→server, 1 = server→client
            record_type: Optional TLS record type (handshake, application_data, etc.)
        """
        self.size = size
        self.direction = direction
        self.record_type = record_type


def _create_flow_key(packet: pd.DataFrame) -> Optional[Tuple]:
    """
    Create a flow key (5-tuple) from a packet DataFrame.
    
    Args:
        packet: DataFrame with packet information
    
    Returns:
        Flow key tuple: (src_ip, dst_ip, src_port, dst_port, protocol)
        or None if insufficient information
    """
    # Try to extract 5-tuple
    src_ip = None
    dst_ip = None
    src_port = None
    dst_port = None
    protocol = 'tcp'  # Default
    
    # Extract IP addresses
    if 'src_ip' in packet.columns:
        src_ip = packet['src_ip'].iloc[0] if len(packet) > 0 else None
    elif 'ip.src' in packet.columns:
        src_ip = packet['ip.src'].iloc[0] if len(packet) > 0 else None
    
    if 'dst_ip' in packet.columns:
        dst_ip = packet['dst_ip'].iloc[0] if len(packet) > 0 else None
    elif 'ip.dst' in packet.columns:
        dst_ip = packet['ip.dst'].iloc[0] if len(packet) > 0 else None
    
    # Extract ports
    if 'src_port' in packet.columns:
        src_port = packet['src_port'].iloc[0] if len(packet) > 0 else None
    elif 'tcp.srcport' in packet.columns:
        src_port = packet['tcp.srcport'].iloc[0] if len(packet) > 0 else None
    
    if 'dst_port' in packet.columns:
        dst_port = packet['dst_port'].iloc[0] if len(packet) > 0 else None
    elif 'tcp.dstport' in packet.columns:
        dst_port = packet['tcp.dstport'].iloc[0] if len(packet) > 0 else None
    
    # Extract protocol
    if 'protocol' in packet.columns:
        proto_str = packet['protocol'].iloc[0] if len(packet) > 0 else None
        if proto_str:
            protocol = str(proto_str).lower()
    
    # Check if we have enough information
    if src_ip and dst_ip and src_port and dst_port:
        # Create bidirectional flow key (smaller IP first for consistency)
        if src_ip < dst_ip or (src_ip == dst_ip and src_port < dst_port):
            return (src_ip, dst_ip, src_port, dst_port, protocol)
        else:
            return (dst_ip, src_ip, dst_port, src_port, protocol)
    
    return None


def _group_packets_into_flows(packet_sequence: List[pd.DataFrame]) -> Dict[Tuple, List[pd.DataFrame]]:
    """
    Group packets into flows based on 5-tuple.
    
    Args:
        packet_sequence: List of packet DataFrames
    
    Returns:
        Dictionary mapping flow_key -> list of packets in that flow
    """
    flows = defaultdict(list)
    
    for packet in packet_sequence:
        flow_key = _create_flow_key(packet)
        if flow_key:
            flows[flow_key].append(packet)
        else:
            logger.debug("Could not create flow key for packet, skipping")
    
    return dict(flows)


def _extract_tcp_payload_from_packet_bytes(packet_bytes: bytes) -> bytes:
    """
    Extract TCP payload from raw packet bytes.
    
    Assumes Ethernet/IP/TCP structure. Parses headers to find TCP payload.
    
    Args:
        packet_bytes: Raw packet bytes (Ethernet frame)
    
    Returns:
        TCP payload bytes (empty if extraction fails)
    """
    if len(packet_bytes) < 14:  # Minimum Ethernet header
        return b''
    
    # Skip Ethernet header (14 bytes)
    ip_data = packet_bytes[14:]
    
    if len(ip_data) < 20:  # Minimum IP header
        return b''
    
    # Parse IP header
    ip_version = (ip_data[0] >> 4) & 0x0F
    if ip_version != 4:  # Only support IPv4
        return b''
    
    ip_header_len = (ip_data[0] & 0x0F) * 4
    protocol = ip_data[9]
    
    if protocol != 6:  # Not TCP
        return b''
    
    # Get TCP header
    tcp_data = ip_data[ip_header_len:]
    if len(tcp_data) < 20:  # Minimum TCP header
        return b''
    
    # Parse TCP header length
    tcp_header_len = ((tcp_data[12] >> 4) & 0x0F) * 4
    
    # Extract TCP payload
    if len(tcp_data) > tcp_header_len:
        return tcp_data[tcp_header_len:]
    
    return b''


def _reassemble_tcp_stream(packets: List[pd.DataFrame]) -> Tuple[Optional[bytes], Optional[bytes]]:
    """
    Reassemble TCP stream from packets.
    
    Args:
        packets: List of packet DataFrames from a flow
    
    Returns:
        Tuple of (client_to_server_bytes, server_to_client_bytes)
    """
    client_to_server = bytearray()
    server_to_client = bytearray()
    
    # Sort packets by timestamp if available
    sorted_packets = sorted(
        packets,
        key=lambda p: p.get('timestamp', [0])[0] if 'timestamp' in p.columns and len(p) > 0 else 0
    )
    
    for packet_df in sorted_packets:
        # Determine direction
        direction = 0  # Default: client→server
        if 'direction' in packet_df.columns and len(packet_df) > 0:
            direction = int(packet_df['direction'].iloc[0])
        else:
            # Infer from ports
            dst_port = None
            if 'dst_port' in packet_df.columns:
                dst_port = packet_df['dst_port'].iloc[0]
            elif 'tcp.dstport' in packet_df.columns:
                dst_port = packet_df['tcp.dstport'].iloc[0]
            
            if dst_port and dst_port == 443:
                direction = 0  # Client→server
            elif dst_port and dst_port != 443:
                # Check if src_port is 443
                src_port = None
                if 'src_port' in packet_df.columns:
                    src_port = packet_df['src_port'].iloc[0]
                elif 'tcp.srcport' in packet_df.columns:
                    src_port = packet_df['tcp.srcport'].iloc[0]
                
                if src_port and src_port == 443:
                    direction = 1  # Server→client
        
        # Extract TCP payload
        payload = b''
        if 'packet_bytes' in packet_df.columns and len(packet_df) > 0:
            packet_bytes = packet_df['packet_bytes'].iloc[0]
            if isinstance(packet_bytes, bytes) and len(packet_bytes) > 0:
                payload = _extract_tcp_payload_from_packet_bytes(packet_bytes)
        
        # Also try to get payload from DataFrame columns if available
        if not payload and 'tcp_payload' in packet_df.columns and len(packet_df) > 0:
            payload_data = packet_df['tcp_payload'].iloc[0]
            if isinstance(payload_data, bytes):
                payload = payload_data
        elif not payload and 'payload' in packet_df.columns and len(packet_df) > 0:
            payload_data = packet_df['payload'].iloc[0]
            if isinstance(payload_data, bytes):
                payload = payload_data
        
        # Add to appropriate buffer
        if direction == 0:
            client_to_server.extend(payload)
        else:
            server_to_client.extend(payload)
    
    return bytes(client_to_server), bytes(server_to_client)


def _parse_tls_records_from_bytes(data: bytes, direction: int) -> List[TLSRecord]:
    """
    Parse TLS records from reassembled TCP stream bytes.
    
    Uses the same validation logic as encryption_detector for consistency.
    
    TLS Record Format:
    - Content Type (1 byte): 0x14=ChangeCipherSpec, 0x15=Alert, 0x16=Handshake, 0x17=ApplicationData
    - Version (2 bytes): 0x0301=TLS 1.0, 0x0303=TLS 1.2, 0x0304=TLS 1.3
    - Length (2 bytes): Record length (excluding header)
    
    Args:
        data: Reassembled TCP stream bytes
        direction: 0 = client→server, 1 = server→client
    
    Returns:
        List of TLSRecord objects
    """
    # Import TLS detection logic from encryption_detector
    try:
        from src.encryption_detector.signatures import detect_tls_record
    except ImportError:
        # Fallback to local implementation
        detect_tls_record = None
    
    records = []
    offset = 0
    
    while offset < len(data):
        # Need at least 5 bytes for TLS record header
        if offset + 5 > len(data):
            break
        
        # Get remaining data from this offset
        remaining_data = data[offset:]
        
        # Use encryption_detector's validation if available
        if detect_tls_record:
            is_tls, error = detect_tls_record(remaining_data, strict=False)
            if not is_tls:
                # Not a TLS record, try next byte
                offset += 1
                continue
        
        # Parse TLS record header
        content_type = data[offset]
        version_major = data[offset + 1]
        version_minor = data[offset + 2]
        record_length = (data[offset + 3] << 8) | data[offset + 4]
        
        # Validate TLS record (same validation as encryption_detector)
        # Content type should be valid TLS content type
        valid_content_types = {0x14, 0x15, 0x16, 0x17, 0x18}
        if content_type not in valid_content_types:
            # Not a TLS record, skip
            offset += 1
            continue
        
        # Version should be TLS (0x03xx)
        if version_major != 0x03:
            # Not TLS, skip
            offset += 1
            continue
        
        # Validate record length (TLS max is 18432 bytes)
        if record_length < 1 or record_length > 18432:
            # Invalid length, skip
            offset += 1
            continue
        
        # Check if we have the full record (allow some fragmentation)
        if offset + 5 + record_length > len(data):
            # Incomplete record, stop parsing
            break
        
        # Create TLS record
        # Note: record_length is the payload size (excluding 5-byte header)
        # Joy's 'b' field is the record payload size, not including header
        record = TLSRecord(
            size=record_length,  # Record payload size (excluding 5-byte header)
            direction=direction,
            record_type=_get_tls_content_type_name(content_type)
        )
        records.append(record)
        
        # Move to next record
        offset += 5 + record_length
    
    return records


def _get_tls_content_type_name(content_type: int) -> str:
    """Get TLS content type name."""
    types = {
        0x14: 'change_cipher_spec',
        0x15: 'alert',
        0x16: 'handshake',
        0x17: 'application_data',
    }
    return types.get(content_type, 'unknown')


def _extract_tls_records_from_packets_scapy(packets: List[pd.DataFrame]) -> List[TLSRecord]:
    """
    Extract TLS records from packets using scapy (if available) or manual parsing.
    
    Args:
        packets: List of packet DataFrames from a flow
    
    Returns:
        List of TLSRecord objects
    """
    tls_records = []
    
    try:
        # Step 1: Reassemble TCP stream
        client_to_server, server_to_client = _reassemble_tcp_stream(packets)
        
        # Step 2: Parse TLS records from both directions
        if client_to_server:
            records_c2s = _parse_tls_records_from_bytes(client_to_server, direction=0)
            tls_records.extend(records_c2s)
        
        if server_to_client:
            records_s2c = _parse_tls_records_from_bytes(server_to_client, direction=1)
            tls_records.extend(records_s2c)
        
        # Step 3: Sort records by order of appearance (simplified - use direction and count)
        # In practice, you'd want to interleave based on timestamps
        # For now, we'll take client→server first, then server→client
        sorted_records = []
        c2s_records = [r for r in tls_records if r.direction == 0]
        s2c_records = [r for r in tls_records if r.direction == 1]
        
        # Interleave: take first from each direction, then next, etc.
        max_len = max(len(c2s_records), len(s2c_records))
        for i in range(max_len):
            if i < len(c2s_records):
                sorted_records.append(c2s_records[i])
            if i < len(s2c_records):
                sorted_records.append(s2c_records[i])
        
        return sorted_records[:20]  # Return first 20 records (model uses first 10)
    
    except Exception as e:
        logger.warning(f"Error extracting TLS records: {e}", exc_info=True)
        return []


def _extract_tls_records_from_packets_pyshark(packets: List[pd.DataFrame]) -> List[TLSRecord]:
    """
    Extract TLS records from packets using pyshark.
    
    Args:
        packets: List of packet DataFrames from a flow
    
    Returns:
        List of TLSRecord objects
    """
    if not HAS_PYSHARK:
        logger.warning("pyshark not available, cannot extract TLS records")
        return []
    
    tls_records = []
    
    # pyshark typically works with PCAP files or live capture
    # For packet DataFrames, we'd need to reconstruct or use a different approach
    # This is a placeholder for pyshark-based extraction
    
    logger.debug("pyshark extraction not yet implemented for DataFrame input")
    
    return tls_records


def _extract_tls_records_from_packets(packets: List[pd.DataFrame]) -> List[TLSRecord]:
    """
    Extract TLS records from packets by reassembling TCP and parsing TLS.
    
    Process:
    1. Reassemble TCP stream (handle fragmentation)
    2. Parse TLS records from reassembled stream
    3. Extract records with size and direction
    
    Args:
        packets: List of packet DataFrames from a flow
    
    Returns:
        List of TLSRecord objects
    """
    tls_records = []
    
    try:
        # Step 1: Reassemble TCP stream
        client_to_server, server_to_client = _reassemble_tcp_stream(packets)
        
        # Step 2: Parse TLS records from both directions
        if client_to_server:
            records_c2s = _parse_tls_records_from_bytes(client_to_server, direction=0)
            tls_records.extend(records_c2s)
            logger.debug(f"Extracted {len(records_c2s)} TLS records from client→server stream")
        
        if server_to_client:
            records_s2c = _parse_tls_records_from_bytes(server_to_client, direction=1)
            tls_records.extend(records_s2c)
            logger.debug(f"Extracted {len(records_s2c)} TLS records from server→client stream")
        
        # Step 3: Interleave records by chronological order
        # Joy processes records in chronological order (first 20 records)
        # For simplicity, we'll take client→server first, then server→client
        # In production, you'd want to interleave based on packet timestamps
        sorted_records = []
        c2s_records = [r for r in tls_records if r.direction == 0]
        s2c_records = [r for r in tls_records if r.direction == 1]
        
        # Interleave: alternate between directions (simplified)
        # This approximates chronological order
        max_len = max(len(c2s_records), len(s2c_records))
        for i in range(max_len):
            if i < len(c2s_records):
                sorted_records.append(c2s_records[i])
            if i < len(s2c_records):
                sorted_records.append(s2c_records[i])
        
        logger.debug(f"Total TLS records extracted: {len(sorted_records)}")
        return sorted_records[:20]  # Return first 20 records (model uses first 10)
    
    except Exception as e:
        logger.warning(f"Error extracting TLS records: {e}", exc_info=True)
        return []


def extract_tls_records_from_flow(packets: List[pd.DataFrame]) -> List[TLSRecord]:
    """
    Extract TLS records from a flow of packets.
    
    This function:
    1. Reassembles TCP stream (handles fragmentation)
    2. Parses TLS protocol (identifies record boundaries)
    3. Extracts TLS records (each with size and direction)
    
    Args:
        packets: List of packet DataFrames from a single flow
    
    Returns:
        List of TLSRecord objects (up to 20 records, model uses first 10)
    """
    # Use manual TLS parsing (works without scapy/pyshark)
    tls_records = _extract_tls_records_from_packets(packets)
    
    if tls_records:
        return tls_records[:20]  # Return first 20 (model uses first 10)
    
    # If no TLS records found, return empty list
    logger.debug("No TLS records extracted from flow")
    return []


def extract_tls_features_from_records(tls_records: List[TLSRecord]) -> np.ndarray:
    """
    Extract 20 TLS features from TLS records.
    
    Features: tls_b_0-9 (record sizes) + tls_dir_0-9 (directions)
    Order: [tls_b_0, ..., tls_b_9, tls_dir_0, ..., tls_dir_9]
    
    Args:
        tls_records: List of TLSRecord objects (should have at least 10 records)
    
    Returns:
        Feature array of shape (1, 20) with dtype np.float64
    """
    # Initialize features with -1 (missing value - valid for TLS models)
    tls_b = [-1.0] * 10  # TLS record sizes
    tls_dir = [-1.0] * 10  # TLS record directions
    
    # Extract from first 10 records
    n_records = min(10, len(tls_records))
    
    for i in range(n_records):
        record = tls_records[i]
        tls_b[i] = float(record.size)
        tls_dir[i] = float(record.direction)
    
    # Combine features in exact order: [tls_b_0...tls_b_9, tls_dir_0...tls_dir_9]
    features = np.array(tls_b + tls_dir, dtype=np.float64).reshape(1, 20)
    
    return features


def extract_tls_features_from_packet_sequence(packet_sequence: List[pd.DataFrame]) -> np.ndarray:
    """
    Extract 20 TLS features from packet sequence using proper TLS record extraction.
    
    This is the main function that should be called from the MoE integration.
    
    Process:
    1. Group packets into flows (5-tuple)
    2. For each flow, extract TLS records
    3. Extract features from first 10 records
    
    Args:
        packet_sequence: List of DataFrames, each representing a packet
    
    Returns:
        Feature array of shape (1, 20) with dtype np.float64
    """
    if not packet_sequence:
        logger.warning("Empty packet sequence, returning -1 features")
        return np.array([[-1.0] * 20], dtype=np.float64)
    
    # Group packets into flows
    flows = _group_packets_into_flows(packet_sequence)
    
    if not flows:
        logger.warning("Could not group packets into flows, using fallback")
        # Fallback: try to extract from all packets as single flow
        tls_records = extract_tls_records_from_flow(packet_sequence)
        if tls_records:
            return extract_tls_features_from_records(tls_records)
        else:
            # Ultimate fallback: return -1 features
            return np.array([[-1.0] * 20], dtype=np.float64)
    
    # Use the first flow (or largest flow if multiple)
    # In practice, you might want to use the flow with the most packets
    flow_key = max(flows.keys(), key=lambda k: len(flows[k]))
    flow_packets = flows[flow_key]
    
    logger.debug(f"Processing flow {flow_key} with {len(flow_packets)} packets")
    
    # Extract TLS records from flow
    tls_records = extract_tls_records_from_flow(flow_packets)
    
    if not tls_records:
        logger.warning(f"No TLS records extracted from flow {flow_key}, using fallback")
        # Fallback: return -1 features
        return np.array([[-1.0] * 20], dtype=np.float64)
    
    # Extract features from records
    features = extract_tls_features_from_records(tls_records)
    
    logger.debug(f"Extracted {len(tls_records)} TLS records, features shape: {features.shape}")
    
    return features

