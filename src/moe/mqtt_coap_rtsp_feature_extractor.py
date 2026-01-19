"""
MQTT/CoAP/RTSP Feature Extractor

Extracts 16 features from packet-level data for MQTT/CoAP/RTSP models.
"""

import pandas as pd
import numpy as np
import logging
from typing import List, Optional, Dict
from pathlib import Path
import struct

logger = logging.getLogger(__name__)

# Try to import preprocessing components
try:
    from .mqtt_coap_rtsp_preprocessing import (
        load_preprocessing_components,
        FEATURE_ORDER,
        CATEGORICAL_COLUMNS,
    )
    PREPROCESSING_AVAILABLE = True
except ImportError:
    PREPROCESSING_AVAILABLE = False
    logger.warning("MQTT/CoAP/RTSP preprocessing components not available")


def _extract_packet_features_from_bytes(packet_bytes: bytes) -> Dict[str, any]:
    """
    Extract packet features from raw packet bytes (Ethernet frame).
    
    Args:
        packet_bytes: Raw packet bytes (Ethernet frame)
    
    Returns:
        Dictionary with feature names as keys
    """
    features = {}
    
    if len(packet_bytes) < 14:  # Minimum Ethernet header
        logger.warning("Packet too short, returning default features")
        return _get_default_features()
    
    # Extract frame length
    features['frame.len'] = len(packet_bytes)
    
    # Skip Ethernet header (14 bytes)
    ip_data = packet_bytes[14:]
    
    if len(ip_data) < 20:  # Minimum IP header
        logger.warning("IP header too short, returning default features")
        return _get_default_features()
    
    # Parse IP header
    ip_version = (ip_data[0] >> 4) & 0x0F
    if ip_version != 4:  # Only support IPv4
        logger.warning("Not IPv4, returning default features")
        return _get_default_features()
    
    ip_header_len = (ip_data[0] & 0x0F) * 4
    ip_protocol = ip_data[9]
    ip_ttl = ip_data[8]
    
    # Extract IP fields
    features['ip.ttl'] = int(ip_ttl)
    features['ip.proto'] = int(ip_protocol)
    features['ip.flags'] = f"0x{(ip_data[6] >> 5) & 0x07:02x}"  # IP flags (simplified)
    features['ip.checksum'] = f"0x{struct.unpack('>H', ip_data[10:12])[0]:04x}"  # IP checksum
    
    # Build protocol stack
    protocol_stack = "eth:ethertype:ip"
    
    # Parse L4 protocol
    l4_data = ip_data[ip_header_len:]
    
    if ip_protocol == 6:  # TCP
        protocol_stack += ":tcp"
        features.update(_extract_tcp_features(l4_data))
        features['udp.srcport'] = np.nan
        features['udp.dstport'] = np.nan
    elif ip_protocol == 17:  # UDP
        protocol_stack += ":udp"
        features.update(_extract_udp_features(l4_data))
        features['tcp.srcport'] = np.nan
        features['tcp.dstport'] = np.nan
        features['tcp.flags'] = np.nan
        features['tcp.window_size_value'] = np.nan
        features['tcp.window_size_scalefactor'] = np.nan
        features['tcp.checksum'] = np.nan
        features['tcp.options'] = np.nan
        features['tcp.pdu.size'] = np.nan
    else:
        # Other protocol (ICMP, etc.)
        protocol_stack += f":proto{ip_protocol}"
        # Set all TCP/UDP fields to NaN
        features.update(_get_default_tcp_udp_features())
    
    features['frame.protocols'] = protocol_stack
    
    return features


def _extract_tcp_features(tcp_data: bytes) -> Dict[str, any]:
    """Extract TCP-specific features."""
    features = {}
    
    if len(tcp_data) < 20:  # Minimum TCP header
        return _get_default_tcp_features()
    
    # Extract TCP ports
    features['tcp.srcport'] = struct.unpack('>H', tcp_data[0:2])[0]
    features['tcp.dstport'] = struct.unpack('>H', tcp_data[2:4])[0]
    
    # Extract TCP flags
    flags_byte = tcp_data[13]
    features['tcp.flags'] = f"0x{flags_byte:04x}"
    
    # Extract TCP window size
    features['tcp.window_size_value'] = struct.unpack('>H', tcp_data[14:16])[0]
    
    # Extract TCP checksum
    features['tcp.checksum'] = f"0x{struct.unpack('>H', tcp_data[16:18])[0]:04x}"
    
    # Extract TCP header length
    tcp_header_len = ((tcp_data[12] >> 4) & 0x0F) * 4
    
    # Extract TCP options (if present)
    if tcp_header_len > 20:
        options = tcp_data[20:tcp_header_len]
        features['tcp.options'] = options.hex()
    else:
        features['tcp.options'] = np.nan
    
    # Extract TCP PDU size (payload size)
    if len(tcp_data) > tcp_header_len:
        features['tcp.pdu.size'] = len(tcp_data) - tcp_header_len
    else:
        features['tcp.pdu.size'] = 0
    
    # Extract window scale factor (from TCP options, simplified)
    # This is a simplified extraction - real implementation would parse options
    features['tcp.window_size_scalefactor'] = 0  # Default, would need proper parsing
    
    return features


def _extract_udp_features(udp_data: bytes) -> Dict[str, any]:
    """Extract UDP-specific features."""
    features = {}
    
    if len(udp_data) < 8:  # Minimum UDP header
        return {'udp.srcport': np.nan, 'udp.dstport': np.nan}
    
    features['udp.srcport'] = struct.unpack('>H', udp_data[0:2])[0]
    features['udp.dstport'] = struct.unpack('>H', udp_data[2:4])[0]
    
    return features


def _get_default_features() -> Dict[str, any]:
    """Return default feature values (all NaN/0)."""
    features = {
        'frame.len': 0,
        'frame.protocols': 'eth:ethertype:ip',
        'ip.flags': '0x00',
        'ip.ttl': 64,
        'ip.proto': 0,
        'ip.checksum': '0x0000',
    }
    features.update(_get_default_tcp_udp_features())
    return features


def _get_default_tcp_features() -> Dict[str, any]:
    """Return default TCP feature values."""
    return {
        'tcp.srcport': np.nan,
        'tcp.dstport': np.nan,
        'tcp.flags': np.nan,
        'tcp.window_size_value': np.nan,
        'tcp.window_size_scalefactor': np.nan,
        'tcp.checksum': np.nan,
        'tcp.options': np.nan,
        'tcp.pdu.size': np.nan,
    }


def _get_default_tcp_udp_features() -> Dict[str, any]:
    """Return default TCP and UDP feature values."""
    features = _get_default_tcp_features()
    features.update({
        'udp.srcport': np.nan,
        'udp.dstport': np.nan,
    })
    return features


def extract_mqtt_coap_rtsp_features(packet_data: pd.DataFrame,
                                    packet_bytes: Optional[bytes] = None,
                                    label_encoders: Optional[Dict] = None,
                                    scaler: Optional[object] = None) -> np.ndarray:
    """
    Extract 16 features for MQTT/CoAP/RTSP models from packet-level DataFrame.
    
    Args:
        packet_data: DataFrame with packet-level features (one row per packet)
                    Expected columns match CSV structure
        packet_bytes: Optional raw packet bytes (if not provided, extract from DataFrame)
        label_encoders: Optional dict of LabelEncoder objects (if None, try to load)
        scaler: Optional StandardScaler object (if None, try to load)
    
    Returns:
        Feature array of shape (n_packets, 16) ready for model prediction
    """
    # Step 1: Extract features from packet_data or packet_bytes
    if packet_bytes is not None:
        # Extract from raw packet bytes
        features_dict = _extract_packet_features_from_bytes(packet_bytes)
        packet_df = pd.DataFrame([features_dict])
    else:
        # Use packet_data DataFrame (assume it has the right columns)
        packet_df = packet_data.copy()
    
    # Step 2: Drop identifier columns
    cols_to_drop = ['frame.time', 'eth.src', 'eth.dst', 'ip.src', 'ip.dst', 'label', 'ip.tos']
    packet_df = packet_df.drop(columns=[c for c in cols_to_drop if c in packet_df.columns], errors='ignore')
    
    # Step 3: Ensure all feature columns exist (fill missing with NaN)
    for col in FEATURE_ORDER:
        if col not in packet_df.columns:
            packet_df[col] = np.nan
    
    # Step 4: Reorder columns to match feature order
    packet_df = packet_df[FEATURE_ORDER]
    
    # Step 5: Load preprocessing components if not provided
    if label_encoders is None or scaler is None:
        if PREPROCESSING_AVAILABLE:
            try:
                preproc = load_preprocessing_components()
                label_encoders = preproc['label_encoders']
                scaler = preproc['scaler']
            except FileNotFoundError:
                logger.warning(
                    "Preprocessing components not found. "
                    "Features will not be encoded/scaled. "
                    "Run create_preprocessing_components() first."
                )
                # Continue without encoding/scaling (will likely fail at model prediction)
                label_encoders = {}
                scaler = None
        else:
            logger.warning("Preprocessing components not available")
            label_encoders = {}
            scaler = None
    
    # Step 6: Encode categorical features
    # Check if all required LabelEncoders are available
    missing_encoders = [col for col in CATEGORICAL_COLUMNS if col in packet_df.columns and col not in label_encoders]
    
    if missing_encoders:
        logger.error(
            f"Missing LabelEncoders for MQTT/CoAP/RTSP feature extraction: {missing_encoders}. "
            f"Please run create_preprocessing_components() first to create the encoders."
        )
        return np.array([])  # Return empty array if encoders missing
    
    for col in CATEGORICAL_COLUMNS:
        if col not in packet_df.columns:
            continue
        
        if col in label_encoders:
            le = label_encoders[col]
            # Handle NaN values
            col_data = packet_df[col].fillna('nan').astype(str)
            # Handle unseen values (use 0 as default)
            encoded = col_data.apply(
                lambda x: le.transform([x])[0] if x in le.classes_ else 0
            )
            packet_df[col] = encoded
        else:
            # This shouldn't happen due to check above, but handle gracefully
            logger.error(f"LabelEncoder not found for '{col}' despite check")
            return np.array([])
    
    # Step 7: Handle NaN values (fill with 0)
    packet_df = packet_df.fillna(0)
    
    # Step 8: Convert to numpy array (all should be numeric now)
    try:
        features = packet_df.values.astype(float)
    except ValueError as e:
        logger.error(
            f"Error converting features to float. Some columns may still be strings. "
            f"Error: {e}. Ensure all categorical columns are encoded."
        )
        return np.array([])
    
    # Step 9: Apply StandardScaler if available
    if scaler is not None:
        features = scaler.transform(features)
    else:
        logger.warning("StandardScaler not available, features not scaled")
    
    return features  # Shape: (n_packets, 16)

