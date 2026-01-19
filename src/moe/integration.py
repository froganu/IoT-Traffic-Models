"""
Mixture of Experts (MoE) System for C2 Traffic Detection - SKELETON

This is a minimal skeleton framework for PACKET-LEVEL processing.
Fill in:
1. Encryption detection logic in check_encryption()
2. Model loading and prediction logic for each expert
3. Packet feature extraction
"""

import logging
from typing import Dict, Optional, Tuple, Any, List
import pandas as pd
import numpy as np

# Import configuration constants
from .config import (
    DEVICE_CLASSIFIER_MIN_CONFIDENCE,
    PROTOCOL_CLASSIFIER_MIN_CONFIDENCE,
    PROTOCOL_CLASSIFIER_PACKET_ONLY_MIN_CONFIDENCE,
    ModelNames,
    PROTOCOL_TO_MODEL,
    DEVICE_TYPE_TO_MODEL,
    PORT_TO_MODEL,
    MAX_PACKET_BYTES_SIZE,
    MAX_PACKET_DATA_ROWS,
    SUPPORTED_L4_PROTOCOLS,
    UDP_PORTS,
    TCP_PORTS,
)
from .accuracy_table import AccuracyTable
from .model_mapping import get_model_file_name

# Global accuracy table instance (lazy-loaded)
_ACCURACY_TABLE: Optional[AccuracyTable] = None


def _get_accuracy_table() -> AccuracyTable:
    """Get or create the global accuracy table instance."""
    global _ACCURACY_TABLE
    if _ACCURACY_TABLE is None:
        _ACCURACY_TABLE = AccuracyTable()
    return _ACCURACY_TABLE

# Set up logger
logger = logging.getLogger(__name__)

# Module-level imports (performance optimization)
try:
    from src.context_selection_models import (
        select_device_context_safe,
        classify_packet,
        PacketMetadata,
        ProtocolLabel,
    )
    _DEVICE_CLASSIFIER_AVAILABLE = True
    _PROTOCOL_CLASSIFIER_AVAILABLE = True
except ImportError as e:
    logger.warning(f"Context selection models not available: {e}")
    _DEVICE_CLASSIFIER_AVAILABLE = False
    _PROTOCOL_CLASSIFIER_AVAILABLE = False


def check_encryption(packet_data: pd.DataFrame, 
                     port: Optional[int] = None,
                     protocol: Optional[str] = None,
                     packet_bytes: Optional[bytes] = None) -> Tuple[bool, Optional[str]]:
    """
    Check if a packet (or packet sequence) is encrypted or not.
    
    Uses the encryption_detector module for deterministic detection.
    
    Args:
        packet_data: DataFrame with packet-level features (one row per packet)
        port: Destination port number (optional, from packet header)
        protocol: Protocol string (optional, from packet header)
        packet_bytes: Raw packet bytes (optional, for header inspection)
    
    Returns:
        Tuple of (is_encrypted: bool, protocol_type: Optional[str])
        protocol_type examples: 'tls', 'quic', 'dtls', or None
    """
    # Use encryption_detector module if packet_bytes provided
    # Note: Check 'is not None' to allow empty bytes (b'') to be analyzed
    if packet_bytes is not None:
        try:
            import sys
            from pathlib import Path
            # Add src to path for imports
            src_path = Path(__file__).parent.parent.parent
            if str(src_path) not in sys.path:
                sys.path.insert(0, str(src_path))
            from src.encryption_detector import analyze_packet
            result = analyze_packet(packet_bytes, port=port, protocol=protocol)
            # Extract protocol_type from encrypted_family when encrypted
            protocol_type = result.encrypted_family.value if result.encrypted else None
            # Map 'unknown' to None for consistency
            if protocol_type == 'unknown':
                protocol_type = None
            return result.encrypted, protocol_type
        except ImportError:
            # Fallback if module not available
            pass
        except Exception as e:
            # Log other exceptions but fall back to heuristics
            # This prevents silent failures while maintaining fallback behavior
            import warnings
            warnings.warn(f"Encryption detection failed: {e}. Falling back to port heuristics.", RuntimeWarning)
            pass
    
    # Fallback: Port-based heuristics
    if port == 443:
        return True, 'tls'
    elif port == 53:
        return False, None
    elif port in [1883, 8883]:
        return False, None  # MQTT
    elif port in [5683, 5684]:
        return False, None  # CoAP
    
    return False, None


def _validate_packet_data(packet_data: pd.DataFrame) -> None:
    """
    Validate packet_data DataFrame structure and size.
    
    Args:
        packet_data: DataFrame to validate
    
    Raises:
        ValueError: If packet_data is invalid
    """
    if not isinstance(packet_data, pd.DataFrame):
        raise ValueError(f"packet_data must be a pandas DataFrame, got {type(packet_data)}")
    
    if packet_data.empty:
        raise ValueError("packet_data cannot be empty")
    
    if len(packet_data) > MAX_PACKET_DATA_ROWS:
        raise ValueError(
            f"packet_data has too many rows ({len(packet_data)} > {MAX_PACKET_DATA_ROWS}). "
            "This may indicate a processing error."
        )


def _extract_packet_metadata(packet_data: pd.DataFrame) -> Tuple[Optional[int], Optional[int], str]:
    """
    Extract metadata from packet_data DataFrame.
    
    Args:
        packet_data: DataFrame with packet features
    
    Returns:
        Tuple of (dst_port, src_port, l4_proto)
    """
    dst_port = None
    src_port = None
    l4_proto = 'tcp'  # Default
    
    # Extract ports
    if 'dst_port' in packet_data.columns:
        dst_port = packet_data['dst_port'].iloc[0] if len(packet_data) > 0 else None
    elif 'port' in packet_data.columns:
        dst_port = packet_data['port'].iloc[0] if len(packet_data) > 0 else None
    
    if 'src_port' in packet_data.columns:
        src_port = packet_data['src_port'].iloc[0] if len(packet_data) > 0 else None
    
    # Infer L4 protocol
    if 'protocol' in packet_data.columns:
        proto_str = packet_data['protocol'].iloc[0] if len(packet_data) > 0 else None
        if proto_str and isinstance(proto_str, str):
            l4_proto = proto_str.lower()
            if l4_proto not in SUPPORTED_L4_PROTOCOLS:
                logger.warning(f"Unsupported protocol '{l4_proto}', defaulting to 'tcp'")
                l4_proto = 'tcp'
    elif dst_port:
        # Heuristic: infer from port
        if dst_port in UDP_PORTS:
            l4_proto = 'udp'
        elif dst_port in TCP_PORTS:
            l4_proto = 'tcp'
    
    return dst_port, src_port, l4_proto


def _get_packet_bytes_safe(packet_data: pd.DataFrame) -> Optional[bytes]:
    """
    Safely extract packet_bytes from DataFrame with size validation.
    
    Args:
        packet_data: DataFrame that may contain 'packet_bytes' column
    
    Returns:
        Packet bytes or None if not available/invalid
    """
    if 'packet_bytes' not in packet_data.columns:
        return None
    
    if len(packet_data) == 0:
        return None
    
    try:
        packet_bytes = packet_data['packet_bytes'].iloc[0]
        
        # Validate type
        if not isinstance(packet_bytes, bytes):
            logger.warning(f"packet_bytes is not bytes type: {type(packet_bytes)}")
            return None
        
        # Validate size (security check)
        if len(packet_bytes) > MAX_PACKET_BYTES_SIZE:
            logger.warning(
                f"packet_bytes too large ({len(packet_bytes)} > {MAX_PACKET_BYTES_SIZE} bytes). "
                "Truncating for security."
            )
            return packet_bytes[:MAX_PACKET_BYTES_SIZE]
        
        return packet_bytes
    except (IndexError, AttributeError) as e:
        logger.debug(f"Error extracting packet_bytes: {e}")
        return None


def select_context(packet_data: pd.DataFrame, 
                   is_encrypted: bool,
                   protocol_type: Optional[str] = None) -> str:
    """
    Phase 2: Context Selection - Device Type Classification + Protocol Classification.
    
    Returns a context identifier (not a model name). Phase 3 will use this context
    to select the best model from the accuracy table.
    
    Phase 2 performs TWO types of classification for non-encrypted traffic:
    1. **Device Type Classification**: Identifies device type (Doorbell vs Other)
       - Uses meta-feature extraction (pymfe) and Random Forest classifier
       - If Doorbell detected with high confidence → returns 'doorbell' context
       - If Other or low confidence → continues to protocol classification
    2. **Protocol Classification**: Identifies protocol (DNS, MQTT, CoAP, RTSP)
       - Uses deterministic signature-based detection
       - Returns protocol-specific context (e.g., 'dns', 'mqtt_coap_rtsp')
    
    For encrypted traffic:
    - Returns 'tls' context (all encrypted traffic uses TLS context)
    
    Args:
        packet_data: DataFrame with packet-level features (one row per packet)
        is_encrypted: Whether traffic is encrypted (from check_encryption)
        protocol_type: Type of encryption protocol if encrypted (e.g., 'tls', 'quic', 'dtls')
    
    Returns:
        Context identifier string:
        - 'tls': Encrypted traffic
        - 'doorbell': Doorbell device (from device classifier)
        - 'dns': DNS protocol (from protocol classifier)
        - 'mqtt_coap_rtsp': MQTT, CoAP, or RTSP protocol (from protocol classifier)
        - 'gre': Fallback for unknown non-encrypted traffic
    
    Raises:
        ValueError: If packet_data is invalid
    
    Flow for non-encrypted traffic:
    1. **Device Classifier** → if Doorbell (high confidence): return 'doorbell' (wins immediately)
    2. **Device Classifier** → if Other (high confidence): continue to protocol classifier
    3. **Protocol Classifier** → if DNS/MQTT/CoAP/RTSP (high confidence): return protocol context
    4. **Protocol Classifier** → if UNKNOWN or low confidence: 
       - If device is "Other" (high confidence): return 'gre' (Other device context)
       - Otherwise: continue to port fallback
    5. **Port-based Fallback** → use port heuristics
    6. **Default**: 'mqtt_coap_rtsp'
    """
    # Input validation
    _validate_packet_data(packet_data)
    
    if is_encrypted:
        # Encrypted traffic: return TLS context
        # Phase 3 will select the best model for TLS context
        if protocol_type == 'tls':
            logger.debug("Selected context: tls (encrypted TLS traffic)")
            return 'tls'
        elif protocol_type == 'quic':
            logger.debug("Selected context: tls (QUIC uses TLS context)")
            return 'tls'  # QUIC uses TLS context for now
        elif protocol_type == 'dtls':
            logger.debug("Selected context: tls (DTLS uses TLS context)")
            return 'tls'  # DTLS uses TLS context for now
        else:
            logger.debug(f"Unknown encryption protocol '{protocol_type}', defaulting to TLS context")
            return 'tls'  # Default to TLS context for encrypted traffic
    else:
        # Non-encrypted traffic: use TWO classifiers in sequence
        # Step 1: Device Type Classification
        # Step 2: Protocol Classification (if device is "Other")
        
        device_type = None
        device_confidence = None
        
        # Step 1: Device Type Classifier - Identify device type (Doorbell vs Other)
        if _DEVICE_CLASSIFIER_AVAILABLE:
            try:
                device_type, device_confidence = select_device_context_safe(packet_data)
                
                if device_type is not None and device_confidence is not None:
                    logger.debug(
                        f"Device classifier result: {device_type} "
                        f"(confidence: {device_confidence:.2f})"
                    )
                    
                    # Check if confidence is sufficient
                    if device_confidence >= DEVICE_CLASSIFIER_MIN_CONFIDENCE:
                        if device_type == 'Doorbell':
                            # Doorbell wins - return immediately
                            logger.info("Selected context: doorbell (device classifier identified Doorbell)")
                            return 'doorbell'
                        # 'Other' device type: continue to protocol classifier
                        logger.debug(f"Device type is 'Other', continuing to protocol classifier")
                    else:
                        logger.debug(
                            f"Device classifier confidence too low "
                            f"({device_confidence:.2f} < {DEVICE_CLASSIFIER_MIN_CONFIDENCE}), "
                            "trying protocol classifier"
                        )
                else:
                    logger.debug("Device classifier returned None, trying protocol classifier")
            except Exception as e:
                logger.warning(f"Device classifier error: {e}. Trying protocol classifier.", exc_info=True)
        else:
            logger.debug("Device classifier not available, trying protocol classifier")
        
        # Step 2: Protocol Classifier - Identify protocol (DNS, MQTT, CoAP, RTSP)
        # Only used if device type is "Other" or device classifier unavailable/failed
        protocol_classified = False
        protocol_context = None
        
        if _PROTOCOL_CLASSIFIER_AVAILABLE:
            try:
                # Extract metadata efficiently
                dst_port, src_port, l4_proto = _extract_packet_metadata(packet_data)
                
                # Get packet bytes safely
                packet_bytes = _get_packet_bytes_safe(packet_data)
                
                # Create metadata for protocol classifier
                meta = PacketMetadata(
                    l4_proto=l4_proto,
                    src_port=src_port,
                    dst_port=dst_port,
                    captured_payload_offset=0
                )
                
                # Classify protocol
                protocol_result = classify_packet(packet_bytes or b'', meta)
                
                logger.debug(
                    f"Protocol classifier result: {protocol_result.label.value} "
                    f"(confidence: {protocol_result.confidence:.2f}, "
                    f"evidence: {protocol_result.evidence.value})"
                )
                
                # Check if protocol classifier succeeded with sufficient confidence
                min_confidence = (
                    PROTOCOL_CLASSIFIER_PACKET_ONLY_MIN_CONFIDENCE 
                    if packet_bytes is None 
                    else PROTOCOL_CLASSIFIER_MIN_CONFIDENCE
                )
                
                if (protocol_result.label != ProtocolLabel.UNKNOWN and 
                    protocol_result.confidence >= min_confidence):
                    
                    # Map protocol to context
                    protocol_name = protocol_result.label.value.lower()
                    context_map = {
                        'dns': 'dns',
                        'mqtt': 'mqtt_coap_rtsp',
                        'coap': 'mqtt_coap_rtsp',
                        'rtsp': 'mqtt_coap_rtsp',
                    }
                    protocol_context = context_map.get(protocol_name)
                    
                    if protocol_context:
                        protocol_classified = True
                        logger.info(
                            f"Selected context: {protocol_context} "
                            f"(protocol classifier identified {protocol_result.label.value})"
                        )
                        return protocol_context
                    else:
                        logger.debug(f"Protocol '{protocol_result.label.value}' not mapped to context")
                else:
                    logger.debug(
                        f"Protocol classifier confidence too low "
                        f"({protocol_result.confidence:.2f} < {min_confidence:.2f}) "
                        f"or UNKNOWN protocol"
                    )
            except Exception as e:
                logger.warning(f"Protocol classifier error: {e}. Using fallback.", exc_info=True)
        else:
            logger.debug("Protocol classifier not available, using fallback")
        
        # Step 3: Fallback logic
        # If device type is "Other" and protocol classification failed → use "Other" device context
        if device_type == 'Other' and device_confidence is not None and device_confidence >= DEVICE_CLASSIFIER_MIN_CONFIDENCE:
            # Device is "Other" with high confidence, but protocol unknown → use "Other" device context
            logger.info(
                f"Selected context: gre (device type is 'Other' with confidence {device_confidence:.2f}, "
                f"but protocol classification failed/unknown)"
            )
            return 'gre'  # GRE context for "Other" device type
        
        # Step 3: Port-based fallback (only if device classifier didn't identify "Other" with confidence)
        dst_port, _, _ = _extract_packet_metadata(packet_data)
        
        if dst_port is not None:
            model = PORT_TO_MODEL.get(dst_port)
            if model:
                # Map model name to context
                port_to_context = {
                    ModelNames.DNS: 'dns',
                    ModelNames.MQTT: 'mqtt_coap_rtsp',
                    ModelNames.MQTT_COAP_RTSP: 'mqtt_coap_rtsp',
                }
                context = port_to_context.get(model)
                
                if context:
                    logger.info(f"Selected context: {context} (based on port {dst_port})")
                    return context
        
        # Default: use mqtt_coap_rtsp context for unknown non-encrypted traffic
        logger.debug("No classifier or port match, using default context: mqtt_coap_rtsp")
        return 'mqtt_coap_rtsp'


def select_ai_model(context: str) -> str:
    """
    Phase 3: Select the best AI model for a given context using the accuracy table.
    
    Args:
        context: Context identifier from Phase 2 (e.g., 'tls', 'dns', 'doorbell', 'mqtt_coap_rtsp')
    
    Returns:
        Model identifier string in format: '{context}_{model_id}_model'
        Example: 'dns_xgboost_model', 'tls_xgboost_model'
    
    Raises:
        ValueError: If context is invalid or no models found
    """
    logger.debug(f"Phase 3: Selecting best model for context '{context}'")
    
    # Get accuracy table
    acc_table = _get_accuracy_table()
    
    # Get best model for context
    best_model = acc_table.get_best_model(context)
    
    if best_model:
        model_id, accuracy = best_model
        model_name = f"{context}_{model_id}_model"
        logger.info(
            f"Selected model: {model_name} "
            f"(accuracy: {accuracy:.4f} from accuracy table)"
        )
        return model_name
    else:
        # Fallback: use legacy model name format
        logger.warning(f"No models found in accuracy table for context '{context}', using legacy format")
        legacy_map = {
            'tls': ModelNames.TLS,
            'dns': ModelNames.DNS,
            'doorbell': ModelNames.DOORBELL,
            'mqtt_coap_rtsp': ModelNames.MQTT_COAP_RTSP,
            'gre': ModelNames.MQTT_COAP_RTSP,  # GRE uses mqtt_coap_rtsp as fallback
        }
        return legacy_map.get(context, ModelNames.DEFAULT)


def load_model(model_name: str):
    """
    Load a trained AI model.
    
    Supports two model name formats:
    1. Legacy format: 'tls_model', 'dns_model', etc. (uses default/best model)
    2. New format: 'context_modelid_model' (e.g., 'tls_xgboost_model', 'dns_random_forest_model')
    
    Args:
        model_name: Model identifier (from select_ai_model)
    
    Returns:
        Loaded model object
    
    Raises:
        FileNotFoundError: If model file not found
        ImportError: If required libraries not available
    """
    logger.debug(f"Loading model: {model_name}")
    
    # Parse model name format: context_modelid_model or legacy format
    if '_' in model_name and model_name.endswith('_model'):
        # New format: context_modelid_model
        parts = model_name.rsplit('_', 2)  # Split from right to get [context, modelid, 'model']
        if len(parts) == 3:
            context = parts[0]
            model_id = parts[1]
            
            # Get model file path
            model_file = get_model_file_name(context, model_id)
            if model_file:
                return _load_model_from_file(model_file)
            else:
                logger.warning(f"Model file not found for {model_name}, trying legacy format")
    
    # Legacy format: use accuracy table to get best model
    legacy_to_context = {
        ModelNames.TLS: 'tls',
        ModelNames.DNS: 'dns',
        ModelNames.DOORBELL: 'doorbell',
        ModelNames.MQTT_COAP_RTSP: 'mqtt_coap_rtsp',
        ModelNames.MQTT: 'mqtt_coap_rtsp',
    }
    
    context = legacy_to_context.get(model_name)
    if context:
        acc_table = _get_accuracy_table()
        best_model = acc_table.get_best_model(context)
        if best_model:
            model_id, _ = best_model
            model_file = get_model_file_name(context, model_id)
            if model_file:
                return _load_model_from_file(model_file)
    
    logger.warning(f"Could not load model: {model_name}")
    return None


def _load_model_from_file(model_file: str):
    """
    Load a model from file based on file extension.
    
    Args:
        model_file: Path to model file
    
    Returns:
        Loaded model object
    """
    from pathlib import Path
    
    model_path = Path(model_file)
    
    if not model_path.exists():
        raise FileNotFoundError(f"Model file not found: {model_path}")
    
    file_ext = model_path.suffix.lower()
    
    try:
        if file_ext == '.pkl':
            import joblib
            logger.debug(f"Loading pickle model: {model_path}")
            return joblib.load(model_path)
        elif file_ext in ['.h5', '.keras']:
            try:
                import tensorflow as tf
                logger.debug(f"Loading Keras/TensorFlow model: {model_path}")
                return tf.keras.models.load_model(model_path)
            except ImportError:
                raise ImportError("TensorFlow is required to load .h5/.keras models. Install with: pip install tensorflow")
        elif file_ext == '.zip':
            import zipfile
            import joblib
            logger.debug(f"Loading zipped model: {model_path}")
            # Extract and load (simplified - may need adjustment based on actual zip structure)
            with zipfile.ZipFile(model_path, 'r') as zip_ref:
                # Assume model is in root of zip
                import tempfile
                with tempfile.TemporaryDirectory() as tmpdir:
                    zip_ref.extractall(tmpdir)
                    # Try to find .pkl file in extracted contents
                    for file in Path(tmpdir).rglob('*.pkl'):
                        return joblib.load(file)
                    raise ValueError(f"No .pkl file found in zip: {model_path}")
        else:
            raise ValueError(f"Unsupported model file format: {file_ext}")
    
    except Exception as e:
        logger.error(f"Error loading model from {model_path}: {e}", exc_info=True)
        raise


def extract_packet_features(packet_data: pd.DataFrame, 
                           model_name: str,
                           packet_sequence: Optional[List[pd.DataFrame]] = None) -> np.ndarray:
    """
    Extract features from packet(s) for model prediction.
    
    TODO: Implement feature extraction for each model type.
    
    Args:
        packet_data: DataFrame with packet-level features (one row per packet)
        model_name: Model identifier (to know which features to extract)
        packet_sequence: Optional sequence of previous packets (for sequence-based models)
    
    Returns:
        Feature array ready for model prediction
    """
    # TODO: Implement feature extraction
    # Examples:
    # if model_name == 'tls_model':
    #     # Extract TLS behavior features: packet sizes, directions
    #     # For TLS: need first N packets to extract tls_b_0-9, tls_dir_0-9
    #     # If packet_sequence provided, use it; otherwise use current packet
    #     features = extract_tls_features(packet_sequence or [packet_data])
    #     return features
    # elif model_name == 'dns_model':
    #     # Extract DNS features: packet size, port, protocol
    #     features = extract_dns_features(packet_data)
    #     return features
    
    # Placeholder: return empty array
    return np.array([])


def predict_c2(model, packet_features: np.ndarray) -> Dict[str, Any]:
    """
    Use the selected model to predict C2 traffic from packet features.
    
    TODO: Implement prediction logic for each model type.
    
    Args:
        model: Loaded model object (from load_model)
        packet_features: Feature array extracted from packet(s) (from extract_packet_features)
    
    Returns:
        Dictionary with prediction results:
        {
            'is_c2': bool or array of bools,
            'probability': float or array of floats,
            'predictions': array of predictions
        }
    """
    # TODO: Implement prediction logic
    # Examples:
    # if hasattr(model, 'predict'):
    #     predictions = model.predict(packet_features)
    #     probabilities = model.predict_proba(packet_features)[:, 1] if hasattr(model, 'predict_proba') else None
    #     return {
    #         'is_c2': predictions == 1,
    #         'probability': probabilities,
    #         'predictions': predictions
    #     }
    
    return {
        'is_c2': None,
        'probability': None,
        'predictions': None
    }  # Placeholder


def detect_c2(packet_data: pd.DataFrame,
              port: Optional[int] = None,
              protocol: Optional[str] = None,
              packet_bytes: Optional[bytes] = None,
              packet_sequence: Optional[List[pd.DataFrame]] = None) -> Dict[str, Any]:
    """
    Main function: Detect C2 traffic using MoE system at PACKET LEVEL.
    
    Flow:
    1. Check if encrypted (from packet header/bytes)
    2. Select appropriate AI model
    3. Load model
    4. Extract packet features
    5. Predict C2
    
    Args:
        packet_data: DataFrame with packet-level features (one row per packet)
        port: Destination port number (optional, from packet header)
        protocol: Protocol string (optional, from packet header)
        packet_bytes: Raw packet bytes (optional, for encryption detection)
        packet_sequence: Optional sequence of previous packets (for sequence-based features)
    
    Returns:
        Dictionary with detection results:
        {
            'is_encrypted': bool,
            'protocol_type': str or None,
            'model_used': str,
            'is_c2': bool or array,
            'probability': float or array,
            'predictions': array
        }
    """
    # Phase 1: Check encryption
    is_encrypted, protocol_type = check_encryption(
        packet_data, port=port, protocol=protocol, packet_bytes=packet_bytes
    )
    
    # Phase 2: Select context
    context = select_context(packet_data, is_encrypted, protocol_type)
    
    # Phase 3: Select best AI model for context (using accuracy table)
    model_name = select_ai_model(context)
    
    # Load model
    model = load_model(model_name)
    
    # Extract packet features
    packet_features = extract_packet_features(packet_data, model_name, packet_sequence)
    
    # Predict
    prediction_results = predict_c2(model, packet_features)
    
    # Combine results
    result = {
        'is_encrypted': is_encrypted,
        'protocol_type': protocol_type,
        'context': context,  # Phase 2 output
        'model_used': model_name,  # Phase 3 output
        **prediction_results
    }
    
    return result


if __name__ == "__main__":
    # Example usage
    print("MoE System Skeleton - C2 Traffic Detection (PACKET-LEVEL)")
    print("=" * 50)
    print("\nThis is a skeleton for PACKET-LEVEL processing. Implement the TODO sections:")
    print("1. check_encryption() - Encryption detection from packet header/bytes")
    print("2. select_ai_model() - Model selection logic")
    print("3. load_model() - Model loading logic")
    print("4. extract_packet_features() - Extract features from packet(s)")
    print("5. predict_c2() - Prediction logic")
    print("\nExample call:")
    print("  result = detect_c2(packet_data, port=443, packet_bytes=raw_bytes)")
    print("  print(result)")
    print("\nNote: For sequence-based models (e.g., TLS with first N packets),")
    print("      provide packet_sequence parameter with previous packets.")
