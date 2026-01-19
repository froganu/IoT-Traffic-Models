"""
Configuration constants for MoE Phase 2 (Context Selection).

Centralizes thresholds, model names, and other configuration values.
"""

from typing import Dict, Set

# Confidence thresholds
DEVICE_CLASSIFIER_MIN_CONFIDENCE: float = 0.7
PROTOCOL_CLASSIFIER_MIN_CONFIDENCE: float = 0.7
PROTOCOL_CLASSIFIER_PACKET_ONLY_MIN_CONFIDENCE: float = 0.75

# Model name constants
class ModelNames:
    """Model identifier constants."""
    TLS = 'tls_model'
    QUIC = 'quic_model'
    DTLS = 'dtls_model'
    DNS = 'dns_model'
    MQTT = 'mqtt_model'
    MQTT_COAP_RTSP = 'mqtt_coap_rtsp_model'
    DOORBELL = 'doorbell_model'
    DEFAULT = 'mqtt_coap_rtsp_model'  # Default for unknown non-encrypted

# Protocol to model mapping
PROTOCOL_TO_MODEL: Dict[str, str] = {
    'dns': ModelNames.DNS,
    'mqtt': ModelNames.MQTT,
    'coap': ModelNames.MQTT_COAP_RTSP,
    'rtsp': ModelNames.MQTT_COAP_RTSP,
}

# Device type to model mapping
DEVICE_TYPE_TO_MODEL: Dict[str, str] = {
    'Doorbell': ModelNames.DOORBELL,
    'Other': None,  # Falls through to protocol classifier
}

# Port-based routing (fallback)
PORT_TO_MODEL: Dict[int, str] = {
    53: ModelNames.DNS,      # DNS
    1883: ModelNames.MQTT,   # MQTT
    8883: ModelNames.MQTT,   # MQTT-TLS
    5683: ModelNames.MQTT_COAP_RTSP,  # CoAP
    5684: ModelNames.MQTT_COAP_RTSP,  # CoAP-DTLS
    554: ModelNames.MQTT_COAP_RTSP,   # RTSP
}

# Security limits
MAX_PACKET_BYTES_SIZE: int = 10 * 1024 * 1024  # 10 MB
MAX_PACKET_DATA_ROWS: int = 100000  # Max rows in packet_data DataFrame

# Supported L4 protocols
SUPPORTED_L4_PROTOCOLS: Set[str] = {'tcp', 'udp'}

# Common UDP ports (for protocol inference)
UDP_PORTS: Set[int] = {53, 5683, 5684}

# Common TCP ports (for protocol inference)
TCP_PORTS: Set[int] = {1883, 8883, 554}

