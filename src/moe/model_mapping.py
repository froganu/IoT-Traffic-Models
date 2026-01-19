"""
Model file mapping for MoE system.

Maps context + model_id to actual model file paths.
"""

from typing import Dict, Optional
from pathlib import Path
import logging

logger = logging.getLogger(__name__)

# Base path for trained models
TRAINED_MODELS_BASE = Path(__file__).parent.parent / 'trained_models'

# Model file mapping: (context, model_id) -> model_file_name
MODEL_FILE_MAPPING: Dict[tuple, str] = {
    # TLS models
    ('tls', 'random_forest'): 'TLS/random_forest_model.pkl',
    ('tls', 'dnn'): 'TLS/dnn_model.h5',
    ('tls', 'knn'): 'TLS/knn_model.pkl',
    ('tls', 'xgboost'): 'TLS/xgb_model.pkl',
    ('tls', 'extra_trees'): 'TLS/ extra_trees_model.pkl',  # Note: filename has leading space
    ('tls', 'decision_tree'): 'TLS/decision_tree_model.pkl',
    
    # DNS models
    ('dns', 'random_forest'): 'DNS/random_forest_model.pkl',
    # Note: DNS dnn model not available (no dnn_model.keras file found)
    # ('dns', 'dnn'): 'DNS/dnn_model.keras',  # File does not exist
    ('dns', 'knn'): 'DNS/knn_model.pkl',
    ('dns', 'xgboost'): 'DNS/xgb_model.pkl',
    ('dns', 'extra_trees'): 'DNS/extra_trees_model.pkl',
    ('dns', 'decision_tree'): 'DNS/decision_tree_model.pkl',
    
    # Doorbell models
    ('doorbell', 'random_forest'): 'Doorbell/random_forest_model.pkl',
    ('doorbell', 'dnn'): 'Doorbell/dnn_model.keras',
    ('doorbell', 'knn'): 'Doorbell/knn_model.pkl',
    ('doorbell', 'xgboost'): 'Doorbell/xgb_model.pkl',
    ('doorbell', 'extra_trees'): 'Doorbell/extra_trees_model.pkl',
    ('doorbell', 'decision_tree'): 'Doorbell/decision_tree_model.pkl',
    ('doorbell', 'logistic_regression'): 'Doorbell/logistic_regression_model.pkl',
    
    # MQTT/CoAP/RTSP models
    ('mqtt_coap_rtsp', 'random_forest'): 'MQTT_COAP_RTSP/random_forest_model.pkl',
    ('mqtt_coap_rtsp', 'dnn'): 'MQTT_COAP_RTSP/dnn_model.keras',
    ('mqtt_coap_rtsp', 'knn'): 'MQTT_COAP_RTSP/knn_model.pkl',
    ('mqtt_coap_rtsp', 'xgboost'): 'MQTT_COAP_RTSP/xgb_model.pkl',
    ('mqtt_coap_rtsp', 'extra_trees'): 'MQTT_COAP_RTSP/extra_trees_model.pkl',
    ('mqtt_coap_rtsp', 'decision_tree'): 'MQTT_COAP_RTSP/decision_tree_model.pkl',
    ('mqtt_coap_rtsp', 'logistic_regression'): 'MQTT_COAP_RTSP/logistic_regression_model.pkl',
    
    # GRE models (fallback)
    ('gre', 'random_forest'): 'GRE/random_forest_model.pkl',
    ('gre', 'dnn'): 'GRE/dnn_model.pkl',
    ('gre', 'knn'): 'GRE/knn_model.zip',
    ('gre', 'xgboost'): 'GRE/xgb_model.pkl',
    ('gre', 'extra_trees'): 'GRE/extra_trees_model.pkl',
    ('gre', 'decision_tree'): 'GRE/decision_tree_model.pkl',
    ('gre', 'logistic_regression'): 'GRE/logistic_regression_model.pkl',
}


def get_model_file_path(context: str, model_id: str) -> Optional[Path]:
    """
    Get the file path for a model given context and model_id.
    
    Args:
        context: Context identifier (e.g., 'tls', 'dns', 'doorbell')
        model_id: Model identifier (e.g., 'random_forest', 'dnn')
    
    Returns:
        Path to model file or None if not found
    """
    key = (context, model_id)
    relative_path = MODEL_FILE_MAPPING.get(key)
    
    if relative_path is None:
        logger.warning(f"No model file mapping for context='{context}', model_id='{model_id}'")
        return None
    
    model_path = TRAINED_MODELS_BASE / relative_path
    
    if not model_path.exists():
        logger.warning(f"Model file not found: {model_path}")
        return None
    
    return model_path


def get_model_file_name(context: str, model_id: str) -> Optional[str]:
    """
    Get the model file name (for use in model loading).
    
    Args:
        context: Context identifier
        model_id: Model identifier
    
    Returns:
        Model file name or None if not found
    """
    path = get_model_file_path(context, model_id)
    return str(path) if path else None

