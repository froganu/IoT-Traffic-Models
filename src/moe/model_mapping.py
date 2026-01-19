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
    ('tls', 'extra_trees'): 'TLS/extratrees_model.pkl',
    ('tls', 'decision_tree'): 'TLS/decision_tree_model.pkl',
    
    # DNS models
    ('dns', 'random_forest'): 'DNS/random_forest_model.pkl',
    ('dns', 'dnn'): 'DNS/ann_model.keras',
    ('dns', 'knn'): 'DNS/knnmodel.pkl',
    ('dns', 'xgboost'): 'DNS/xgboost_model.pkl',
    ('dns', 'extra_trees'): 'DNS/extratreesmodel.pkl',
    ('dns', 'decision_tree'): 'DNS/decision_tree_model.pkl',
    
    # Doorbell models
    ('doorbell', 'random_forest'): 'Doorbell/DanminiDoorbell_random_forest.pkl',
    ('doorbell', 'dnn'): 'Doorbell/DanminiDoorbell_neural_network.keras',
    ('doorbell', 'knn'): 'Doorbell/DanminiDoorbell_KNN_balanced_scaled_k3.pkl',
    ('doorbell', 'xgboost'): 'Doorbell/DanminiDoorbell_xgboost.pkl',
    ('doorbell', 'extra_trees'): 'Doorbell/DanminiDoorbell_extra_trees.pkl',
    ('doorbell', 'decision_tree'): 'Doorbell/DanminiDoorbell_decision_tree.pkl',
    ('doorbell', 'logistic_regression'): 'Doorbell/DanminiDoorbell_logistic_regression.pkl',
    
    # MQTT/CoAP/RTSP models
    ('mqtt_coap_rtsp', 'random_forest'): 'MQTT_COAP_RTSP/random_forest_model.pkl',
    ('mqtt_coap_rtsp', 'dnn'): 'MQTT_COAP_RTSP/central_dnn_model.keras',
    ('mqtt_coap_rtsp', 'knn'): 'MQTT_COAP_RTSP/knn_model.pkl',
    ('mqtt_coap_rtsp', 'xgboost'): 'MQTT_COAP_RTSP/xgboost_model.pkl',
    ('mqtt_coap_rtsp', 'extra_trees'): 'MQTT_COAP_RTSP/extra_trees_model.pkl',
    ('mqtt_coap_rtsp', 'decision_tree'): 'MQTT_COAP_RTSP/decision_tree_model.pkl',
    ('mqtt_coap_rtsp', 'logistic_regression'): 'MQTT_COAP_RTSP/logistic_regression_model.pkl',
    
    # GRE models (fallback)
    ('gre', 'random_forest'): 'GRE/RandomForest.pkl',
    ('gre', 'dnn'): 'GRE/DNN.pkl',
    ('gre', 'knn'): 'GRE/KNN.zip',
    ('gre', 'xgboost'): 'GRE/XGBoost.pkl',
    ('gre', 'extra_trees'): 'GRE/ExtraTrees.pkl',
    ('gre', 'decision_tree'): 'GRE/DecisionTree.pkl',
    ('gre', 'logistic_regression'): 'GRE/LogisticRegression.pkl',
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

