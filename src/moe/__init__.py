"""
MoE (Mixture of Experts) System for C2 Traffic Detection

Core MoE integration and accuracy tracking modules.
"""

from .integration import (
    detect_c2,
    check_encryption,
    select_context,  # Phase 2: Context selection
    select_ai_model,  # Phase 3: Model selection
    load_model,
    predict_c2,
    extract_packet_features
)
from .accuracy_table import AccuracyTable

__version__ = "0.1.0"
__all__ = [
    'detect_c2',
    'check_encryption',
    'select_context',  # Phase 2
    'select_ai_model',  # Phase 3
    'load_model',
    'predict_c2',
    'extract_packet_features',
    'AccuracyTable',
]

