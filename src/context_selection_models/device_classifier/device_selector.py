"""
Device Selector for Context Selection

Uses trained Random Forest classifier with pymfe meta-features to identify
device type (Doorbell vs Other) from network traffic patterns.
"""

import logging
from typing import Optional, Tuple, Dict, Any
import pandas as pd
import numpy as np
from pathlib import Path
import warnings

# Set up logger
logger = logging.getLogger(__name__)

# Suppress warnings for cleaner output
warnings.filterwarnings('ignore')

# Model caching (singleton pattern)
_DEVICE_SELECTOR_CACHE: Optional[Tuple[Any, Any]] = None


def load_device_selector(use_cache: bool = True) -> Tuple[Any, Any]:
    """
    Load the trained device selector models.
    
    Uses caching to avoid reloading models on every call (performance optimization).
    
    Args:
        use_cache: If True, use cached models if available
    
    Returns:
        Tuple of (scaler, classifier) objects
    
    Raises:
        FileNotFoundError: If model files don't exist
        ImportError: If required libraries (sklearn, pymfe) not available
    """
    global _DEVICE_SELECTOR_CACHE
    
    # Return cached models if available
    if use_cache and _DEVICE_SELECTOR_CACHE is not None:
        logger.debug("Using cached device selector models")
        return _DEVICE_SELECTOR_CACHE
    
    try:
        import joblib
    except ImportError:
        raise ImportError("joblib is required to load device selector models. Install with: pip install joblib")
    
    # Get path to model files (in same directory as this file)
    model_dir = Path(__file__).parent
    scaler_path = model_dir / 'device_selector_scaler_pymfe.pkl'
    classifier_path = model_dir / 'device_selector_classifier_pymfe.pkl'
    
    if not scaler_path.exists():
        raise FileNotFoundError(f"Scaler model not found: {scaler_path}")
    if not classifier_path.exists():
        raise FileNotFoundError(f"Classifier model not found: {classifier_path}")
    
    logger.info(f"Loading device selector models from {model_dir}")
    scaler = joblib.load(scaler_path)
    classifier = joblib.load(classifier_path)
    
    # Cache models for future use
    if use_cache:
        _DEVICE_SELECTOR_CACHE = (scaler, classifier)
        logger.debug("Device selector models cached")
    
    return scaler, classifier


def extract_metafeatures(df: pd.DataFrame) -> Dict[str, float]:
    """
    Extract meta-features from packet DataFrame using pymfe.
    
    Args:
        df: DataFrame with packet-level features (one row per packet)
    
    Returns:
        Dictionary of meta-feature names to values
    
    Raises:
        ImportError: If pymfe not available
    """
    try:
        from pymfe.mfe import MFE
    except ImportError:
        raise ImportError("pymfe is required for meta-feature extraction. Install with: pip install pymfe")
    
    # Validate input
    if df.empty:
        logger.warning("Empty DataFrame provided to extract_metafeatures")
        return {
            'nr_attr': 0,
            'nr_inst': 0,
            'mean': 0.0
        }
    
    if df.shape[0] < 10:
        logger.debug(f"Small dataset ({df.shape[0]} rows), using minimal features")
        # Return minimal features for very small datasets
        # Only compute mean on numeric columns
        numeric_cols = df.select_dtypes(include=[np.number]).columns
        mean_val = df[numeric_cols].mean().mean() if len(numeric_cols) > 0 else 0.0
        return {
            'nr_attr': df.shape[1],
            'nr_inst': len(df),
            'mean': mean_val
        }
    
    try:
        # Initialize pymfe with same config as training
        mfe = MFE(
            groups=["general", "statistical"],
            summary=["mean", "sd"],
            suppress_warnings=True
        )
        
        # Fit on the data (unsupervised)
        mfe.fit(df.values, None)
        
        # Extract features
        feature_names, feature_values = mfe.extract()
        
        # Convert to dict and handle inf/nan
        meta = dict(zip(feature_names, feature_values))
        
        # Clean infinite and NaN values
        for key in meta:
            if not np.isfinite(meta[key]):
                meta[key] = 0.0
        
        return meta
    
    except Exception as e:
        logger.warning(f"Meta-feature extraction failed: {e}. Using minimal features.", exc_info=True)
        # Fallback to minimal features on error
        # Only compute mean on numeric columns
        numeric_cols = df.select_dtypes(include=[np.number]).columns if not df.empty else []
        mean_val = df[numeric_cols].mean().mean() if len(numeric_cols) > 0 else 0.0
        return {
            'nr_attr': df.shape[1] if not df.empty else 0,
            'nr_inst': len(df),
            'mean': mean_val
        }


def select_device_context(packet_data: pd.DataFrame,
                         scaler: Optional[Any] = None,
                         classifier: Optional[Any] = None) -> Tuple[str, float]:
    """
    Select device context from packet data using trained device selector.
    
    Args:
        packet_data: DataFrame with packet-level features (one row per packet)
        scaler: Optional pre-loaded scaler (if None, loads from file)
        classifier: Optional pre-loaded classifier (if None, loads from file)
    
    Returns:
        Tuple of (device_type: str, confidence: float)
        device_type: 'Doorbell' or 'Other'
        confidence: Probability of prediction (0.0-1.0)
    
    Raises:
        ImportError: If required libraries not available
        FileNotFoundError: If model files not found
        ValueError: If packet_data is invalid
    """
    if packet_data.empty:
        raise ValueError("packet_data cannot be empty")
    
    # Load models if not provided
    if scaler is None or classifier is None:
        scaler, classifier = load_device_selector()
    
    # Extract meta-features
    meta_features = extract_metafeatures(packet_data)
    
    # Convert to array (ensure same order as training)
    # Get feature names from scaler if available, otherwise use dict keys
    if hasattr(scaler, 'feature_names_in_') and scaler.feature_names_in_ is not None:
        feature_names = list(scaler.feature_names_in_)
    elif hasattr(scaler, 'n_features_in_') and scaler.n_features_in_ is not None:
        # If we know the expected number of features but not the names
        # This shouldn't happen, but handle it gracefully
        logger.warning("Scaler has n_features_in_ but not feature_names_in_. Using meta_features keys.")
        feature_names = list(meta_features.keys())
        # Pad to expected size if needed
        expected_size = scaler.n_features_in_
        if len(feature_names) < expected_size:
            # Add placeholder names for missing features
            feature_names.extend([f'unknown_feature_{i}' for i in range(len(feature_names), expected_size)])
    else:
        # Fallback: use keys from meta_features
        feature_names = list(meta_features.keys())
    
    # Create feature vector in correct order
    feature_values = [meta_features.get(name, 0.0) for name in feature_names]
    
    # Handle case where we have fewer features than expected
    # (e.g., if pymfe extraction failed and returned minimal features)
    expected_size = len(feature_names)
    if hasattr(scaler, 'n_features_in_') and scaler.n_features_in_ is not None:
        expected_size = scaler.n_features_in_
    
    if len(feature_values) < expected_size:
        # Pad with zeros
        feature_values.extend([0.0] * (expected_size - len(feature_values)))
        logger.debug(f"Padded feature vector from {len(feature_values) - (expected_size - len(feature_values))} to {expected_size} features")
    elif len(feature_values) > expected_size:
        # Truncate (shouldn't happen, but be safe)
        feature_values = feature_values[:expected_size]
        logger.warning(f"Truncated feature vector from {len(feature_values)} to {expected_size} features")
    
    # Normalize features
    X_scaled = scaler.transform([feature_values])
    
    # Predict
    prediction = classifier.predict(X_scaled)[0]
    probabilities = classifier.predict_proba(X_scaled)[0]
    confidence = float(probabilities.max())
    
    return str(prediction), confidence


def select_device_context_safe(packet_data: pd.DataFrame) -> Tuple[Optional[str], Optional[float]]:
    """
    Safe wrapper for select_device_context that handles errors gracefully.
    
    Args:
        packet_data: DataFrame with packet-level features
    
    Returns:
        Tuple of (device_type: Optional[str], confidence: Optional[float])
        Returns (None, None) on error
    
    This function never raises exceptions, making it safe for use in production
    pipelines where classifier failures should not break the system.
    """
    # Input validation
    if not isinstance(packet_data, pd.DataFrame):
        logger.warning(f"Invalid input type: {type(packet_data)}, expected DataFrame")
        return None, None
    
    if packet_data.empty:
        logger.debug("Empty DataFrame provided to device selector")
        return None, None
    
    try:
        device_type, confidence = select_device_context(packet_data)
        logger.debug(f"Device selector result: {device_type} (confidence: {confidence:.2f})")
        return device_type, confidence
    except ImportError as e:
        logger.debug(f"Device selector dependencies not available: {e}")
        return None, None
    except FileNotFoundError as e:
        logger.warning(f"Device selector model files not found: {e}")
        return None, None
    except Exception as e:
        logger.warning(f"Device selector failed: {e}. Returning None.", exc_info=True)
        return None, None

