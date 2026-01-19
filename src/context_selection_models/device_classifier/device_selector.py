"""
Device Selector for Context Selection

Uses trained Random Forest classifier with pymfe meta-features to identify
device type (Doorbell vs Other) from network traffic patterns.
"""

from typing import Optional, Tuple, Dict, Any
import pandas as pd
import numpy as np
from pathlib import Path
import warnings

# Suppress warnings for cleaner output
warnings.filterwarnings('ignore')


def load_device_selector() -> Tuple[Any, Any]:
    """
    Load the trained device selector models.
    
    Returns:
        Tuple of (scaler, classifier) objects
        Returns (None, None) if models cannot be loaded
    
    Raises:
        FileNotFoundError: If model files don't exist
        ImportError: If required libraries (sklearn, pymfe) not available
    """
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
    
    scaler = joblib.load(scaler_path)
    classifier = joblib.load(classifier_path)
    
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
    
    if df.empty or df.shape[0] < 10:
        # Return minimal features for very small datasets
        return {
            'nr_attr': df.shape[1] if not df.empty else 0,
            'nr_inst': len(df),
            'mean': df.mean().mean() if not df.empty and df.shape[1] > 0 else 0.0
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
        # Fallback to minimal features on error
        return {
            'nr_attr': df.shape[1] if not df.empty else 0,
            'nr_inst': len(df),
            'mean': df.mean().mean() if not df.empty and df.shape[1] > 0 else 0.0
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
        feature_names = scaler.feature_names_in_
    else:
        # Fallback: use keys from meta_features
        feature_names = list(meta_features.keys())
    
    # Create feature vector in correct order
    feature_values = [meta_features.get(name, 0.0) for name in feature_names]
    
    # Handle case where we have fewer features than expected
    # (e.g., if pymfe extraction failed and returned minimal features)
    if len(feature_values) != len(feature_names):
        # Pad with zeros or truncate
        if len(feature_values) < len(feature_names):
            feature_values.extend([0.0] * (len(feature_names) - len(feature_values)))
        else:
            feature_values = feature_values[:len(feature_names)]
    
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
    """
    try:
        return select_device_context(packet_data)
    except Exception as e:
        # Log error but don't raise
        import warnings
        warnings.warn(f"Device selector failed: {e}. Returning None.", RuntimeWarning)
        return None, None

