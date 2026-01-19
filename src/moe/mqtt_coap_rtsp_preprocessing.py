"""
MQTT/CoAP/RTSP Preprocessing Components

Creates and saves LabelEncoders and StandardScaler from training data.
These are required for feature extraction during inference.
"""

import pandas as pd
import numpy as np
from sklearn.preprocessing import LabelEncoder, StandardScaler
import joblib
import logging
from pathlib import Path
from typing import Dict, Optional

logger = logging.getLogger(__name__)

# Feature order (must match training)
FEATURE_ORDER = [
    'frame.len',
    'frame.protocols',  # categorical - needs LabelEncoder
    'ip.flags',  # categorical - needs LabelEncoder
    'ip.ttl',
    'ip.proto',
    'ip.checksum',  # categorical - needs LabelEncoder
    'tcp.srcport',
    'tcp.dstport',
    'tcp.flags',  # categorical - needs LabelEncoder
    'tcp.window_size_value',
    'tcp.window_size_scalefactor',
    'tcp.checksum',  # categorical - needs LabelEncoder
    'tcp.options',  # categorical - needs LabelEncoder
    'tcp.pdu.size',
    'udp.srcport',
    'udp.dstport',
]

# Categorical columns that need LabelEncoder
CATEGORICAL_COLUMNS = [
    'frame.protocols',
    'ip.flags',
    'ip.checksum',
    'tcp.flags',
    'tcp.checksum',
    'tcp.options',
]

# Columns to drop (identifiers, not features)
COLUMNS_TO_DROP = [
    'frame.time',
    'eth.src',
    'eth.dst',
    'ip.src',
    'ip.dst',
    'label',
    'ip.tos',  # Likely constant, drop it
]


def create_preprocessing_components(full_df: pd.DataFrame, 
                                    output_dir: Optional[Path] = None) -> Dict:
    """
    Create LabelEncoders and StandardScaler from training data.
    
    This function replicates the preprocessing pipeline from the training notebook.
    
    Args:
        full_df: DataFrame with raw features (from data loading code)
        output_dir: Directory to save encoders and scaler (default: current directory)
    
    Returns:
        Dictionary with:
        - 'label_encoders': Dict of LabelEncoder objects
        - 'scaler': StandardScaler object
        - 'feature_order': List of feature names in order
    """
    if output_dir is None:
        output_dir = Path.cwd()
    else:
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)
    
    logger.info(f"Creating preprocessing components from {len(full_df)} samples")
    
    # Step 1: Drop identifier columns
    df_features = full_df.drop(columns=[c for c in COLUMNS_TO_DROP if c in full_df.columns], errors='ignore')
    
    logger.debug(f"After dropping identifiers: {df_features.shape}")
    logger.debug(f"Columns: {df_features.columns.tolist()}")
    
    # Step 2: Ensure we have all required features
    missing_cols = set(FEATURE_ORDER) - set(df_features.columns)
    if missing_cols:
        logger.warning(f"Missing feature columns: {missing_cols}")
        # Fill missing columns with NaN (will be handled later)
        for col in missing_cols:
            df_features[col] = np.nan
    
    # Step 3: Reorder columns to match feature order
    # Add any extra columns at the end (shouldn't happen, but be safe)
    extra_cols = [c for c in df_features.columns if c not in FEATURE_ORDER]
    ordered_cols = [c for c in FEATURE_ORDER if c in df_features.columns] + extra_cols
    df_features = df_features[ordered_cols]
    
    # Step 4: Encode categorical features
    label_encoders = {}
    
    for col in CATEGORICAL_COLUMNS:
        if col not in df_features.columns:
            logger.warning(f"Categorical column '{col}' not found, skipping")
            continue
        
        logger.debug(f"Encoding categorical column: {col}")
        
        # Handle NaN values: convert to string 'nan' for encoding
        # This ensures NaN values get a consistent encoding
        col_data = df_features[col].fillna('nan').astype(str)
        
        # Fit LabelEncoder
        le = LabelEncoder()
        df_features[col] = le.fit_transform(col_data)
        label_encoders[col] = le
        
        logger.debug(f"  - Encoded {col}: {len(le.classes_)} unique values")
    
    # Step 5: Handle remaining NaN values (fill with 0)
    # This handles TCP/UDP field NaNs (TCP fields NaN for UDP, vice versa)
    df_features = df_features.fillna(0)
    
    # Step 6: Ensure only feature columns remain (drop any extras)
    df_features = df_features[FEATURE_ORDER]
    
    # Step 7: Fit StandardScaler
    logger.info("Fitting StandardScaler on all features")
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(df_features)
    
    logger.info(f"Scaler fitted on {len(FEATURE_ORDER)} features")
    logger.debug(f"  - Mean shape: {scaler.mean_.shape}")
    logger.debug(f"  - Scale shape: {scaler.scale_.shape}")
    
    # Step 8: Save components
    encoders_path = output_dir / 'mqtt_coap_rtsp_label_encoders.pkl'
    scaler_path = output_dir / 'mqtt_coap_rtsp_scaler.pkl'
    
    joblib.dump(label_encoders, encoders_path)
    joblib.dump(scaler, scaler_path)
    
    logger.info(f"✅ Saved LabelEncoders to: {encoders_path}")
    logger.info(f"✅ Saved StandardScaler to: {scaler_path}")
    
    return {
        'label_encoders': label_encoders,
        'scaler': scaler,
        'feature_order': FEATURE_ORDER,
        'encoders_path': encoders_path,
        'scaler_path': scaler_path,
    }


def load_preprocessing_components(encoders_path: Optional[Path] = None,
                                  scaler_path: Optional[Path] = None) -> Dict:
    """
    Load LabelEncoders and StandardScaler from disk.
    
    Args:
        encoders_path: Path to LabelEncoders file (default: current directory)
        scaler_path: Path to StandardScaler file (default: current directory)
    
    Returns:
        Dictionary with 'label_encoders' and 'scaler'
    """
    if encoders_path is None:
        encoders_path = Path.cwd() / 'mqtt_coap_rtsp_label_encoders.pkl'
    else:
        encoders_path = Path(encoders_path)
    
    if scaler_path is None:
        scaler_path = Path.cwd() / 'mqtt_coap_rtsp_scaler.pkl'
    else:
        scaler_path = Path(scaler_path)
    
    if not encoders_path.exists():
        raise FileNotFoundError(f"LabelEncoders file not found: {encoders_path}")
    
    if not scaler_path.exists():
        raise FileNotFoundError(f"StandardScaler file not found: {scaler_path}")
    
    label_encoders = joblib.load(encoders_path)
    scaler = joblib.load(scaler_path)
    
    logger.info(f"✅ Loaded LabelEncoders from: {encoders_path}")
    logger.info(f"✅ Loaded StandardScaler from: {scaler_path}")
    
    return {
        'label_encoders': label_encoders,
        'scaler': scaler,
        'feature_order': FEATURE_ORDER,
    }

