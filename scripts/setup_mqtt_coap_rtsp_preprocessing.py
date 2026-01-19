#!/usr/bin/env python3
"""
Setup script for MQTT/CoAP/RTSP preprocessing components.

This script creates the LabelEncoders and StandardScaler needed for
MQTT/CoAP/RTSP feature extraction during inference.

Run this ONCE after loading your training data (full_df).

Usage:
    python scripts/setup_mqtt_coap_rtsp_preprocessing.py
"""

import sys
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

import pandas as pd
import logging
from src.moe.mqtt_coap_rtsp_preprocessing import create_preprocessing_components

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
logger = logging.getLogger(__name__)


def main():
    """
    Main setup function.
    
    This function should be called after you've created full_df from your
    data loading code. It will create and save the preprocessing components.
    """
    print("="*70)
    print("MQTT/CoAP/RTSP PREPROCESSING SETUP")
    print("="*70)
    
    print("\n📋 This script will:")
    print("   1. Load your training data (full_df)")
    print("   2. Create LabelEncoders for 6 categorical columns")
    print("   3. Create StandardScaler for all 16 features")
    print("   4. Save both to: src/trained_models/MQTT_COAP_RTSP/")
    
    print("\n⚠️  PREREQUISITES:")
    print("   - You need to have created 'full_df' from your data loading code")
    print("   - full_df should have the 16 feature columns + label")
    print("   - Run this script in the same environment where you created full_df")
    
    print("\n" + "="*70)
    
    # Check if full_df exists in global scope or needs to be loaded
    try:
        # Try to get full_df from user's namespace (if running interactively)
        import __main__
        if hasattr(__main__, 'full_df'):
            full_df = __main__.full_df
            logger.info("Found full_df in global scope")
        else:
            raise AttributeError("full_df not found in global scope")
    except (AttributeError, NameError):
        # If not found, ask user to provide it
        print("\n❌ full_df not found in global scope.")
        print("\n📝 OPTION 1: Run this script interactively")
        print("   After your data loading code, run:")
        print("   ```python")
        print("   from scripts.setup_mqtt_coap_rtsp_preprocessing import create_components")
        print("   create_components(full_df)")
        print("   ```")
        
        print("\n📝 OPTION 2: Modify this script to load your data")
        print("   Edit this script and add your data loading code here")
        print("   Then run: python scripts/setup_mqtt_coap_rtsp_preprocessing.py")
        
        print("\n📝 OPTION 3: Run directly in your notebook/script")
        print("   ```python")
        print("   from src.moe.mqtt_coap_rtsp_preprocessing import create_preprocessing_components")
        print("   preproc = create_preprocessing_components(full_df)")
        print("   ```")
        
        return
    
    # Create preprocessing components
    output_dir = project_root / 'src' / 'trained_models' / 'MQTT_COAP_RTSP'
    
    print(f"\n📊 Processing {len(full_df)} samples...")
    print(f"📁 Output directory: {output_dir}")
    
    try:
        preproc = create_preprocessing_components(full_df, output_dir=output_dir)
        
        print("\n" + "="*70)
        print("✅ SUCCESS!")
        print("="*70)
        print(f"\n✅ Created preprocessing components:")
        print(f"   - LabelEncoders: {preproc['encoders_path']}")
        print(f"   - StandardScaler: {preproc['scaler_path']}")
        print(f"\n✅ MQTT/CoAP/RTSP feature extraction is now ready!")
        print(f"   Phase 3 will automatically use these components.")
        
    except Exception as e:
        logger.error(f"Error creating preprocessing components: {e}", exc_info=True)
        print("\n❌ Setup failed. Please check the error above.")


def create_components(full_df: pd.DataFrame, output_dir: Path = None):
    """
    Convenience function to create preprocessing components.
    
    Call this function directly from your data loading script/notebook.
    
    Args:
        full_df: Your training DataFrame (after data loading and sampling)
        output_dir: Optional output directory (default: src/trained_models/MQTT_COAP_RTSP)
    
    Returns:
        Dictionary with preprocessing components info
    """
    if output_dir is None:
        output_dir = project_root / 'src' / 'trained_models' / 'MQTT_COAP_RTSP'
    
    logger.info(f"Creating preprocessing components from {len(full_df)} samples")
    preproc = create_preprocessing_components(full_df, output_dir=output_dir)
    
    logger.info("✅ Preprocessing components created successfully!")
    return preproc


if __name__ == "__main__":
    main()

