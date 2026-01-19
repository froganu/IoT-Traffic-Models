#!/usr/bin/env python3
"""
Create MQTT/CoAP/RTSP Preprocessing Components

Run this script AFTER your data loading code creates full_df.

This will create the LabelEncoders and StandardScaler needed for
MQTT/CoAP/RTSP feature extraction during inference.
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
    Main function to create preprocessing components.
    
    STEP 1: Run your data loading code first (creates full_df)
    STEP 2: Then run this script
    """
    print("="*70)
    print("CREATE MQTT/CoAP/RTSP PREPROCESSING COMPONENTS")
    print("="*70)
    
    print("\n📋 PREREQUISITES:")
    print("   1. You must have run your data loading code")
    print("   2. full_df must exist (your concatenated DataFrame)")
    print("   3. full_df should have 16 feature columns + label")
    
    print("\n" + "="*70)
    print("OPTION 1: Run this script interactively")
    print("="*70)
    print("\nAfter your data loading code, in the same Python session:")
    print("```python")
    print("# Your data loading code...")
    print("full_df = pd.concat(df_list, ignore_index=True)")
    print("")
    print("# Then run:")
    print("exec(open('scripts/create_mqtt_coap_rtsp_preprocessing.py').read())")
    print("```")
    
    print("\n" + "="*70)
    print("OPTION 2: Add to your data loading script")
    print("="*70)
    print("\nAdd this at the end of your data loading script:")
    print("```python")
    print("# ... your data loading code ...")
    print("full_df = pd.concat(df_list, ignore_index=True)")
    print("")
    print("# Create preprocessing components")
    print("from src.moe.mqtt_coap_rtsp_preprocessing import create_preprocessing_components")
    print("from pathlib import Path")
    print("")
    print("preproc = create_preprocessing_components(")
    print("    full_df,")
    print("    output_dir=Path('src/trained_models/MQTT_COAP_RTSP')")
    print(")")
    print("")
    print("print('✅ Preprocessing components created!')")
    print("print(f'   - LabelEncoders: {preproc[\"encoders_path\"]}')")
    print("print(f'   - StandardScaler: {preproc[\"scaler_path\"]}')")
    print("```")
    
    print("\n" + "="*70)
    print("OPTION 3: Run directly (if full_df is in scope)")
    print("="*70)
    
    # Try to get full_df from global scope
    try:
        import __main__
        if hasattr(__main__, 'full_df'):
            full_df = __main__.full_df
            logger.info(f"Found full_df with {len(full_df)} rows")
            
            # Create preprocessing components
            output_dir = project_root / 'src' / 'trained_models' / 'MQTT_COAP_RTSP'
            
            print(f"\n📊 Processing {len(full_df)} samples...")
            print(f"📁 Output directory: {output_dir}")
            
            preproc = create_preprocessing_components(full_df, output_dir=output_dir)
            
            print("\n" + "="*70)
            print("✅ SUCCESS!")
            print("="*70)
            print(f"\n✅ Created preprocessing components:")
            print(f"   - LabelEncoders: {preproc['encoders_path']}")
            print(f"   - StandardScaler: {preproc['scaler_path']}")
            print(f"\n✅ MQTT/CoAP/RTSP feature extraction is now ready!")
            print(f"   Phase 3 will automatically use these components.")
            
        else:
            print("\n❌ full_df not found in global scope.")
            print("\nPlease use Option 1 or Option 2 above.")
            
    except Exception as e:
        logger.error(f"Error: {e}", exc_info=True)
        print("\nPlease use Option 1 or Option 2 above.")


if __name__ == "__main__":
    main()

