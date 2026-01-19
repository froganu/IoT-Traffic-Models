"""
Accuracy Table Management for MoE System

Loads model performance results from CSV and selects best model per context.
"""

import pandas as pd
import re
import logging
from typing import Dict, List, Optional, Tuple
from pathlib import Path

logger = logging.getLogger(__name__)

# Context name mapping: CSV context name -> MoE context identifier
CONTEXT_MAPPING: Dict[str, str] = {
    'TLS 1.2 to TLS 1.3-enabled Malware': 'tls',
    'MQTT, COAP:v1, RTSP': 'mqtt_coap_rtsp',
    'Different mirai attacks on Danmini Doorbell Device': 'doorbell',
    'Mirai attacks to IoT devices in CICIOT lab (GRE)': 'gre',
    'DNS-Based Command & Control': 'dns',
}

# Model name mapping: CSV model name -> model file identifier
MODEL_NAME_MAPPING: Dict[str, str] = {
    'Random Forest': 'random_forest',
    'Deep Neural Network': 'dnn',
    'KNN': 'knn',
    'XGBoost': 'xgboost',
    'Extra Trees': 'extra_trees',
    'Decision Tree': 'decision_tree',
    'Logistic Regression Model': 'logistic_regression',
}


def _extract_accuracy_value(value: str) -> Optional[float]:
    """
    Extract accuracy value from various formats in CSV.
    
    Handles formats like:
    - "100 %" -> 1.0
    - "0.97% accuracy" -> 0.0097
    - "96.69" -> 0.9669 (assumes percentage)
    - "0.999208 accuracy" -> 0.999208
    - "99.89% Without balancing..." -> 0.9989 (extract first percentage)
    
    Args:
        value: String value from CSV
    
    Returns:
        Accuracy as float (0.0-1.0) or None if cannot parse
    """
    if pd.isna(value) or not isinstance(value, str):
        return None
    
    # Remove whitespace
    value = value.strip()
    
    if not value or value == '':
        return None
    
    # Try to extract percentage or decimal
    # Pattern 1: "X.XX%" or "XX%" (percentage)
    percent_match = re.search(r'(\d+\.?\d*)\s*%', value)
    if percent_match:
        percent_val = float(percent_match.group(1))
        # Convert percentage to decimal
        return percent_val / 100.0 if percent_val > 1.0 else percent_val
    
    # Pattern 2: "X.XXXX accuracy" or just "X.XXXX" (decimal)
    decimal_match = re.search(r'(\d+\.\d+)', value)
    if decimal_match:
        decimal_val = float(decimal_match.group(1))
        # If > 1, assume it's a percentage
        if decimal_val > 1.0:
            return decimal_val / 100.0
        return decimal_val
    
    # Pattern 3: Integer that might be percentage
    int_match = re.search(r'^(\d+)$', value)
    if int_match:
        int_val = float(int_match.group(1))
        # If > 1, assume percentage
        if int_val > 1.0:
            return int_val / 100.0
        return int_val
    
    return None


def _parse_results_csv(csv_path: Path) -> pd.DataFrame:
    """
    Parse the results CSV file into a structured DataFrame.
    
    Args:
        csv_path: Path to Results CSV file
    
    Returns:
        DataFrame with columns: context, model, accuracy, raw_value, notes
    """
    try:
        # Read CSV (may have multi-line cells)
        df = pd.read_csv(csv_path, header=0, keep_default_na=False)
        
        # Get context names from header (skip first column "Model/Context")
        context_names = df.columns[1:].tolist()
        
        # Build structured data
        results = []
        
        for _, row in df.iterrows():
            model_name = row.iloc[0]  # First column is model name
            
            # Skip if model name is empty
            if not model_name or pd.isna(model_name):
                continue
            
            # Process each context
            for context_name in context_names:
                raw_value = row[context_name]
                
                # Extract accuracy
                accuracy = _extract_accuracy_value(str(raw_value))
                
                # Map context and model names
                moe_context = CONTEXT_MAPPING.get(context_name, context_name.lower().replace(' ', '_'))
                model_id = MODEL_NAME_MAPPING.get(model_name, model_name.lower().replace(' ', '_'))
                
                results.append({
                    'context': moe_context,
                    'model': model_id,
                    'model_name': model_name,  # Keep original name
                    'accuracy': accuracy,
                    'raw_value': raw_value,
                    'notes': None
                })
        
        return pd.DataFrame(results)
    
    except Exception as e:
        logger.error(f"Error parsing results CSV: {e}", exc_info=True)
        return pd.DataFrame()


class AccuracyTable:
    """
    Manages accuracy metrics for all contexts and models.
    
    Loads results from CSV and provides best model selection per context.
    """
    
    def __init__(self, results_csv_path: Optional[str] = None):
        """
        Initialize accuracy table from results CSV.
        
        Args:
            results_csv_path: Path to Results CSV file. If None, uses default location.
        """
        if results_csv_path is None:
            # Default location: src/trained_models/Results - Sheet1.csv
            results_csv_path = Path(__file__).parent.parent / 'trained_models' / 'Results - Sheet1.csv'
        
        self.results_csv_path = Path(results_csv_path)
        self.table = self.load_table()
        
        # Cache for best model per context
        self._best_model_cache: Dict[str, Tuple[str, float]] = {}
    
    def load_table(self) -> pd.DataFrame:
        """
        Load accuracy table from results CSV file.
        
        Returns:
            DataFrame with parsed results
        """
        if not self.results_csv_path.exists():
            logger.warning(f"Results CSV not found: {self.results_csv_path}")
            return pd.DataFrame(columns=['context', 'model', 'model_name', 'accuracy', 'raw_value', 'notes'])
        
        logger.info(f"Loading accuracy table from {self.results_csv_path}")
        table = _parse_results_csv(self.results_csv_path)
        
        if len(table) > 0:
            logger.info(f"Loaded {len(table)} model-context combinations")
        else:
            logger.warning("No results parsed from CSV")
        
        return table
    
    def get_best_model(self, context: str, metric: str = 'accuracy') -> Optional[Tuple[str, float]]:
        """
        Get the best model for a given context.
        
        Args:
            context: Context identifier (e.g., 'tls', 'dns', 'doorbell')
            metric: Metric to use for ranking (default: 'accuracy')
        
        Returns:
            Tuple of (model_id, accuracy) or None if no models found
        """
        # Check cache first
        cache_key = f"{context}_{metric}"
        if cache_key in self._best_model_cache:
            return self._best_model_cache[cache_key]
        
        # Filter by context
        context_data = self.table[self.table['context'] == context].copy()
        
        if len(context_data) == 0:
            logger.debug(f"No models found for context: {context}")
            return None
        
        # Filter out rows with no accuracy value
        context_data = context_data[context_data['accuracy'].notna()].copy()
        
        if len(context_data) == 0:
            logger.debug(f"No models with accuracy values for context: {context}")
            return None
        
        # Sort by metric (descending)
        context_data = context_data.sort_values(by=metric, ascending=False, na_position='last')
        
        # Get best model
        best_row = context_data.iloc[0]
        model_id = best_row['model']
        accuracy = float(best_row['accuracy'])
        
        result = (model_id, accuracy)
        
        # Cache result
        self._best_model_cache[cache_key] = result
        
        logger.debug(f"Best model for context '{context}': {model_id} (accuracy: {accuracy:.4f})")
        
        return result
    
    def get_best_models(self, context: str, n: int = 2, metric: str = 'accuracy') -> pd.DataFrame:
        """
        Get best N models for a given context.
        
        Args:
            context: Context identifier
            n: Number of models to return
            metric: Metric to use for ranking
        
        Returns:
            DataFrame with top N models
        """
        context_data = self.table[self.table['context'] == context].copy()
        
        if len(context_data) == 0:
            return pd.DataFrame()
        
        # Filter out rows with no accuracy value
        context_data = context_data[context_data['accuracy'].notna()].copy()
        
        if len(context_data) == 0:
            return pd.DataFrame()
        
        # Sort by metric (descending)
        context_data = context_data.sort_values(by=metric, ascending=False, na_position='last')
        
        return context_data.head(n)
    
    def get_model_accuracy(self, context: str, model: str) -> Optional[float]:
        """
        Get accuracy for a specific model in a context.
        
        Args:
            context: Context identifier
            model: Model identifier
        
        Returns:
            Accuracy value or None if not found
        """
        result = self.table[
            (self.table['context'] == context) & 
            (self.table['model'] == model)
        ]
        
        if len(result) == 0:
            return None
        
        accuracy = result.iloc[0]['accuracy']
        return float(accuracy) if pd.notna(accuracy) else None
    
    def print_summary(self):
        """Print summary of accuracy table."""
        print("=" * 80)
        print("ACCURACY TABLE SUMMARY")
        print("=" * 80)
        
        contexts = self.table['context'].unique()
        
        for context in sorted(contexts):
            print(f"\n{context.upper()}:")
            print("-" * 80)
            context_data = self.table[self.table['context'] == context].copy()
            
            # Filter out rows with no accuracy
            context_data = context_data[context_data['accuracy'].notna()].copy()
            
            if len(context_data) == 0:
                print("  No accuracy data available")
                continue
            
            # Sort by accuracy (descending)
            context_data = context_data.sort_values(by='accuracy', ascending=False, na_position='last')
            
            for _, row in context_data.iterrows():
                accuracy = row['accuracy']
                model_name = row.get('model_name', row['model'])
                print(f"  {model_name:30s} | Accuracy: {accuracy:.4f} ({accuracy*100:.2f}%)")
            
            # Show best model
            best = self.get_best_model(context)
            if best:
                model_id, acc = best
                print(f"\n  → Best Model: {model_id} (Accuracy: {acc:.4f} = {acc*100:.2f}%)")


if __name__ == "__main__":
    # Example usage
    import logging
    logging.basicConfig(level=logging.INFO)
    
    acc_table = AccuracyTable()
    acc_table.print_summary()
    
    # Test getting best models
    print("\n" + "=" * 80)
    print("BEST MODEL SELECTION")
    print("=" * 80)
    
    for context in ['tls', 'dns', 'doorbell', 'mqtt_coap_rtsp']:
        best = acc_table.get_best_model(context)
        if best:
            model_id, accuracy = best
            print(f"{context:20s} → {model_id:20s} (accuracy: {accuracy:.4f})")
        else:
            print(f"{context:20s} → No models found")
