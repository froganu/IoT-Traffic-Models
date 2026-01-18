import pandas as pd
import tarfile
import os
from glob import glob
import gc
import numpy as np

# config
tar_path = "iot_23_datasets_full.tar.gz"
extract_dir = "/media/jaume/HDD/IOT23 DATASET/iot23_extracted"
output_file = "iot23_dns_features.csv"

pd.options.mode.chained_assignment = None

columns = ['ts', 'uid', 'id.orig_h', 'id.orig_p', 'id.resp_h', 'id.resp_p',
           'proto', 'service', 'duration', 'orig_bytes', 'resp_bytes',
           'conn_state', 'local_orig', 'local_resp', 'missed_bytes',
           'history', 'orig_pkts', 'orig_ip_bytes', 'resp_pkts',
           'resp_ip_bytes', 'label']

# Keep ports and service for DNS feature engineering
numeric_cols = ['duration', 'orig_bytes', 'resp_bytes', 'missed_bytes',
                'orig_pkts', 'orig_ip_bytes', 'resp_pkts', 'resp_ip_bytes',
                'id.orig_p', 'id.resp_p']

categorical_cols = ['proto', 'conn_state', 'service']

def process_single_file(file_path):
    print(f"Procesando: {os.path.basename(file_path)}")
    
    try:
        usecols = numeric_cols + categorical_cols + ['label']
        
        chunks = []
        chunksize = 100000
        
        for chunk in pd.read_csv(file_path,
                                   sep='\t',
                                   skiprows=10,
                                   names=columns,
                                   usecols=usecols,
                                   na_values=['-'],
                                   low_memory=False,
                                   chunksize=chunksize):
            
            # 1st step: filter by C&C and Benign
            label_str = chunk['label'].astype(str)
            
            cc_mask = label_str.str.contains('C&C|C%26C', case=False, na=False, regex=True)
            benign_mask = label_str.str.contains('Benign|benign', case=False, na=False, regex=True)
            
            # Exclude other attacks (DDoS, Okiru, PortScan, etc.)
            other_attacks = label_str.str.contains('DDoS|Okiru|PortScan|Mirai|Torii', 
                                                    case=False, na=False, regex=True)
            
            filtered = chunk[(cc_mask | benign_mask) & ~other_attacks]
            
            if len(filtered) > 0:
                chunks.append(filtered)
        
        if len(chunks) == 0:
            return None
            
        df = pd.concat(chunks, ignore_index=True)
        
        if len(df) > 0:
            df = df.iloc[:-1] if len(df) > 1 else df
        
        del chunks
        gc.collect()
        
        # Clean labels
        if 'label' in df.columns:
            df['label'] = df['label'].astype(str).str.replace(
                r'^\(empty\)\s+(Malicious|Benign)\s+', '', regex=True
            ).str.strip()
            df['label'] = df['label'].replace(['nan', '-', ''], 'Benign')
        
        for col in numeric_cols:
            if col in df.columns:
                df[col] = pd.to_numeric(df[col], errors='coerce').fillna(0)
                df[col] = df[col].astype('float32')

        for col in categorical_cols:
            if col in df.columns:
                df[col] = df[col].fillna('unknown').astype('category')
        
        # 2nd step: create DNS features
        # these features help to identify C&C over DNS traffic
        df['is_dns_port'] = ((df['id.orig_p'] == 53) | (df['id.resp_p'] == 53)).astype('int8')
        df['is_dns_service'] = (df['service'] == 'dns').astype('int8')
        df['dns_like_pattern'] = ((df['orig_bytes'] < 512) & 
                                   (df['resp_bytes'] < 4096) & 
                                   (df['proto'] == 'udp')).astype('int8')
        
        cc_count = df['label'].astype(str).str.contains('C&C', case=False).sum()
        benign_count = df['label'].astype(str).str.contains('Benign', case=False).sum()
        
        print(f"Completado: {os.path.basename(file_path)} - {len(df)} filas "
              f"(C&C: {cc_count}, Benign: {benign_count})")
        return df
        
    except Exception as e:
        print(f"ERROR en {file_path}: {str(e)}")
        return None

print("="*70)
print("PREPROCESAMIENTO IoT23 - C&C DETECTION CON DNS FEATURES")
print("="*70)

conn_files = sorted(glob(f"{extract_dir}/**/conn.log.labeled", recursive=True))
print(f"\nArchivos encontrados: {len(conn_files)}\n")

if len(conn_files) == 0:
    print("ERROR: No se encontraron archivos conn.log.labeled")
    exit(1)

total_rows = 0
total_cc = 0
total_benign = 0
first_columns = None

for i, file_path in enumerate(conn_files, 1):
    print(f"\n[{i}/{len(conn_files)}] ", end="")
    df = process_single_file(file_path)
    
    if df is not None and len(df) > 0:
        # Contar antes de encoding
        cc = df['label'].astype(str).str.contains('C&C', case=False).sum()
        benign = df['label'].astype(str).str.contains('Benign', case=False).sum()
        total_cc += cc
        total_benign += benign
        
        print(" Aplicando one-hot encoding...")
        df_encoded = pd.get_dummies(df, columns=categorical_cols, dtype='int8')
        
        if i == 1:
            first_columns = df_encoded.columns.tolist()
        else:
            for col in first_columns:
                if col not in df_encoded.columns:
                    df_encoded[col] = 0
            df_encoded = df_encoded[first_columns]
        
        mode = 'w' if i == 1 else 'a'
        header = i == 1
        df_encoded.to_csv(output_file, mode=mode, header=header, index=False)
        
        total_rows += len(df)
        print(f" Guardado. Total: {total_rows:,} (C&C: {total_cc:,}, Benign: {total_benign:,})")
        
        del df, df_encoded
        gc.collect()
    
    if i % 3 == 0:
        print(" [Liberando memoria...]")
        gc.collect()

print(f"\n{'='*70}")
print("Proceso completado con exito")
print(f"Filas totales: {total_rows:,}")
print(f"  - C&C Attacks: {total_cc:,} ({total_cc/total_rows*100:.2f}%)")
print(f"  - Benign: {total_benign:,} ({total_benign/total_rows*100:.2f}%)")
print(f"Archivo guardado: {output_file}")
print("="*70)
