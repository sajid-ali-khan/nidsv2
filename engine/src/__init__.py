import pandas as pd
import joblib
import os
from pyflowmeter.sniffer import create_sniffer

# --- Configuration: Define paths for assets and input file ---
MODEL_PATH = 'random_forest_model.pkl'
COLUMNS_PATH = 'model_columns.joblib'
PCAP_TO_ANALYZE = 'sample.pcap' # <-- Point this to your new .pcap file

def create_feature_mapping():
    """Creates a dictionary to map pyflowmeter column names to the model's expected names."""
    return {
        'dst_port': 'Destination Port', 'duration': 'Flow Duration',
        'fwd_pkts_tot': 'Total Fwd Packets', 'fwd_bytes_tot': 'Total Length of Fwd Packets',
        'fwd_pkt_len_max': 'Fwd Packet Length Max', 'fwd_pkt_len_min': 'Fwd Packet Length Min',
        'fwd_pkt_len_mean': 'Fwd Packet Length Mean', 'fwd_pkt_len_std': 'Fwd Packet Length Std',
        'bwd_pkt_len_max': 'Bwd Packet Length Max', 'bwd_pkt_len_min': 'Bwd Packet Length Min',
        'bwd_pkt_len_mean': 'Bwd Packet Length Mean', 'bwd_pkt_len_std': 'Bwd Packet Length Std',
        'flow_b_s': 'Flow Bytes/s', 'flow_pkt_s': 'Flow Packets/s',
        'flow_iat_mean': 'Flow IAT Mean', 'flow_iat_std': 'Flow IAT Std',
        'flow_iat_max': 'Flow IAT Max', 'flow_iat_min': 'Flow IAT Min',
        'fwd_iat_tot': 'Fwd IAT Total', 'fwd_iat_mean': 'Fwd IAT Mean',
        'fwd_iat_std': 'Fwd IAT Std', 'fwd_iat_max': 'Fwd IAT Max',
        'fwd_iat_min': 'Fwd IAT Min', 'bwd_iat_tot': 'Bwd IAT Total',
        'bwd_iat_mean': 'Bwd IAT Mean', 'bwd_iat_std': 'Bwd IAT Std',
        'bwd_iat_max': 'Bwd IAT Max', 'bwd_iat_min': 'Bwd IAT Min',
        'fwd_hdr_len': 'Fwd Header Length', 'bwd_hdr_len': 'Bwd Header Length',
        'fwd_pkt_s': 'Fwd Packets/s', 'bwd_pkt_s': 'Bwd Packets/s',
        'pkt_len_min': 'Min Packet Length', 'pkt_len_max': 'Max Packet Length',
        'pkt_len_mean': 'Packet Length Mean', 'pkt_len_std': 'Packet Length Std',
        'pkt_len_var': 'Packet Length Variance', 'fin_cnt': 'FIN Flag Count',
        'psh_cnt': 'PSH Flag Count', 'ack_cnt': 'ACK Flag Count',
        'pkt_size_avg': 'Average Packet Size', 'fwd_subflow_bytes': 'Subflow Fwd Bytes',
        'fwd_win_init': 'Init_Win_bytes_forward', 'bwd_win_init': 'Init_Win_bytes_backward',
        'fwd_data_pkts_tot': 'act_data_pkt_fwd', 'fwd_seg_size_min': 'min_seg_size_forward',
        'active_mean': 'Active Mean', 'active_max': 'Active Max', 'active_min': 'Active Min',
        'idle_mean': 'Idle Mean', 'idle_max': 'Idle Max', 'idle_min': 'Idle Min',
    }

def predict_from_pcap(pcap_file):
    """Analyzes a pcap file, translates features, and makes a prediction."""

    # 1. Load the trained model and the required column list
    try:
        model = joblib.load(MODEL_PATH)
        model_columns = joblib.load(COLUMNS_PATH)
    except FileNotFoundError:
        print(f"❌ Error: Model or column file not found. Run the training script first.")
        return

    # 2. Generate features from the new pcap file
    output_csv = 'temp_flow_features.csv'
    if os.path.exists(output_csv):
        os.remove(output_csv)

    sniffer = create_sniffer(input_file=pcap_file, to_csv=True, output_file=output_csv)
    sniffer.start()
    sniffer.join()

    if not os.path.exists(output_csv):
        print("❌ Error: pyflowmeter did not generate a feature file.")
        return

    df_new_raw = pd.read_csv(output_csv)
    os.remove(output_csv)

    # 3. Translate the pyflowmeter output to match the model's training data
    df_translated = df_new_raw.copy()
    time_cols = [col for col in df_translated.columns if 'iat' in col or 'duration' in col or 'active' in col or 'idle' in col]
    for col in time_cols:
        df_translated[col] = df_translated[col] * 1_000_000

    mapping = create_feature_mapping()
    df_translated.rename(columns=mapping, inplace=True)

    # 4. Align the translated data with the model's required columns
    missing_cols = set(model_columns) - set(df_translated.columns)
    for c in missing_cols:
        df_translated[c] = 0
    df_aligned = df_translated[model_columns]

    # 5. Make predictions
    predictions = model.predict(df_aligned)
    df_new_raw['Predicted_Label'] = predictions

    # 6. Display results
    print("\n--- Prediction Results ---")
    print(df_new_raw[['src_ip', 'dst_ip', 'dst_port', 'protocol', 'Predicted_Label']])
    print("------------------------\n")

if __name__ == '__main__':
    if os.path.exists(PCAP_TO_ANALYZE):
        predict_from_pcap(PCAP_TO_ANALYZE)
    else:
        print(f"Input file not found: {PCAP_TO_ANALYZE}")

