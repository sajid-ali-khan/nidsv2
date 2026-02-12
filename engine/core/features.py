"""
Feature mapping from pyflowmeter column names to CICIDS2017 model column names.
Also handles unit conversion (seconds → microseconds) and missing column alignment.
"""

import pandas as pd


FEATURE_MAP = {
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


def translate_features(df_raw, model_columns):
    df = df_raw.copy()

    time_cols = [c for c in df.columns if 'iat' in c or 'duration' in c or 'active' in c or 'idle' in c]
    for col in time_cols:
        df[col] = df[col] * 1_000_000

    df.rename(columns=FEATURE_MAP, inplace=True)

    for c in set(model_columns) - set(df.columns):
        df[c] = 0

    return df[model_columns]
