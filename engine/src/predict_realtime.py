"""
NIDS Engine - Real-time Network Traffic Analysis

Captures live network packets using Scapy, aggregates them into flows using 5-tuple keys,
extracts features via pyflowmeter, and classifies traffic using a pre-trained Random Forest model.
Uses producer-consumer threading pattern for non-blocking packet capture and ML inference.

"""

import pandas as pd
import joblib
import os
import time
import platform
import threading
import queue
from scapy.all import sniff, wrpcap
from scapy.layers.inet import IP, TCP, UDP
from pyflowmeter.sniffer import create_sniffer

MODEL_PATH = '/home/sajid/Desktop/nids/engine/src/random_forest_model.pkl'
COLUMNS_PATH = '/home/sajid/Desktop/nids/engine/src/model_columns.joblib'
default_interface = 'wlp3s0' if platform.system() == 'Linux' else 'en0' if platform.system() == 'Darwin' else 'Ethernet'
NETWORK_INTERFACE = os.getenv("NETWORK_INTERFACE", default_interface)
FLOW_TIMEOUT_SECONDS = 15
FLOW_MAX_LIFE_SECONDS = 120

analysis_queue = queue.Queue()
active_flows = {}
flows_lock = threading.Lock()


def create_feature_mapping():
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


def analysis_worker(model, model_columns):
    while True:
        flow_to_process = analysis_queue.get()
        flow_key, packets = flow_to_process['key'], flow_to_process['packets']

        temp_dir = f"temp_{threading.get_ident()}"
        os.makedirs(temp_dir, exist_ok=True)
        temp_pcap = os.path.join(temp_dir, "flow.pcap")
        output_csv = os.path.join(temp_dir, "features.csv")

        try:
            wrpcap(temp_pcap, packets)
            sniffer = create_sniffer(input_file=temp_pcap, to_csv=True, output_file=output_csv)
            sniffer.start()
            sniffer.join()

            if not os.path.exists(output_csv) or os.path.getsize(output_csv) == 0:
                continue

            df_new_raw = pd.read_csv(output_csv)
            df_translated = df_new_raw.copy()
            time_cols = [c for c in df_translated.columns if
                         'iat' in c or 'duration' in c or 'active' in c or 'idle' in c]
            for col in time_cols:
                df_translated[col] = df_translated[col] * 1_000_000

            mapping = create_feature_mapping()
            df_translated.rename(columns=mapping, inplace=True)

            missing_cols = set(model_columns) - set(df_translated.columns)
            for c in missing_cols:
                df_translated[c] = 0
            df_aligned = df_translated[model_columns]

            predictions = model.predict(df_aligned)


            df_new_raw['Predicted_Label'] = predictions

            print(f"\n--- Prediction for Flow {flow_key} ---")
            print(df_new_raw[['src_ip', 'dst_ip', 'dst_port', 'protocol', 'Predicted_Label']].iloc[0])
            print("------------------------------------------\n")

        finally:
            if os.path.exists(temp_pcap): os.remove(temp_pcap)
            if os.path.exists(output_csv): os.remove(output_csv)
            if os.path.exists(temp_dir): os.rmdir(temp_dir)
            analysis_queue.task_done()


# def get_flow_key(packet):
#     """Generates a standardized key for a packet's flow."""
#     if IP in packet and (TCP in packet or UDP in packet):
#         proto = 'TCP' if TCP in packet else 'UDP'
#         src_ip, dst_ip = sorted((packet[IP].src, packet[IP].dst))
#         src_port, dst_port = sorted((packet[proto].sport, packet[proto].dport))
#         return src_ip, src_port, dst_ip, dst_port, proto
#     return None
def get_flow_key(packet):
    if IP in packet and (TCP in packet or UDP in packet):
        try:

            protocol = 'TCP' if TCP in packet else 'UDP'
            proto_layer = packet[protocol]
            print(proto_layer.sport, proto_layer.dport)
            print(type(proto_layer.sport), type(proto_layer.dport))
            sport = int(proto_layer.sport)
            dport = int(proto_layer.dport)

            ip1, ip2 = sorted((packet[IP].src, packet[IP].dst))
            port1, port2 = sorted((sport, dport))
            return (ip1, port1, ip2, port2, protocol)
        except (TypeError, ValueError):
            print(TypeError, ValueError)
            return None
    return None

def packet_handler(packet):
    flow_key = get_flow_key(packet)
    if not flow_key:
        return

    with flows_lock:
        now = time.time()
        if flow_key not in active_flows:
            active_flows[flow_key] = {'packets': [], 'start_time': now, 'last_seen': now}

        flow = active_flows[flow_key]
        flow['packets'].append(packet)
        flow['last_seen'] = now

        
        if TCP in packet:
            tcp_flags = packet[TCP].flags
            
            if 'F' in tcp_flags or 'R' in tcp_flags:
                
                if flow_key in active_flows:
                    flow_data = active_flows.pop(flow_key)
                    analysis_queue.put({'key': flow_key, 'packets': flow_data['packets']})
                    print(f"Flow {flow_key} ended (FIN/RST). Moved to analysis queue.")


def check_flow_timeouts():
    while True:
        time.sleep(FLOW_TIMEOUT_SECONDS)
        now = time.time()
        with flows_lock:
            
            for key in list(active_flows.keys()):
                flow = active_flows[key]

                
                is_timed_out = (now - flow['last_seen']) > FLOW_TIMEOUT_SECONDS

                


                is_max_life = (now - flow['start_time']) > FLOW_MAX_LIFE_SECONDS

                if is_timed_out or is_max_life:
                    flow_data = active_flows.pop(key)
                    analysis_queue.put({'key': key, 'packets': flow_data['packets']})

                    reason = "timed out" if is_timed_out else "exceeded max life"
                    print(f"Flow {key} {reason}. Moved to analysis queue.")


def start_event_driven_prediction():
    try:
        model = joblib.load(MODEL_PATH)
        model_columns = joblib.load(COLUMNS_PATH)
        print("Model and column list loaded successfully.")
    except FileNotFoundError:
        print(f"Error: Model or column file not found. Run the training script first.")
        return

    
    worker = threading.Thread(target=analysis_worker, args=(model, model_columns), daemon=True)
    worker.start()

    
    timeout_checker = threading.Thread(target=check_flow_timeouts, daemon=True)
    timeout_checker.start()

    print(f"starting  event driven traffic analysis on interface '{NETWORK_INTERFACE}'...")

    try:
        sniff(iface=NETWORK_INTERFACE, prn=packet_handler, store=False)
    except KeyboardInterrupt:
        print("\nstopping traffic capture.")
    except Exception as e:
        print(f"\nerror occurred: {e}")
        print("issue with administrator/root privileges.")


if __name__ == '__main__':
    start_event_driven_prediction()

