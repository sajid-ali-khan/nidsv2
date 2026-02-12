"""
NIDS Engine - PCAP File Analysis

Analyzes pre-captured PCAP files for offline testing and demonstration.
Processes packets into flows, extracts features, classifies using ML model,
and sends predictions to the backend API for dashboard visualization.

"""

import pandas as pd
import joblib
import os
import time
import threading
import queue
import requests
from datetime import datetime, timezone
from scapy.all import sniff, wrpcap
from scapy.layers.inet import IP, TCP, UDP
from pyflowmeter.sniffer import create_sniffer

MODEL_PATH = 'src/random_forest_model.pkl'
COLUMNS_PATH = 'src/model_columns.joblib'
PCAP_TEST_FILE = 'src/sample.pcap'
BACKEND_API_URL = "http://127.0.0.1:8000/api/log_event"

analysis_queue = queue.Queue()
active_flows = {}
flows_lock = threading.Lock()


def create_feature_mapping():
    return {
        'dst_port': 'Destination Port', 'duration': 'Flow Duration', 'fwd_pkts_tot': 'Total Fwd Packets',
        'fwd_bytes_tot': 'Total Length of Fwd Packets', 'fwd_pkt_len_max': 'Fwd Packet Length Max',
        'fwd_pkt_len_min': 'Fwd Packet Length Min', 'fwd_pkt_len_mean': 'Fwd Packet Length Mean',
        'fwd_pkt_len_std': 'Fwd Packet Length Std', 'bwd_pkt_len_max': 'Bwd Packet Length Max',
        'bwd_pkt_len_min': 'Bwd Packet Length Min', 'bwd_pkt_len_mean': 'Bwd Packet Length Mean',
        'bwd_pkt_len_std': 'Bwd Packet Length Std', 'flow_b_s': 'Flow Bytes/s', 'flow_pkt_s': 'Flow Packets/s',
        'flow_iat_mean': 'Flow IAT Mean', 'flow_iat_std': 'Flow IAT Std', 'flow_iat_max': 'Flow IAT Max',
        'flow_iat_min': 'Flow IAT Min', 'fwd_iat_tot': 'Fwd IAT Total', 'fwd_iat_mean': 'Fwd IAT Mean',
        'fwd_iat_std': 'Fwd IAT Std', 'fwd_iat_max': 'Fwd IAT Max', 'fwd_iat_min': 'Fwd IAT Min',
        'bwd_iat_tot': 'Bwd IAT Total', 'bwd_iat_mean': 'Bwd IAT Mean', 'bwd_iat_std': 'Bwd IAT Std',
        'bwd_iat_max': 'Bwd IAT Max', 'bwd_iat_min': 'Bwd IAT Min', 'fwd_hdr_len': 'Fwd Header Length',
        'bwd_hdr_len': 'Bwd Header Length', 'fwd_pkt_s': 'Fwd Packets/s', 'bwd_pkt_s': 'Bwd Packets/s',
        'pkt_len_min': 'Min Packet Length', 'pkt_len_max': 'Max Packet Length', 'pkt_len_mean': 'Packet Length Mean',
        'pkt_len_std': 'Packet Length Std', 'pkt_len_var': 'Packet Length Variance', 'fin_cnt': 'FIN Flag Count',
        'psh_cnt': 'PSH Flag Count', 'ack_cnt': 'ACK Flag Count', 'pkt_size_avg': 'Average Packet Size',
        'fwd_subflow_bytes': 'Subflow Fwd Bytes', 'fwd_win_init': 'Init_Win_bytes_forward',
        'bwd_win_init': 'Init_Win_bytes_backward', 'fwd_data_pkts_tot': 'act_data_pkt_fwd',
        'fwd_seg_size_min': 'min_seg_size_forward', 'active_mean': 'Active Mean', 'active_max': 'Active Max',
        'active_min': 'Active Min', 'idle_mean': 'Idle Mean', 'idle_max': 'Idle Max', 'idle_min': 'Idle Min',
    }


def analysis_worker(model, model_columns):
    while True:
        flow_to_process = analysis_queue.get()
        if flow_to_process is None:
            break

        flow_key, packets = flow_to_process['key'], flow_to_process['packets']

        temp_dir = f"temp_worker_{threading.get_ident()}"
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
                df_translated[col] *= 1_000_000

            df_translated.rename(columns=create_feature_mapping(), inplace=True)

            missing_cols = set(model_columns) - set(df_translated.columns)
            for c in missing_cols:
                df_translated[c] = 0
            df_aligned = df_translated[model_columns]

            predictions = model.predict(df_aligned)

            flow_details = df_new_raw.iloc[0]
            ip1, port1, ip2, port2, proto = flow_key
            src_ip, dst_ip = str(flow_details.get('src_ip', ip1)), str(flow_details.get('dst_ip', ip2))
            src_port, dst_port = int(flow_details.get('src_port', port1)), int(flow_details.get('dst_port', port2))

            result_data = {
                "timestamp_utc": datetime.now(timezone.utc).isoformat(),
                "flow_id": f"{src_ip}:{src_port}-{dst_ip}:{dst_port}-{proto}",
                "source_ip": src_ip, "source_port": src_port,
                "dest_ip": dst_ip, "dest_port": dst_port,
                "protocol": proto, "prediction": str(predictions[0]),
                "flow_duration_ms": int(flow_details.get('duration', 0) * 1000)
            }

            try:
                requests.post(BACKEND_API_URL, json=result_data)
                print(f"Prediction for flow {result_data['flow_id']}: {result_data['prediction']}")
            except requests.exceptions.ConnectionError:
                print(f"❌ Could not connect to backend at {BACKEND_API_URL}.")

        except Exception as e:
            print(f"Error in worker thread for flow {flow_key}: {e}")
        finally:
            if os.path.exists(temp_pcap): os.remove(temp_pcap)
            if os.path.exists(output_csv): os.remove(output_csv)
            if os.path.exists(temp_dir): os.rmdir(temp_dir)
            analysis_queue.task_done()


def get_flow_key(packet):
    if IP in packet and (TCP in packet or UDP in packet):
        try:
            protocol = 'TCP' if TCP in packet else 'UDP'
            proto_layer = packet[protocol]
            if proto_layer.sport is None or proto_layer.dport is None: return None

            sport, dport = int(proto_layer.sport), int(proto_layer.dport)
            ip1, ip2 = sorted((packet[IP].src, packet[IP].dst))
            port1, port2 = sorted((sport, dport))
            return (ip1, port1, ip2, port2, protocol)
        except (TypeError, ValueError):
            return None
    return None


def packet_handler(packet):
    flow_key = get_flow_key(packet)
    if not flow_key:
        return

    with flows_lock:
        if flow_key not in active_flows:
            active_flows[flow_key] = {'packets': [], 'start_time': time.time(), 'last_seen': time.time()}

        flow = active_flows[flow_key]
        flow['packets'].append(packet)
        flow['last_seen'] = time.time()

        if TCP in packet and ('F' in packet[TCP].flags or 'R' in packet[TCP].flags):
            if flow_key in active_flows:
                flow_data = active_flows.pop(flow_key)
                analysis_queue.put({'key': flow_key, 'packets': flow_data['packets']})


def flush_remaining_flows():
    with flows_lock:
        print(f"\nFlushing {len(active_flows)} remaining flows for analysis...")
        for key, flow_data in active_flows.items():
            analysis_queue.put({'key': key, 'packets': flow_data['packets']})
        active_flows.clear()


def test_engine_with_pcap(pcap_file):
    if not os.path.exists(pcap_file):
        print(f"❌ Error: Test file not found at '{pcap_file}'")
        return

    try:
        model = joblib.load(MODEL_PATH)
        model_columns = joblib.load(COLUMNS_PATH)
    except FileNotFoundError:
        print(f"❌ Error: Model or column files not found. Please check paths.")
        return

    # Start the worker thread
    worker = threading.Thread(target=analysis_worker, args=(model, model_columns), daemon=True)
    worker.start()

    print(f"🚀 Analyzing PCAP file '{pcap_file}'...")

    # Process all packets in the file
    sniff(offline=pcap_file, prn=packet_handler, store=False)

    # Once sniffing is done, process any remaining flows
    flush_remaining_flows()

    # Wait for the queue to be empty
    analysis_queue.join()

    # Stop the worker thread
    analysis_queue.put(None)
    worker.join()

    print("\n✅ PCAP analysis complete.")


if __name__ == '__main__':
    test_engine_with_pcap(PCAP_TEST_FILE)
