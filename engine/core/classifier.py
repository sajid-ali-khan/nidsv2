"""
ML classification worker. Consumes completed flows from the analysis queue,
extracts features via pyflowmeter, runs the Random Forest model, and POSTs
predictions to the backend API.
"""

import os
import threading
import requests
import pandas as pd
from datetime import datetime, timezone
from scapy.all import wrpcap
from pyflowmeter.sniffer import create_sniffer

from core.config import analysis_queue, BACKEND_API_URL
from core.features import translate_features


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

            df_raw = pd.read_csv(output_csv)
            df_aligned = translate_features(df_raw, model_columns)
            predictions = model.predict(df_aligned)

            flow_details = df_raw.iloc[0]
            ip1, port1, ip2, port2, proto = flow_key

            result_data = {
                "timestamp_utc": datetime.now(timezone.utc).isoformat(),
                "flow_id": f"{flow_details.get('src_ip', ip1)}:{int(flow_details.get('src_port', port1))}"
                           f"-{flow_details.get('dst_ip', ip2)}:{int(flow_details.get('dst_port', port2))}-{proto}",
                "source_ip": str(flow_details.get('src_ip', ip1)),
                "source_port": int(flow_details.get('src_port', port1)),
                "dest_ip": str(flow_details.get('dst_ip', ip2)),
                "dest_port": int(flow_details.get('dst_port', port2)),
                "protocol": proto,
                "prediction": str(predictions[0]),
                "flow_duration_ms": int(flow_details.get('duration', 0) * 1000),
            }

            try:
                requests.post(BACKEND_API_URL, json=result_data)
                print(f"Prediction for {result_data['flow_id']}: {result_data['prediction']}")
            except requests.exceptions.ConnectionError:
                print(f"Could not connect to backend at {BACKEND_API_URL}.")

        except Exception as e:
            print(f"Error processing flow {flow_key}: {e}")
        finally:
            if os.path.exists(temp_pcap): os.remove(temp_pcap)
            if os.path.exists(output_csv): os.remove(output_csv)
            if os.path.exists(temp_dir): os.rmdir(temp_dir)
            analysis_queue.task_done()
