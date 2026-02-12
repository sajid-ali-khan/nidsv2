"""
NIDS Engine - Entry Point

Starts the real-time network intrusion detection engine.
Launches the packet sniffer, flow timeout checker, and ML classification worker
as separate threads. Predictions are sent to the backend API.

Usage: sudo python main.py
"""

import threading
import joblib
from scapy.all import sniff

from core.config import MODEL_PATH, COLUMNS_PATH, NETWORK_INTERFACE
from core.capture import packet_handler, check_flow_timeouts
from core.classifier import analysis_worker


def start():
    try:
        model = joblib.load(MODEL_PATH)
        model_columns = joblib.load(COLUMNS_PATH)
        print("Model and column list loaded successfully.")
    except FileNotFoundError:
        print("Error: Model or column file not found. Run the training script first.")
        return

    worker = threading.Thread(target=analysis_worker, args=(model, model_columns), daemon=True)
    worker.start()

    timeout_checker = threading.Thread(target=check_flow_timeouts, daemon=True)
    timeout_checker.start()

    print(f"Starting NIDS engine on interface '{NETWORK_INTERFACE}'...")
    print("Press Ctrl+C to stop.\n")

    try:
        sniff(iface=NETWORK_INTERFACE, prn=packet_handler, store=False)
    except KeyboardInterrupt:
        print("\nStopping traffic capture.")
    except Exception as e:
        print(f"\nError: {e}")
        print("Ensure you are running with root/administrator privileges.")


if __name__ == '__main__':
    start()
