"""
Centralized configuration for the NIDS engine.
All paths, network settings, and tuning parameters.
"""

import os
import platform
import queue
import threading

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

MODEL_PATH = os.path.join(BASE_DIR, 'model', 'random_forest_model.pkl')
COLUMNS_PATH = os.path.join(BASE_DIR, 'model', 'model_columns.joblib')

BACKEND_API_URL = os.getenv("BACKEND_API_URL", "http://127.0.0.1:8000/api/log_event")

_default_interface = 'wlp3s0' if platform.system() == 'Linux' else 'en0' if platform.system() == 'Darwin' else 'Ethernet'
NETWORK_INTERFACE = os.getenv("NETWORK_INTERFACE", _default_interface)

FLOW_TIMEOUT_SECONDS = 15
FLOW_MAX_LIFE_SECONDS = 120

analysis_queue = queue.Queue()
active_flows = {}
flows_lock = threading.Lock()
