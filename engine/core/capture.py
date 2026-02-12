"""
Packet capture and flow aggregation. Sniffs packets via Scapy, groups them
into bidirectional flows using 5-tuple keys, and enqueues completed flows
for ML classification. Handles TCP FIN/RST teardown and idle/max-life timeouts.
"""

import time
from scapy.layers.inet import IP, TCP, UDP

from core.config import (
    analysis_queue, active_flows, flows_lock,
    FLOW_TIMEOUT_SECONDS, FLOW_MAX_LIFE_SECONDS,
)


def get_flow_key(packet):
    if IP in packet and (TCP in packet or UDP in packet):
        try:
            protocol = 'TCP' if TCP in packet else 'UDP'
            proto_layer = packet[protocol]
            sport = int(proto_layer.sport)
            dport = int(proto_layer.dport)
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


def check_flow_timeouts():
    while True:
        time.sleep(FLOW_TIMEOUT_SECONDS)
        now = time.time()
        with flows_lock:
            for key in list(active_flows.keys()):
                flow = active_flows.get(key)
                if not flow:
                    continue

                is_timed_out = (now - flow['last_seen']) > FLOW_TIMEOUT_SECONDS
                is_max_life = (now - flow['start_time']) > FLOW_MAX_LIFE_SECONDS

                if is_timed_out or is_max_life:
                    flow_data = active_flows.pop(key)
                    analysis_queue.put({'key': key, 'packets': flow_data['packets']})
                    reason = "timed out" if is_timed_out else "exceeded max life"
                    print(f"Flow {key} {reason}. Moved to analysis queue.")
