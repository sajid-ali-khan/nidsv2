from scapy.all import rdpcap
import os
from collections import deque

from scapy.layers.inet import IP, TCP, UDP

PCAP_FILE = 'sample.pcap'

def get_flow_key(packet):
    """Creates a unique key for a packet's flow."""
    if IP in packet and (TCP in packet or UDP in packet):
        protocol = 'TCP' if TCP in packet else 'UDP'
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        src_port = packet[protocol].sport
        dst_port = packet[protocol].dport

        # To keep flows consistent, we order by IP and port
        if (src_ip, src_port) > (dst_ip, dst_port):
            src_ip, dst_ip = dst_ip, src_ip
            src_port, dst_port = dst_port, src_port

        return protocol, src_ip, src_port, dst_ip, dst_port
    return None

def process_pcap(file_path):
    """Reads a pcap file, groups packets into flows, and moves them all to a queue."""
    if not os.path.exists(file_path):
        print(f"Error: File '{file_path}' does not exist")
        return

    print(f"Reading packets from '{file_path}'...")
    try:
        packets = rdpcap(file_path)
    except Exception as e:
        print(f"Error reading pcap file: {e}")
        return

    active_flows = {}
    analysis_queue = deque()

    # --- Step 1: Group all packets into flows ---
    for packet in packets:
        flow_key = get_flow_key(packet)
        if not flow_key:
            continue

        packet_time = float(packet.time)

        if flow_key not in active_flows:
            active_flows[flow_key] = {
                'packets': [packet],
                'start_time': packet_time,
                'last_seen': packet_time,
                'key': flow_key
            }
        else:
            active_flows[flow_key]['packets'].append(packet)
            active_flows[flow_key]['last_seen'] = packet_time

    # --- Step 2: Move all collected flows to the analysis queue ---
    print(f'\nEnd of PCAP file. Moving {len(active_flows)} flows to analysis queue.')
    analysis_queue.extend(active_flows.values())
    active_flows.clear()

    print(f'\nProcessing complete.')
    print(f'Total flows in analysis queue: {len(analysis_queue)}')

    # The next step is to process flows from this analysis_queue
    return analysis_queue

if __name__ == '__main__':
    completed_flows = process_pcap(PCAP_FILE)
    if completed_flows:
        print(f"\nReady to analyze {len(completed_flows)} flows.")