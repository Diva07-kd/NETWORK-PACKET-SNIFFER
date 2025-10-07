import threading
from queue import Queue
from scapy.all import sniff
from db import insert_packets_batch
from anomaly import analyze_packet

# A thread-safe queue to hold captured packets
packet_queue = Queue()

def packet_processor():
    """Pulls packets from the queue and processes them in batches."""
    packet_batch = []
    while True:
        packet_info = packet_queue.get()
        if packet_info is None:  # Add a way to stop the thread gracefully if needed
            break
        packet_batch.append(packet_info)
        
        # Process in batches of 50 or more
        if len(packet_batch) >= 50:
            insert_packets_batch(packet_batch)
            for pkt in packet_batch:
                analyze_packet(pkt)
            packet_batch = []

def packet_callback(packet):
    """Callback function for Scapy's sniff, adds packet to queue."""
    # --- THIS IS THE CORRECTED PART ---
    # We now use 0 as the default for missing numerical values, just like in training.
    info = {
       "timestamp": packet.time,
       "src": packet.getlayer('IP').src if packet.haslayer('IP') else '',
       "dst": packet.getlayer('IP').dst if packet.haslayer('IP') else '',
       "proto": packet.proto if hasattr(packet, 'proto') else 0,
       "sport": packet.sport if hasattr(packet, 'sport') else 0,
       "dport": packet.dport if hasattr(packet, 'dport') else 0,
       "length": len(packet)
    }
    packet_queue.put(info)

# Start the consumer thread
processor_thread = threading.Thread(target=packet_processor, daemon=True)
processor_thread.start()

print("[*] Starting Efficient Network Sniffer...")
# This will run until you stop it with Ctrl+C
sniff(prn=packet_callback, store=0)