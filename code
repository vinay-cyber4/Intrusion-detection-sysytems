# Intrusion-detection-sysytems using Python 
step 1:pip install scapy
step 2 :pip install scapy pandas
step 3:

import pandas as pd
from scapy.all import sniff, IP, TCP
import time

# Global variables to store packet data
packet_data = []
start_time = time.time()

# Define a threshold for unusual behavior
THRESHOLD = 100  # Example threshold for packet count

# Function to process packets
def packet_callback(packet):
    if IP in packet and TCP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        packet_data.append((time.time(), ip_src, ip_dst))

# Function to analyze packet data
def analyze_packets():
    global packet_data
    df = pd.DataFrame(packet_data, columns=['timestamp', 'src_ip', 'dst_ip'])
    
    # Calculate the number of packets per source IP
    packet_count = df['src_ip'].value_counts()
    
    # Identify unusual behavior
    unusual_ips = packet_count[packet_count > THRESHOLD].index.tolist()
    
    if unusual_ips:
        print(f"Unusual activity detected from IPs: {unusual_ips}")

# Start sniffing packets
def start_sniffing():
    print("Starting packet capture...")
    sniff(prn=packet_callback, filter="tcp", store=0)

# Main function to run the IDS
if __name__ == "__main__":
    try:
        while True:
            start_sniffing()
            time.sleep(10)  # Capture packets for 10 seconds
            analyze_packets()
            packet_data.clear()  # Clear data for the next analysis cycle
    except KeyboardInterrupt:
        print("Stopping packet capture.")



