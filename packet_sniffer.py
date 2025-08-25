"""
==================================================
Network Packet Sniffer & Analyzer (Layer 3 - Windows)
Author : Pranya Gupta
Description :
    - Captures live packets using Scapy (IP layer only).
    - Analyzes TCP, UDP, and ICMP traffic.
    - Detects simple port scanning attempts (based on SYN flag).
    - Visualizes traffic distribution with Matplotlib.

Note:
    - Layer 3 sniffing works on Windows without Npcap.
    - Only IP packets are captured (no Ethernet/ARP).
==================================================
"""

# Import required libraries
from scapy.all import sniff, IP, TCP, UDP, ICMP, conf
import matplotlib
matplotlib.use("Agg")   # force non-GUI backend (saves plots as PNG)
import matplotlib.pyplot as plt
from collections import Counter

# Counter to store packet counts by protocol
protocol_counter = Counter()


def analyze_packet(packet):
    """
    Callback function for each sniffed packet.
    Updates protocol counters and checks for suspicious traffic.
    """
    if IP in packet:  # Ensure packet has IP layer
        proto = packet[IP].proto

        # Map protocol numbers to names
        if proto == 6:       # TCP
            protocol_counter['TCP'] += 1
        elif proto == 17:    # UDP
            protocol_counter['UDP'] += 1
        elif proto == 1:     # ICMP
            protocol_counter['ICMP'] += 1
        else:
            protocol_counter['Other'] += 1

        # Detect simple port scanning (TCP SYN packets)
        if TCP in packet and packet[TCP].flags == "S":
            print(f"[!] Possible Port Scan Detected from {packet[IP].src}")


def visualize_traffic():
    """
    Save a bar chart of captured traffic distribution (PNG file).
    """
    if not protocol_counter:
        print("No packets captured. Exiting without visualization.")
        return

    # Extract protocol names and counts
    protocols = list(protocol_counter.keys())
    counts = list(protocol_counter.values())

    # Plot chart
    plt.bar(protocols, counts, color='skyblue', edgecolor='black')
    plt.xlabel("Protocol")
    plt.ylabel("Packet Count")
    plt.title("Live Network Traffic Distribution")

    # Save instead of showing (no Tkinter needed)
    output_file = "traffic.png"
    plt.savefig(output_file)
    print(f"[+] Traffic distribution saved as {output_file}")


def start_sniffer():
    """
    Start sniffing packets at Layer 3 (IP level).
    Works on Windows with admin rights or Npcap.
    """
    print("=======================================")
    print("   Starting Layer 3 Packet Sniffer...  ")
    print("   Press Ctrl+C to stop.               ")
    print("=======================================")

    try:
        # Run the sniffer (blocks until Ctrl+C)
        sniff(
            prn=analyze_packet,
            store=False,
            lfilter=lambda p: IP in p,
            iface=None,
            opened_socket=conf.L3socket()
        )
    except KeyboardInterrupt:
        print("\n[!] Stopping Sniffer...")
    finally:
        # Always visualize results
        visualize_traffic()


if __name__ == "__main__":
    start_sniffer()

