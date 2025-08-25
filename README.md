# Network Packet Sniffer & Analyzer

A Python-based tool that captures and analyzes live network packets (TCP, UDP, ICMP). It detects suspicious activity such as port scans and provides **visual insights** using Matplotlib.

## 🚀 Features
- Captures live packets in real time using Scapy  
- Analyzes TCP, UDP, and ICMP traffic  
- Detects possible **port scanning attempts**  
- **Unique Feature:** Visualizes packet distribution across protocols using Matplotlib  

## ⚙️ How It Works
- **Input:** Live network traffic (no file input needed)  
- **Process:** Captures packets → Identifies protocol → Updates counters → Detects anomalies  
- **Output:**  
  - Console alerts (e.g., “Possible port scan detected from 192.168.x.x”)  
  - A bar chart showing distribution of TCP/UDP/ICMP packets  

## ▶️ Run Instructions
```bash
pip install scapy matplotlib
python sniffer.py
