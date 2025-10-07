readme_content =  Network Packet Sniffer with Anomaly Detection System 

## Project Objective
The objective of this project is to build a real-time network traffic sniffer with basic anomaly detection capabilities. The system will capture network packets, extract relevant information, detect potential security threats like port scanning and flooding, store the data and anomalies in a database for historical analysis, and generate alerts for detected anomalies.

## Tools Used
- Python
- scapy: A powerful interactive packet manipulation tool.
- SQLite: A self-contained, serverless, zero-configuration, transactional SQL database engine.
- matplotlib: A comprehensive library for creating static, interactive, and animated visualizations in Python.

## Features

### Packet Capture and Logging
- Captures network packets using `scapy`.
- Extracts key header information: Source IP, Destination IP, Protocol, Source Port, Destination Port, Packet Length, and TCP Flags.
- Logs captured packet information (optional, currently set up for database storage).

### Anomaly Detection
- Implements basic anomaly detection techniques.
- **Port Scanning Detection:** Identifies potential port scans by monitoring the number of unique destination ports a single source IP attempts to connect to within a defined time window.
- **Flooding Detection:** Detects potential flooding attacks by monitoring the volume of traffic (packet count) originating from a single source IP within a defined time window.

### Database Storage
- Stores captured packet data in an SQLite database (`network_traffic.db`).
- Stores detected anomaly events in the same SQLite database.
- Allows for historical analysis and reporting of network traffic and security events.

### Alerting System
- Generates alerts when anomalies are detected.
- Alerts are written to a log file (`alerts.log`) with a timestamp and details of the anomaly.

### Traffic Summary and Visualization
- Provides a summary of the captured network traffic, including:
    - Total packets captured.
    - Unique source and destination IP addresses.
    - Most frequent destination ports.
    - Total anomalies recorded.
    - Unique source IP addresses that triggered anomalies.
- (Optional) Can be extended to include real-time traffic visualization using `matplotlib`.

## Setup and Installation

1.  **Clone the repository:**
"""
