# NIDS
Network Intruder Detection System with Python
🛡️ Network Intrusion Detection & Alert System (Python)
This Python-based Network Intrusion Detection and Alert System is designed to monitor, detect, and alert administrators about potential DDoS (Distributed Denial of Service) attacks in real-time. Built with a strong focus on cybersecurity and network defense, the system analyzes live traffic, logs suspicious activity, and notifies the user through a Telegram bot. The solution is ideal for small-scale network setups or educational environments where basic network security mechanisms are being implemented or tested.
At its core, the program uses the Scapy library to sniff network packets at a low level. It captures and logs traffic data including source IPs, protocols used, and timestamps. These logs are saved with precise filenames based on the current date and time, ensuring each session is properly archived for later review or forensic analysis.
The detection engine processes the sniffed packet logs to identify common forms of DDoS attacks across multiple layers. These include SYN floods, UDP floods, ICMP floods at the transport and network layers, and HTTP floods, Slowloris attacks at the application layer. Each attack type is identified by monitoring request frequency and comparing it against predefined safe and critical thresholds.
To enhance the detection logic, the system incorporates real-time geolocation tracking of incoming IPs using external APIs. This allows you to compare local versus external traffic origins and better evaluate potential threats. It can intelligently distinguish between local internal network traffic and external IPs that may be launching attacks.
For every confirmed or suspected attack, the system generates a detailed log entry and sends an immediate alert via Telegram. These alerts contain information about the type of attack, source IP, geolocation, time of occurrence, and packet rate. Telegram bot integration ensures that admins are instantly notified, even when they are not physically present at the monitoring system.
The system is modular and designed for extensibility. Detection logic for new attack types can be easily added, and the logging system can be integrated with other dashboards or SIEM tools in the future. The alerting mechanism can also be extended to include SMS, email, or desktop notifications, depending on user requirements.
This project is also ideal for students, researchers, or hobbyists looking to deepen their understanding of network traffic analysis, packet inspection, and cybersecurity threat detection. It helps bridge the gap between theoretical networking knowledge and practical, real-world implementation.
Finally, the program runs smoothly on lightweight hardware setups, such as Raspberry Pi, making it suitable for deployment in home labs, educational institutions, or small business networks. With well-structured code, organized logs, and reliable alerting, this project provides a strong foundation for building more advanced network defense systems.
Features
📡 Packet Sniffing
Captures and logs all incoming packets using scapy.

🧠 DDoS Detection
      --Detects various types of DDoS attacks based on traffic patterns:
SYN Flood
UDP Flood
ICMP Flood
HTTP Flood
DNS Amplification

🌐 Geo-IP Analysis
Identifies whether the source IP is public or private and optionally gets location info.

🔔 Real-Time Alerts
Sends alert messages to a Telegram bot when an attack is detected.

🗂️ Log Management
Automatically creates time-stamped logs in the logs/ folder.
📚 Libraries Used
scapy – For capturing, analyzing, and handling network packets.
ipaddress – To validate and check if IP addresses are private or public.
datetime – For creating timestamps and organizing log files.
collections – Using defaultdict and Counter for packet counting and analysis.
os – To create directories, handle file paths, and manage logs.
re – For regular expression operations (e.g., extracting IPs from logs).
json – To parse responses from geo-location APIs (if used).
requests – For sending data to Telegram bot API and accessing external APIs.
socket – For IP parsing and network-level utilities.
time – To control sniffing durations and intervals.
threading – To run packet sniffing and detection concurrently.
sys – To handle command-line arguments and system operations.
