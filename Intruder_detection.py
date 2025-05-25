import os
from scapy.all import sniff, IP, TCP, UDP, ICMP, DNS, DNSQR, DNSRR, wrpcap, rdpcap
from datetime import datetime
import re
from collections import defaultdict
import ipaddress
from scapy.layers.l2 import ARP
from dotenv import load_dotenv
import requests
import uuid
from scapy.layers.l2 import Ether
SYN_THRESHOLDS = {"likely": 500, "definite": 10000}
UDP_THRESHOLDS = {"likely": 2000, "severe": 10000}
ICMP_THRESHOLDS = {"likely": 500, "severe": 5000}
HTTP_THRESHOLDS = {"likely": 500, "critical": 10000}
DNS_THRESHOLDS = {"likely": 1000, "severe": 10000}
load_dotenv()
bot_token = os.getenv("BOT_TOKEN")
chat_id = os.getenv("CHAT_ID")
def send_telegram_message(bot_token, chat_id, text):
    url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
    payload = {"chat_id": chat_id, "text": text, "parse_mode": "HTML"}
    try:
        response = requests.post(url, data=payload)
        if response.status_code != 200:
            print(f"Telegram send failed: {response.text}")
    except Exception as e:
        print(f"Telegram send exception: {e}")
def get_mac_address():
    mac = uuid.getnode()
    if (mac >> 40) % 2:
        return "Unknown"
    return ':'.join(f'{(mac >> ele) & 0xff:02x}' for ele in range(40, -1, -8))
def get_public_ip():
    try:
        response = requests.get("https://api.ipify.org", timeout=5)
        response.raise_for_status()
        return response.text.strip()
    except Exception:
        return None 

def get_geo_location(ip):
    if ip is None:
        return "Unknown Location"
    try:
        if ipaddress.ip_address(ip).is_private:
            return "Local Network"
    except ValueError:
        return "Invalid IP Address"
    try:
        res = requests.get(f"https://ipinfo.io/{ip}/json", timeout=5).json()
        city = res.get("city", "")
        region = res.get("region", "")
        country = res.get("country", "")
        return f"{city}, {region}, {country}".strip(', ')
    except Exception:
        return "Unknown Location"
def get_own_location():
    ip = get_public_ip()
    location = get_geo_location(ip)
    return ip or "Unknown", location
def get_mac():
    try:
        mac = uuid.getnode()
        if (mac >> 40) % 2:
            return "Unknown"
        return ':'.join(f'{(mac >> ele) & 0xff:02x}' for ele in range(40, -1, -8))
    except Exception:
        return "Unknown"
def format_packet(packet):
    timestamp = datetime.now().strftime("[%Y-%m-%d %H:%M:%S]")
    summary = packet.summary()
    src_ip = dst_ip = src_mac = dst_mac = proto = sport = dport = flags = "-"
    extra = ""
    if Ether in packet:
        src_mac = packet[Ether].src
        dst_mac = packet[Ether].dst
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        proto = packet[IP].proto
    if TCP in packet:
        sport = packet[TCP].sport
        dport = packet[TCP].dport
        flags = packet[TCP].flags
        flag_str = str(flags)
        extra += f" TCP sport={sport}, dport={dport}, flags={flag_str}"
    elif UDP in packet:
        sport = packet[UDP].sport
        dport = packet[UDP].dport
        extra += f" UDP sport={sport}, dport={dport}"
    elif ICMP in packet:
        extra += " ICMP Packet"
    if DNS in packet:
        dns = packet[DNS]
        if dns.qr == 0 and DNSQR in dns:  
            qname = dns[DNSQR].qname.decode(errors='ignore')
            extra += f" DNS Query for {qname}"
        elif dns.qr == 1 and DNSRR in dns: 
            rdata = dns[DNSRR].rdata
            rname = dns[DNSRR].rrname.decode(errors='ignore')
            extra += f" DNS Response: {rname} -> {rdata}"
    if ARP in packet:
        arp = packet[ARP]
        if arp.op == 2: 
            extra += f" ARP {arp.psrc} is at {arp.hwsrc}"
        elif arp.op == 1: 
            extra += f" ARP who has {arp.pdst}? Tell {arp.psrc}"
    log_entry = (f"{timestamp} {summary}{extra} | "
             f"SRC_IP: {src_ip} SRC_MAC: {src_mac} -> "
             f"DST_IP: {dst_ip} DST_MAC: {dst_mac} | "
             f"PROTOCOL: {proto}")
    return log_entry
def sniff_packets(interface='eth0'):
    if not os.path.exists("logs"):
        os.makedirs("logs")
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    log_filename = f"logs/log_{timestamp}.txt"
    pcap_filename = f"logs/packets_{timestamp}.pcap"
    packets = []
    def process_packet(packet):
        packets.append(packet)
        print(packet.summary())
    print(f"[+] Capturing packets on {interface} (no real-time logging)...")
    sniff(
        iface=interface,
        prn=process_packet,
        store=True,
        filter="tcp or udp or icmp or arp"
    )
    print("[+] Sniffing complete. Writing logs and PCAP...")
    with open(log_filename, "w") as f:
        f.write("\n".join(format_packet(p) for p in packets))
    wrpcap(pcap_filename, packets)
    print(f"[+] Log saved: {log_filename}")
    print(f"[+] PCAP saved: {pcap_filename}")
    detect_ddos(log_filename, bot_token, chat_id)
    detect_port_scan(log_filename, bot_token, chat_id)
    detect_mitm_attack(log_filename, bot_token, chat_id)
    detect_dns_spoofing(log_filename, bot_token, chat_id)
    detect_arp_spoofing(log_filename, bot_token, chat_id)
    return log_filename
def parse_log_line(line):
    try:
        timestamp_match = re.search(r"\[(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\]", line)
        if not timestamp_match:
            return None, None, None, None
        timestamp_str = timestamp_match.group(1)
        timestamp = datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S")
        proto_match = re.search(r"PROTOCOL: (\d+)", line)
        protocol = int(proto_match.group(1)) if proto_match else -1
        src_match = re.search(r"SRC_IP: ([\d\.]+)", line)
        src_ip = src_match.group(1) if src_match else "unknown"
        src_mac_match = re.search(r"SRC_MAC: ([\da-fA-F:]{17})", line)
        src_mac = src_mac_match.group(1).lower() if src_mac_match else "unknown"
        line_lower = line.lower()
        if "syn" in line_lower and "ack" not in line_lower and protocol == 6:
            packet_type = "SYN"
        elif protocol == 17:
            packet_type = "DNS" if "dns" in line_lower else "UDP"
        elif protocol == 1:
            packet_type = "ICMP"
        elif protocol == 6 and "http" in line_lower:
            packet_type = "HTTP"
        else:
            packet_type = None
        return timestamp, src_ip, src_mac, packet_type
    except Exception:
        return None, None, None, None
def detect_ddos(log_file, bot_token, chat_id):
    print(f"\n[+] Analyzing log file for DDoS attacks: {log_file}")
    packet_counts = defaultdict(lambda: defaultdict(int))
    mac_map = {}
    with open(log_file, "r") as f:
        for line in f:
            timestamp, src_ip, src_mac, packet_type = parse_log_line(line)
            if packet_type:
                time_bucket = timestamp.replace(microsecond=0)
                key = f"{packet_type}_{src_ip}"
                packet_counts[time_bucket][key] += 1
                mac_map[src_ip] = src_mac
    user_ip, user_location = get_own_location()
    for time_bucket in sorted(packet_counts.keys()):
        for key, count in packet_counts[time_bucket].items():
            pkt_type, attacker_ip = key.split("_", 1)
            attacker_mac = mac_map.get(attacker_ip, "unknown")
            attacker_location = get_geo_location(attacker_ip)
            alert = None
            if pkt_type == "SYN":
                if count >= SYN_THRESHOLDS["definite"]:
                    alert = "[!!] DEF SYN FLOOD"
                elif count >= SYN_THRESHOLDS["likely"]:
                    alert = "[!] LIKELY SYN FLOOD"
            elif pkt_type == "UDP":
                if count >= UDP_THRESHOLDS["severe"]:
                    alert = "[!!] SEVERE UDP FLOOD"
                elif count >= UDP_THRESHOLDS["likely"]:
                    alert = "[!] LIKELY UDP FLOOD"
            elif pkt_type == "ICMP":
                if count >= ICMP_THRESHOLDS["severe"]:
                    alert = "[!!] SEVERE ICMP FLOOD"
                elif count >= ICMP_THRESHOLDS["likely"]:
                    alert = "[!] LIKELY ICMP FLOOD"
            elif pkt_type == "HTTP":
                if count >= HTTP_THRESHOLDS["critical"]:
                    alert = "[!!] CRITICAL HTTP FLOOD"
                elif count >= HTTP_THRESHOLDS["likely"]:
                    alert = "[!] LIKELY HTTP FLOOD"
            elif pkt_type == "DNS":
                if count >= DNS_THRESHOLDS["severe"]:
                    alert = "[!!] SEVERE DNS AMP ATTACK"
                elif count >= DNS_THRESHOLDS["likely"]:
                    alert = "[!] LIKELY DNS AMP ATTACK"
            if alert:
                message = (
                    f"{alert}\n"
                    f"Time: {time_bucket}\n"
                    f"Attack Type: {pkt_type}\n"
                    f"Attacker IP: {attacker_ip}\n"
                    f"Attacker MAC: {attacker_mac}\n"
                    f"Attacker Location: {attacker_location}\n"
                    f"User IP: {user_ip}\n"
                    f"User Location: {user_location}\n"
                    f"Details: {pkt_type} traffic from {attacker_ip} = {count} packets/sec"
                )
                send_telegram_message(bot_token, chat_id, message)
                print(message)
def detect_port_scan(log_file, bot_token, chat_id):
    print(f"\n[+] Analyzing log file for Port Scan activity: {log_file}")
    scan_tracker = defaultdict(lambda: defaultdict(set))
    mac_map = {}
    with open(log_file, "r") as f:
        for line in f:
            try:
                timestamp, src_ip, src_mac, packet_type = parse_log_line(line)
                if not packet_type or packet_type != "SYN":
                    continue
                dst_match = re.search(r"DST: ([\d\.]+)", line)
                dst_ip = dst_match.group(1) if dst_match else None
                port_match = re.search(r"dport=(\d+)", line.lower())
                if not port_match:
                    port_match = re.search(r"->.*:(\d+)", line)
                dst_port = port_match.group(1) if port_match else None
                if dst_ip and dst_port:
                    scan_tracker[src_ip][dst_ip].add(dst_port)
                    mac_map[src_ip] = src_mac
            except Exception:
                continue
    user_ip = get_public_ip()
    user_location = get_geo_location(user_ip)
    for src_ip in scan_tracker:
        for dst_ip in scan_tracker[src_ip]:
            port_count = len(scan_tracker[src_ip][dst_ip])
            if port_count > 100:
                attacker_mac = mac_map.get(src_ip, "unknown")
                attacker_location = get_geo_location(src_ip)
                alert_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                alert_message = (
                    f"<b>Port Scan Detected</b>\n"
                    f"Time: {alert_time}\n"
                    f"Attacker IP: {src_ip}\n"
                    f"Attacker MAC: {attacker_mac}\n"
                    f"Attacker Location: {attacker_location}\n"
                    f"Target IP: {dst_ip}\n"
                    f"Ports Scanned: {port_count}\n"
                    f"User IP: {user_ip}\n"
                    f"User Location: {user_location}"
                )
                print(f"[!] POSSIBLE PORT SCAN from {src_ip} -> {dst_ip}: Scanned {port_count} ports")
                send_telegram_message(bot_token, chat_id, alert_message)
def detect_mitm_attack(log_file, bot_token, chat_id):
    print(f"\n[+] Analyzing log file for Man-in-the-Middle (MitM) attacks: {log_file}")
    arp_table = defaultdict(set)
    mac_table = defaultdict(set)
    suspicious_dns = []
    with open(log_file, "r") as f:
        for line in f:
            try:
                timestamp, src_ip, src_mac, packet_type = parse_log_line(line)
                if "ARP" in line:
                    ip_match = re.search(r"who has ([\d\.]+)", line)
                    mac_match = re.search(r"src=([0-9a-f:]{17})", line, re.IGNORECASE)
                    sender_match = re.search(r"Request who-has ([\d\.]+) tell ([\d\.]+)", line)
                    if sender_match:
                        target_ip = sender_match.group(1)
                        sender_ip = sender_match.group(2)
                        ip = sender_ip
                    elif ip_match:
                        ip = ip_match.group(1)
                    else:
                        continue
                    if ip and mac_match:
                        mac = mac_match.group(1).lower()
                        arp_table[ip].add(mac)
                        mac_table[mac].add(ip)
                if "DNS" in line and "Response" in line:
                    dns_resp_ip_match = re.search(r"SRC: ([\d\.]+)", line)
                    if dns_resp_ip_match:
                        dns_ip = dns_resp_ip_match.group(1)
                        if dns_ip.startswith(("192.168.", "10.", "172.")):
                            suspicious_dns.append(dns_ip)
            except Exception:
                continue
    user_ip = get_public_ip()
    user_location = get_geo_location(user_ip)
    alert_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    for ip, macs in arp_table.items():
        if len(macs) > 1:
            attacker_location = get_geo_location(ip)
            attacker_mac_str = ', '.join(macs)
            print(f"[!!] ARP Spoofing Detected: IP {ip} has multiple MACs: {macs}")
            message = (
                f"<b>ARP Spoofing Detected</b>\n"
                f"Time: {alert_time}\n"
                f"Attacker IP: {ip}\n"
                f"Attacker MAC(s): {attacker_mac_str}\n"
                f"Attacker Location: {attacker_location}\n"
                f"Reason: Multiple MACs seen for the same IP\n"
                f"User IP: {user_ip}\n"
                f"User Location: {user_location}"
            )
            send_telegram_message(bot_token, chat_id, message)
    for mac, ips in mac_table.items():
        if len(ips) > 3:
            ips_str = ', '.join(ips)
            print(f"[!!] MAC Spoofing Detected: MAC {mac} used by IPs: {ips}")
            message = (
                f"<b>MAC Spoofing Detected</b>\n"
                f"Time: {alert_time}\n"
                f"MAC Address: {mac}\n"
                f"Used By IPs: {ips_str}\n"
                f"User IP: {user_ip}\n"
                f"User Location: {user_location}"
            )
            send_telegram_message(bot_token, chat_id, message)
    for ip in set(suspicious_dns):
        attacker_location = get_geo_location(ip)
        print(f"[!] Possible DNS Hijack: DNS response from local IP {ip}")
        message = (
            f"<b>DNS Hijack Suspected</b>\n"
            f"Time: {alert_time}\n"
            f"Suspicious DNS Response from: {ip}\n"
            f"Location: {attacker_location}\n"
            f"User IP: {user_ip}\n"
            f"User Location: {user_location}"
        )
        send_telegram_message(bot_token, chat_id, message)
def detect_dns_spoofing(log_file, bot_token, chat_id):
    print(f"\n[+] Analyzing DNS Spoofing activity from: {log_file}")
    dns_records = defaultdict(lambda: defaultdict(set)) 
    with open(log_file, "r") as f:
        for line in f:
            try:
                timestamp, src_ip, src_mac, packet_type = parse_log_line(line)
                if "DNS Response" in line:
                    domain_match = re.search(r"DNS Response: ([\w\.-]+) -> ([\d\.]+)", line)
                    if domain_match:
                        domain = domain_match.group(1)
                        ip = domain_match.group(2)
                        dns_records[domain][ip].add(src_mac)
            except Exception:
                continue
    user_ip = get_public_ip()
    user_location = get_geo_location(user_ip)
    alert_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    for domain, ip_mac_map in dns_records.items():
        if len(ip_mac_map) > 1:
            unique_macs = set()
            for macs in ip_mac_map.values():
                unique_macs.update(macs)
            if len(unique_macs) > 1:
                ip_list = ', '.join(ip_mac_map.keys())
                mac_list = ', '.join(unique_macs)
                attacker_info = []
                for attacker_ip in ip_mac_map.keys():
                    loc = get_geo_location(attacker_ip)
                    attacker_info.append(f"{attacker_ip} ({loc})")
                attacker_info_str = '\n'.join(attacker_info)
                print(f"[!!] Possible DNS Spoofing Detected: Domain {domain} resolved to IPs: {ip_list} from MACs: {mac_list}")
                message = (
                    f"<b>DNS Spoofing Detected</b>\n"
                    f"Time: {alert_time}\n"
                    f"Domain: {domain}\n"
                    f"Resolved IPs: {ip_list}\n"
                    f"Source MACs: {mac_list}\n"
                    f"Attacker IP(s) and Location(s):\n{attacker_info_str}\n"
                    f"User IP: {user_ip}\n"
                    f"User Location: {user_location}"
                )
                send_telegram_message(bot_token, chat_id, message)
def detect_arp_spoofing(log_file, bot_token, chat_id):
    print(f"\n[+] Analyzing ARP packets for spoofing: {log_file}")
    ip_mac_map = defaultdict(set)
    suspicious_entries = []
    with open(log_file, "r") as f:
        for line in f:
            if "ARP" not in line or "who has" in line:
                continue
            mac_match = re.search(r"ARP .*? is at ([\w:]+)", line)
            ip_match = re.search(r"who has ([\d\.]+)", line) or re.search(r"ARP, (\d+\.\d+\.\d+\.\d+)", line)
            if mac_match and ip_match:
                mac = mac_match.group(1).lower()
                ip = ip_match.group(1)
                ip_mac_map[ip].add(mac)
                if len(ip_mac_map[ip]) > 1 and (ip, list(ip_mac_map[ip])) not in suspicious_entries:
                    print(f"[!!] POSSIBLE ARP SPOOFING: IP {ip} mapped to multiple MACs: {ip_mac_map[ip]}")
                    suspicious_entries.append((ip, list(ip_mac_map[ip])))
    if not suspicious_entries:
        print("[+] No ARP spoofing detected.")
        return
    user_ip = get_public_ip()
    user_location = get_geo_location(user_ip)
    alert_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    for ip, macs in suspicious_entries:
        attacker_location = get_geo_location(ip)
        message = (
            f"<b>ARP Spoofing Alert!</b>\n"
            f"Time: {alert_time}\n"
            f"IP: {ip}\n"
            f"MAC Addresses: {', '.join(macs)}\n"
            f"Attacker Location: {attacker_location}\n"
            f"User IP: {user_ip}\n"
            f"User Location: {user_location}"
        )
        if send_telegram_message(bot_token, chat_id, message):
            print(f"[+] Telegram alert sent for IP {ip}")
        else:
            print(f"[!] Telegram alert failed for IP {ip}")
if __name__ == "__main__":
    sniff_packets(interface='eth0') 
