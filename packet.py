import socket
import struct
import datetime
import csv
import platform

try:
    from scapy.all import IP, TCP, UDP, ICMP
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

PROTOCOLS = {1: "ICMP", 6: "TCP", 17: "UDP"}
LOG_FILE = "packet_logs.csv"
SCAPY_SUMMARY_ENABLED = True

def get_local_ip():

    try:
        temp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        temp_sock.connect(("8.8.8.8", 80))
        ip = temp_sock.getsockname()[0]
        temp_sock.close()
        return ip
    except Exception:
        return "127.0.0.1"

def init_log_file():

    with open(LOG_FILE, mode='w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(["Timestamp", "Source IP", "Destination IP", "Protocol", "Payload (Hex)"])

def log_packet(timestamp, src_ip, dst_ip, protocol, payload_hex):

    with open(LOG_FILE, mode='a', newline='') as file:
        writer = csv.writer(file)
        writer.writerow([timestamp, src_ip, dst_ip, protocol, payload_hex])

def parse_ip_header(data):
    ip_header = struct.unpack('!BBHHHBBH4s4s', data[:20])
    src_ip = socket.inet_ntoa(ip_header[8])
    dst_ip = socket.inet_ntoa(ip_header[9])
    protocol = PROTOCOLS.get(ip_header[6], str(ip_header[6]))
    return src_ip, dst_ip, protocol

def display_payload(data):
    payload = data[20:]
    return payload.hex()

def scapy_parse(packet_data):
    if SCAPY_AVAILABLE and SCAPY_SUMMARY_ENABLED:
        pkt = IP(packet_data)
        return pkt.summary()
    return None

def start_sniffer():
    init_log_file()
    host_ip = get_local_ip()
    print(f"Binding to local IP: {host_ip}")

    try:
        if platform.system() == "Windows":
            sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
            sniffer.bind((host_ip, 0))
            sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
        else:
            sniffer = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))

        print("Sniffing started... Press Ctrl+C to stop.\n")

        while True:
            raw_data, _ = sniffer.recvfrom(65565)
            timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            src_ip, dst_ip, protocol = parse_ip_header(raw_data)
            payload_hex = display_payload(raw_data)

            print(f"[{timestamp}] {src_ip} â†’ {dst_ip} | Protocol: {protocol}")
            print(f"Payload: {payload_hex[:100]}...")

            scapy_summary = scapy_parse(raw_data)
            if scapy_summary:
                print("Scapy Summary:", scapy_summary)

            log_packet(timestamp, src_ip, dst_ip, protocol, payload_hex)

    except KeyboardInterrupt:
        print("\n›‘ Sniffing stopped by user.")
    except Exception as e:
        print(f" Error: {e}")

if __name__ == "__main__":
    start_sniffer()