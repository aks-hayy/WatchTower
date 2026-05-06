import scapy.all as scapy
from scapy.layers.inet import IP, TCP

def create_ftp_pcap():
    packets = []
    
    # TCP Handshake (simplified)
    # SYN
    packets.append(IP(src="192.168.1.50", dst="10.0.0.5") / TCP(sport=1024, dport=21, flags="S"))
    # SYN-ACK
    packets.append(IP(src="10.0.0.5", dst="192.168.1.50") / TCP(sport=21, dport=1024, flags="SA"))
    # ACK
    packets.append(IP(src="192.168.1.50", dst="10.0.0.5") / TCP(sport=1024, dport=21, flags="A"))

    # FTP USER command
    packets.append(IP(src="192.168.1.50", dst="10.0.0.5") / TCP(sport=1024, dport=21, flags="PA") / "USER admin_user\r\n")
    
    # FTP PASS command
    packets.append(IP(src="192.168.1.50", dst="10.0.0.5") / TCP(sport=1024, dport=21, flags="PA") / "PASS supersecret123\r\n")

    # Write to file
    scapy.wrpcap("data/test_ftp.pcap", packets)
    print("Created data/test_ftp.pcap")

if __name__ == "__main__":
    create_ftp_pcap()
