
from scapy.all import Ether, IP, TCP, Raw, wrpcap
from scapy.contrib.ospf import OSPF_Hdr, OSPF_Hello

packets = []

# --------------------------------------------------
# 1. OSPF HELLO PACKET
# --------------------------------------------------
ospf_packet = (
    Ether() /
    IP(src="192.0.2.1", dst="224.0.0.5", proto=89) /
    OSPF_Hdr(version=2, type=1, src="192.0.2.1", area="0.0.0.0") /
    OSPF_Hello(
        mask="255.255.255.0",
        hellointerval=10,
        options=2,
        prio=1,
        deadinterval=40
    )
)

packets.append(ospf_packet)

# --------------------------------------------------
# 1B. OSPF LINK-STATE UPDATE WITH ONE ROUTER-LSA
# --------------------------------------------------

# OSPF header: version 2, type 4 (Link-State Update)
ospf_header = (
    b"\x02\x04" +
    (52).to_bytes(2, "big") +
    bytes([192, 0, 2, 1]) +       # Router ID
    bytes([0, 0, 0, 0]) +         # Area ID
    b"\x00\x00" +                 # Checksum placeholder
    b"\x00\x00" +                 # Authentication type
    b"\x00" * 8                   # Authentication data
)

# One Router-LSA
lsa_header = (
    b"\x00\x00" +                 # LS age
    b"\x02" +                     # Options
    b"\x01" +                     # LSA type: Router-LSA
    bytes([10, 0, 0, 1]) +        # Link-State ID
    bytes([192, 0, 2, 1]) +       # Advertising Router
    b"\x80\x00\x00\x01" +         # LSA sequence number
    b"\x00\x00" +                 # LSA checksum placeholder
    (24).to_bytes(2, "big")       # LSA length
)

# Router-LSA body: flags, reserved byte, link count = 0
lsa_body = b"\x00\x00\x00\x00"

# OSPF Update body: number of LSAs, followed by the LSA
ospf_ls_update = (
    ospf_header +
    (1).to_bytes(4, "big") +
    lsa_header +
    lsa_body
)

ospf_update_packet = (
    Ether() /
    IP(src="192.0.2.1", dst="224.0.0.5", proto=89) /
    Raw(load=ospf_ls_update)
)

packets.append(ospf_update_packet)



# Second OSPF update: same LSA identity, newer sequence number
lsa_header_v2 = (
    b"\x00\x00" +
    b"\x02" +
    b"\x01" +
    bytes([10, 0, 0, 1]) +
    bytes([192, 0, 2, 1]) +
    b"\x80\x00\x00\x02" +
    b"\x00\x00" +
    (24).to_bytes(2, "big")
)

ospf_ls_update_v2 = (
    ospf_header[:2] +
    (52).to_bytes(2, "big") +
    ospf_header[4:] +
    (1).to_bytes(4, "big") +
    lsa_header_v2 +
    lsa_body
)

ospf_update_packet_v2 = (
    Ether() /
    IP(src="192.0.2.1", dst="224.0.0.5", proto=89) /
    Raw(load=ospf_ls_update_v2)
)

packets.append(ospf_update_packet_v2)


# --------------------------------------------------
# 2. BGP MESSAGE DATA
# --------------------------------------------------
marker = b"\xff" * 16

# BGP OPEN: version 4, AS 65000, hold time 90
bgp_open_body = (
    b"\x04" +
    (65000).to_bytes(2, "big") +
    (90).to_bytes(2, "big") +
    bytes([192, 0, 2, 1]) +
    b"\x00"
)

bgp_open = (
    marker +
    (19 + len(bgp_open_body)).to_bytes(2, "big") +
    b"\x01" +
    bgp_open_body
)

# BGP NOTIFICATION: error code 2, subcode 1
notification_body = b"\x02\x01"

bgp_notification = (
    marker +
    (19 + len(notification_body)).to_bytes(2, "big") +
    b"\x03" +
    notification_body
)

# BGP UPDATE announcing 203.0.113.0/24
withdrawn_routes = b""

path_attributes = (
    b"\x40\x01\x01\x00" +
    b"\x40\x02\x04\x02\x01\xfd\xe8" +
    b"\x40\x03\x04\xc0\x00\x02\x01"
)

announced_routes = b"\x18\xcb\x00\x71"

update_body = (
    len(withdrawn_routes).to_bytes(2, "big") +
    withdrawn_routes +
    len(path_attributes).to_bytes(2, "big") +
    path_attributes +
    announced_routes
)

bgp_update = (
    marker +
    (19 + len(update_body)).to_bytes(2, "big") +
    b"\x02" +
    update_body
)

# --------------------------------------------------
# 3. TCP SESSION AND BGP PACKETS
# --------------------------------------------------
src_ip = "192.0.2.1"
dst_ip = "192.0.2.2"
src_port = 50000
dst_port = 179

client_seq = 1000
server_seq = 5000

def tcp_packet(seq, ack, flags, payload=b""):
    pkt = (
        Ether() /
        IP(src=src_ip, dst=dst_ip) /
        TCP(
            sport=src_port,
            dport=dst_port,
            seq=seq,
            ack=ack,
            flags=flags
        )
    )

    if payload:
        pkt = pkt / Raw(load=payload)

    return pkt

# TCP three-way handshake
packets.append(tcp_packet(client_seq, 0, "S"))
packets.append(
    Ether() /
    IP(src=dst_ip, dst=src_ip) /
    TCP(
        sport=dst_port,
        dport=src_port,
        seq=server_seq,
        ack=client_seq + 1,
        flags="SA"
    )
)
packets.append(tcp_packet(client_seq + 1, server_seq + 1, "A"))

# Send the synthetic BGP messages in sequence
current_seq = client_seq + 1

for message in (
    bgp_open,
    bgp_notification,
    bgp_update,
    bgp_update
):
    packets.append(
        tcp_packet(current_seq, server_seq + 1, "PA", message)
    )
    current_seq += len(message)

# Add a BGP UPDATE that withdraws 203.0.113.0/24
withdrawn_prefix = b"\x18\xcb\x00\x71"

withdraw_body = (
    len(withdrawn_prefix).to_bytes(2, "big")
    + withdrawn_prefix
    + b"\x00\x00"
)

bgp_withdraw = (
    marker
    + (19 + len(withdraw_body)).to_bytes(2, "big")
    + b"\x02"
    + withdraw_body
)

packets.append(
    tcp_packet(current_seq, server_seq + 1, "PA", bgp_withdraw)
)

# Re-announce the same prefix after withdrawal
packets.append(
    tcp_packet(
        current_seq + len(bgp_withdraw),
        server_seq + 1,
        "PA",
        bgp_update
    )
)

current_seq += len(bgp_withdraw) + len(bgp_update)

# Write capture file
wrpcap("test_capture.pcap", packets)

print("Created test_capture.pcap")
print("Total packets:", len(packets))
print("BGP OPEN length:", len(bgp_open))
print("BGP NOTIFICATION length:", len(bgp_notification))
print("BGP UPDATE length:", len(bgp_update))
print("Announced prefix: 203.0.113.0/24")
