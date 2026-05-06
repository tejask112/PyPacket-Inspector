from datetime import datetime

from core.utils.NetworkLookupStore import NetworkLookupStore

class Renderer:

    def render(self, packet) -> None:
        self._render_header(packet)
        self._render_network(packet)
        self._render_transport(packet)
        # self._render_application(packet)

    # RENDER HEADER TXT
    def _render_header(self, packet) -> None:
        timestamp = packet.timestamp.strftime("%H:%M:%S.%f")[:-3]
        
        eth = packet.ethernet
        ethertype = eth.get("ethertype")
        ethertype_str = NetworkLookupStore.ETHER_CODES.get(ethertype, "")
        ethertype_disp = f"0x{ethertype:04X}" if ethertype is not None else "Unknown"

        print(f"[{timestamp}] Packet #{packet.packet_number} | IP {packet.network.get("src_ip")} \u2192 {packet.network.get("dst_ip")} (EtherType: {ethertype_disp} {ethertype_str})")   

    # RENDER LAYER 3 NETWORK TXT
    def _render_network(self, packet) -> None:
        protocol = packet.network_protocol

        if protocol == "IPv4":
            self._render_ipv4(packet.network)
        elif protocol == "IPv6":
            self._render_ipv6(packet.network)
        elif protocol == "ARP":
            self._render_arp(packet.network)

    def _render_ipv4(self, ip_datagram: dict) -> None:
        protocol = ip_datagram.get("protocol")
        protocol_str = NetworkLookupStore.IP_PROTOCOLS.get(protocol, "UKNOWN")

        flags_val = ip_datagram.get("flags", 0)
        flags_str = _format_ipv4_flags(flags_val)

        print("IPv4")
        print(f"  Version: {ip_datagram.get('version')}")
        print(f"  Header Length: {ip_datagram.get('ihl')} bytes")
        print(f"  Total Length: {ip_datagram.get('total_length')}")
        print(f"  Identification: 0x{ip_datagram.get('identification', 0):04x}")
        print(f"  Flags: {flags_str}")
        print(f"  Fragment Offset: {ip_datagram.get('fragment_offset')}")
        print(f"  TTL: {ip_datagram.get('ttl')}")
        print(f"  Protocol: {protocol_str} ({protocol})")
        print(f"  Header Checksum: 0x{ip_datagram.get('checksum', 0):04x}")
        print(f"  Src IP: {ip_datagram.get('src_ip')}")
        print(f"  Dst IP: {ip_datagram.get('dst_ip')}")
        print()

    def _render_ipv6(self, ip: dict) -> None:
        next_header = ip.get("next_header", 0)
        next_header_str = NetworkLookupStore.IP_PROTOCOLS.get(next_header, "UKNOWN")

        print("IPv6")
        print(f"  Version: {ip.get('version')}")
        print(f"  Traffic Class: {ip.get('traffic_class')}")
        print(f"  Flow Label: 0x{ip.get('flow_label', 0):05x}")
        print(f"  Payload Length: {ip.get('payload_length')}")
        print(f"  Next Header: {next_header_str} ({next_header})")
        print(f"  Hop Limit: {ip.get('hop_limit')}")
        print(f"  Src IP: {ip.get('src_ip')}")
        print(f"  Dst IP: {ip.get('dst_ip')}")
        print()

    def _render_arp(self, arp: dict) -> None:
        print("ARP")
        print(f"  Hardware Type: {'Ethernet' if arp.get('htype') == 1 else arp.get('htype')}")
        print(f"  Protocol Type: {'IPv4' if arp.get('ptype') == 0x0800 else arp.get('ptype')}")
        print(f"  Opcode: {arp.get('op_label', 'N/A').capitalize()}")
        print(f"  Sender MAC: {arp.get('sender_mac')}")
        print(f"  Sender IP: {arp.get('sender_ip')}")
        print(f"  Target MAC: {arp.get('target_mac')}")
        print(f"  Target IP: {arp.get('target_ip')}")
        print()

    # RENDER LAYER 4 TRANSPORT TXT
    def _render_transport(self, packet) -> None:
        proto = packet.transport_protocol

        if proto == "TCP":
            self._render_tcp(packet.transport)
        elif proto == "UDP":
            self._render_udp(packet.transport)
        elif proto == "ICMP":
            self._render_icmp(packet.transport)

    def _render_tcp(self, tcp: dict) -> None:
        src_port   = tcp.get("src_port", 0)
        dst_port   = tcp.get("dst_port", 0)
        flags_str  = _format_tcp_flags(tcp.get("flags", {}))
        offset     = tcp.get("data_offset", 20)

        print("TCP")
        print(f"  Src Port: {_format_port(src_port)}")
        print(f"  Dst Port: {_format_port(dst_port)}")
        print(f"  Seq: {tcp.get('sequence')}")
        print(f"  Ack: {tcp.get('acknowledgement')}")
        print(f"  Header Length: {offset} bytes")
        print(f"  Flags: {flags_str}")
        print(f"  Window Size: {tcp.get('window_size')}")
        print(f"  Checksum: 0x{tcp.get('checksum', 0):04x}")
        print()

    def _render_udp(self, udp: dict) -> None:
        src_port = udp.get("src_port", 0)
        dst_port = udp.get("dst_port", 0)

        print("UDP")
        print(f"  Src Port: {_format_port(src_port)}")
        print(f"  Dst Port: {_format_port(dst_port)}")
        print(f"  Length: {udp.get('length')}")
        print(f"  Checksum: 0x{udp.get('checksum', 0):04x}")
        print()

    def _render_icmp(self, icmp: dict) -> None:
        print("ICMP")
        print(f"  Type: {icmp.get('type')} ({icmp.get('type_label')})")
        print(f"  Code: {icmp.get('code')}")

        if "identifier" in icmp:
            print(f"  Identifier: 0x{icmp.get('identifier', 0):04x}")
            print(f"  Sequence: {icmp.get('sequence')}")

        print(f"  Checksum: 0x{icmp.get('checksum', 0):04x}")
        print()

    # RENDER LAYER 7 APPLICATION TXT
    def _render_application(self, packet) -> None:
        if packet.application_protocol == "DNS":
            self._render_dns(packet.application)

    def _render_dns(self, dns: dict) -> None:
        if not dns:
            return

        flags       = dns.get("flags", {})
        is_response = flags.get("is_response", False)
        msg_type    = "Response" if is_response else "Query"
        questions   = dns.get("questions", [])
        answers     = dns.get("answers", [])

        rcode     = flags.get("rcode", 0)
        rcode_str = _format_rcode(rcode)

        print("DNS")
        print(f"  Transaction ID: 0x{dns.get('transaction_id', 0):04x}")
        print(f"  Message Type: {msg_type}")

        if is_response:
            print(f"  Response Code: {rcode_str}")

        print(f"  Questions: {len(questions)}")
        print(f"  Answers: {len(answers)}")

        for q in questions:
            print(f"  Query Name: {q.get('name')}")
            print(f"  Record Type: {q.get('type')}")

        if answers:
            print("  Answer:")
            for a in answers:
                print(f"    {a.get('type')} {a.get('rdata')}")

        print()



# defining all helper functions
def _format_port(port: int) -> str:
    name = NetworkLookupStore.PORT_NAMES.get(port)
    return f"{port} ({name})" if name else str(port)


def _format_tcp_flags(flags: dict) -> str:
    active = [name for name, value in flags.items() if value]
    return ", ".join(active) if active else "None"


def _format_ipv4_flags(flags_val: int) -> str:
    parts = []
    if flags_val & 0x2:
        parts.append("DF")   # Don't Fragment
    if flags_val & 0x1:
        parts.append("MF")   # More Fragments
    return ", ".join(parts) if parts else "None"


def _format_rcode(rcode: int) -> str:
    return {
        0: "NOERROR",
        1: "FORMERR",
        2: "SERVFAIL",
        3: "NXDOMAIN",
        4: "NOTIMP",
        5: "REFUSED",
    }.get(rcode, f"UNKNOWN({rcode})")