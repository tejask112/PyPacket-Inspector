from datetime import datetime

from core.utils.NetworkLookupStore import NetworkLookupStore

class Renderer:
    
    show_detailed_info: bool

    def __init__(self, show_detailed_info: bool = False):
        self.show_detailed_info = show_detailed_info

    def render(self, packet) -> None:
        if (self.show_detailed_info):
            self._render_detailed_view(packet)
        else:
            self._render_compact_view(packet)

    # RENDERING TYPES
    def _render_detailed_view(self, packet):
        self._render_header(packet)
        self._render_network(packet)
        self._render_transport(packet)
        self._render_application(packet)

    def _render_compact_view(self, packet):
        timestamp = packet.timestamp.strftime("%H:%M:%S.%f")[:-3]
        num = packet.packet_number
        length = len(packet.raw_data)
        net = packet.network
        transport = packet.transport
        net_proto = packet.network_protocol
        trans_proto  = packet.transport_protocol
        app_proto = packet.application_protocol

        src_ip = net.get("src_ip", "?")
        dst_ip = net.get("dst_ip", "?")

        if trans_proto in ("TCP", "UDP"):
            src_port    = transport.get("src_port", "?")
            dst_port    = transport.get("dst_port", "?")
            proto_label = app_proto if app_proto else trans_proto

            if trans_proto == "TCP":
                flags = transport.get("flags", {})
                flags_str = "/".join(k for k, v in flags.items() if v)
                summary = f"{src_ip}:{src_port} -> {dst_ip}:{dst_port}  [{flags_str}]"
            else:
                summary = f"{src_ip}:{src_port} -> {dst_ip}:{dst_port}"

            # append domain name if DNS
            if app_proto == "DNS":
                dns = packet.application
                questions  = dns.get("questions", [])
                is_response = dns.get("flags", {}).get("is_response", False)
                name = questions[0].get("name") if questions else None

                if name:
                    label = "RSP" if is_response else "QRY"
                    summary += f"  {label}: {name}"

        elif trans_proto == "ICMP":
            proto_label = "ICMP"
            type_label  = transport.get("type_label", "?")
            summary = f"{src_ip} -> {dst_ip}  {type_label}"

        elif net_proto == "ARP":
            proto_label = "ARP"
            op = packet.network.get("op_label", "?").capitalize()
            sender_ip = packet.network.get("sender_ip", "?")
            target_ip = packet.network.get("target_ip", "?")
            summary = f"{op}  {sender_ip} -> {target_ip}"

        else:
            proto_label = net_proto or "UNKNOWN"
            summary = f"{src_ip} -> {dst_ip}"

        print(f"[{timestamp}]  #{num}  {net_proto}  {proto_label}  {length}B  {summary}")

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