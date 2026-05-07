from dataclasses import dataclass


from .ParsedPacket import ParsedPacket
from .utils.NetworkLookupStore import NetworkLookupStore
from .utils.validator import validate_ipv4_checksum, validate_tcp_checksum, validate_udp_checksum, validate_icmp_checksum

from parsers.ethernet import parse_ethernet
from parsers.ipv4 import parse_ipv4
from parsers.ipv6 import parse_ipv6
from parsers.arp import parse_arp
from parsers.tcp import parse_tcp
from parsers.udp import parse_udp
from parsers.icmp import parse_icmp
from parsers.dns import parse_dns

@dataclass
class Analyser:
    """
    Orchestrates the parsing of a RawPacket through all protocol layers.
    Returns:
        ParsedPacket = a ParsedPacket object containing all decoded layers from the RawPacket inputted.
    """

    def analyse(self, raw_packet) -> ParsedPacket:
        """
        Entry point for the Analyser class. It takes a RawPacket, parses each layer from the OSI model 
        in order and returns the fully populated ParsedPacket object.
        """
        
        parsed_packet = ParsedPacket(
            packet_number=raw_packet.packet_number,
            timestamp=raw_packet.timestamp,
            raw_data=raw_packet.raw_data
        )

        try:
            self._parse_ethernet(parsed_packet)
        except Exception as e:
            parsed_packet.ethernet = {"error": str(e)}

        return parsed_packet
    

    # LAYER 2 - ETHERNET decoder 
    def _parse_ethernet(self, parsed_packet: ParsedPacket):
        parsed_packet.ethernet = parse_ethernet(parsed_packet.raw_data)
        ethertype = parsed_packet.ethernet.get("ethertype")

        if ethertype == NetworkLookupStore.ETHER_TYPES.get("IPV4"):
            parsed_packet.network_protocol = "IPv4"
            self._parse_ipv4(parsed_packet)

        elif ethertype == NetworkLookupStore.ETHER_TYPES.get("IPV6"):
            parsed_packet.network_protocol = "IPv6"
            self._parse_ipv6(parsed_packet)

        elif ethertype == NetworkLookupStore.ETHER_TYPES.get("ARP"):
            parsed_packet.network_protocol = "ARP"
            self._parse_arp(parsed_packet)


    # LAYER 3 - NETWORK decoder 
    def _parse_ipv4(self, parsed_packet: ParsedPacket):
        ip_data = parsed_packet.raw_data[14:]
        parsed_packet.network = parse_ipv4(ip_data)
        parsed_packet.network["checksum_valid"] = validate_ipv4_checksum(ip_data)

        protocol = parsed_packet.network.get("protocol")
        ihl = parsed_packet.network.get("ihl", 20)

        total_length = parsed_packet.network.get("total_length", len(ip_data))
        transport_data = ip_data[ihl:total_length]

        if protocol == NetworkLookupStore.TRANSPORT_PROTOCOL.get("TCP"):
            parsed_packet.transport_protocol = "TCP"
            self._parse_tcp(parsed_packet, transport_data)
            parsed_packet.transport["checksum_valid"] = validate_tcp_checksum(parsed_packet.network, transport_data)
            

        elif protocol == NetworkLookupStore.TRANSPORT_PROTOCOL.get("UDP"):
            parsed_packet.transport_protocol = "UDP"
            self._parse_udp(parsed_packet, transport_data)
            parsed_packet.transport["checksum_valid"] = validate_udp_checksum(parsed_packet.network, transport_data)


        elif protocol == NetworkLookupStore.TRANSPORT_PROTOCOL.get("ICMP"):
            parsed_packet.transport_protocol = "ICMP"
            self._parse_icmp(parsed_packet, transport_data)
            parsed_packet.transport["checksum_valid"] = validate_icmp_checksum(transport_data)


    def _parse_ipv6(self, parsed_packet: ParsedPacket):
        ip_data = parsed_packet.raw_data[14:]
        parsed_packet.network = parse_ipv6(ip_data)

        next_header    = parsed_packet.network.get("next_header")
        payload_length = parsed_packet.network.get("payload_length", len(ip_data) - 40)

        transport_data = ip_data[40:40 + payload_length]

        if next_header == NetworkLookupStore.TRANSPORT_PROTOCOL.get("TCP"):
            parsed_packet.transport_protocol = "TCP"
            self._parse_tcp(parsed_packet, transport_data)
            parsed_packet.transport["checksum_valid"] = validate_tcp_checksum(parsed_packet.network, transport_data)

        elif next_header == NetworkLookupStore.TRANSPORT_PROTOCOL.get("UDP"):
            parsed_packet.transport_protocol = "UDP"
            self._parse_udp(parsed_packet, transport_data)
            parsed_packet.transport["checksum_valid"] = validate_udp_checksum(parsed_packet.network, transport_data)

        elif next_header == NetworkLookupStore.TRANSPORT_PROTOCOL.get("ICMP"):
            parsed_packet.transport_protocol = "ICMP"
            self._parse_icmp(parsed_packet, transport_data)

    def _parse_arp(self, parsed: ParsedPacket):
        arp_data = parsed.raw_data[14:]
        parsed.network = parse_arp(arp_data)

    # LAYER 4 - TRANSPORT decoder 
    def _parse_tcp(self, parsed_packet: ParsedPacket, transport_data: bytes):
        parsed_packet.transport = parse_tcp(transport_data)

        src_port = parsed_packet.transport.get("src_port")
        dst_port = parsed_packet.transport.get("dst_port")
        payload = parsed_packet.transport.get("payload", b"")

        ports = NetworkLookupStore.DNS_CODES.get("PORTS")
        if src_port in ports or dst_port in ports:
            parsed_packet.application_protocol = "DNS"
            self._parse_dns(parsed_packet, payload)

    def _parse_udp(self, parsed_packet: ParsedPacket, transport_data: bytes):
        parsed_packet.transport = parse_udp(transport_data)

        src_port = parsed_packet.transport.get("src_port")
        dst_port = parsed_packet.transport.get("dst_port")
        payload = parsed_packet.transport.get("payload", b"")

        ports = NetworkLookupStore.DNS_CODES.get("PORTS")
        if src_port in ports or dst_port in ports:
            parsed_packet.application_protocol = "DNS"
            self._parse_dns(parsed_packet, payload)

    def _parse_icmp(self, parsed: ParsedPacket, transport_data: bytes):
        parsed.transport = parse_icmp(transport_data)


    # LAYER 7 - APPLICATION decoder 
    def _parse_dns(self, parsed: ParsedPacket, payload: bytes):
        if payload:
            parsed.application = parse_dns(payload)