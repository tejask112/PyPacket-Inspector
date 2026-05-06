from dataclasses import dataclass


from ParsedPacket import ParsedPacket
from utils.NetworkLookupStore import NetworkLookupStore

from ..parsers.ethernet import parse_ethernet

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
    

    """ 
    LAYER 2 - ETHERNET decoder 
    """
    def _parse_ethernet(self, parsed_packet: ParsedPacket):
        parsed_packet.ethernet = parse_ethernet(self, parsed_packet.raw_data)
        ethertype = parsed_packet.ethernet.get("ethertype")

        if ethertype == NetworkLookupStore.ADDRESS_PART["eth_type"].get("IPV4"):
            parsed_packet.network_protocol = "IPv4"
            self._parse_ipv4(parsed_packet)

        elif ethertype == NetworkLookupStore.ADDRESS_PART["eth_type"].get("IPV6"):
            parsed_packet.network_protocol = "IPv6"
            self._parse_ipv6(parsed_packet)

        elif ethertype == NetworkLookupStore.ADDRESS_PART["eth_type"].get("ARP"):
            parsed_packet.network_protocol = "ARP"
            self._parse_arp(parsed_packet)



