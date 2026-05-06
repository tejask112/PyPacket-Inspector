import struct
import socket

from core.utils.NetworkLookupStore import NetworkLookupStore

def parse_arp(arp_data: bytes) -> dict:
    """   
    Parses the ARP packet from raw ARP data. Assumes standard Ethernet + IPv4 ARP (htype=1, ptype=0x0800).
    Returns:
        htype = hardware type
        ptype = protocol type
        hlen = hardware address length in bytes
        plen = protocol address length in bytes
        operation = ARP operation code
        op_label = human-readable ARP operation label
        sender_mac = sender hardware MAC address
        sender_ip = sender protocol IPv4 address
        target_mac = target hardware MAC address
        target_ip = target protocol IPv4 address
    """

    if len(arp_data) < 40:
        raise ValueError(f"Captured ARP Packet too short. Expected Minimum Length 28, Got Minimum Length {len(arp_data)}")

    (
        htype,          
        ptype,   
        hlen, 
        plen,        
        operation,
        sender_mac_raw,
        sender_ip_raw,
        target_mac_raw,
        target_ip_raw
    ) = struct.unpack("!HHBBH6s4s6s4s", arp_data[:28])

    return {
        "htype": htype,
        "ptype": ptype,
        "hlen": hlen,
        "plen": plen,
        "operation": operation,
        "op_label": _op_label(operation), #
        "sender_mac": _format_mac(sender_mac_raw),
        "sender_ip": socket.inet_ntoa(sender_ip_raw),
        "target_mac": _format_mac(target_mac_raw),
        "target_ip": socket.inet_ntoa(target_ip_raw),
    }


def _op_label(operation: int) -> str:
    return {
        NetworkLookupStore.ARP_CODES.get("REQUEST"): "REQUEST",
        NetworkLookupStore.ARP_CODES.get("REPLY"): "REPLY"
    }.get(operation, f"UNKNOWN({operation})")


def _format_mac(raw_mac: bytes) -> str:
    return ":".join(f"{byte:02x}" for byte in raw_mac)