import struct 

from .formatter import mac_to_str

def parse_address(address, NetworkLookupStore):
    
    """
        iface = interface in use (e.g. wlan0, eth0)
        proto = ethernet protocol (e.g. IPv4, IPv6)
        pkt_type = where the packet is going (e.g. 0=to us, 4=outgoing from us)
        hatype = hardware address type (e.g. 1 for WiFI/Ethernet)
        mac_bytes = MAC address of sender (source).
    """

    iface, proto, pkt_type, hatype, mac_bytes = address

    mac_address = mac_to_str(mac_bytes)
    protocol = NetworkLookupStore.ADDRESS_PART["proto"].get(proto)
    packet_type = NetworkLookupStore.ADDRESS_PART["pkt_type"].get(pkt_type)
    hardware_address_type = NetworkLookupStore.ADDRESS_PART["pkt_type"].get(hatype)

    return iface, mac_address, protocol, packet_type, hardware_address_type

def parse_raw_data(data, NetworkLookupStore):
    destination_mac_addr = mac_to_str(data[0:6])
    source_mac_addr = mac_to_str(data[6:12])
    ether_type = NetworkLookupStore.ADDRESS_PART["proto"].get(struct.unpack('!H', data[12:14])[0])
    payload = data[14:]

    return destination_mac_addr, source_mac_addr, ether_type, payload

def get_protocol(data, NetworkLookupStore):
    pass