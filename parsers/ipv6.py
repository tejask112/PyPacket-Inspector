import struct
import socket

def parse_ipv6(ip_data: bytes) -> dict:
    """
    Parses the IPv6 header from raw packet data.
    Returns:
        version = ip version number
        traffic_class = traffic class field
        flow_label = ipv6 flow label
        payload_length = length of the payload in bytes
        next_header = next header protocol number
        hop_limit = hop limit value (same as ttl in ipv4)
        src_ip = source ip address
        dst_ip = destination ip address
    """

    if len(ip_data) < 40:
        raise ValueError(f"Captured IP Datagram too short. Expected Minimum Length 40, Got Length {len(ip_data)}")
    

    (
        version_tc_fl,
        payload_length,
        next_header,
        hop_limit,
        src_ip_raw,
        dst_ip_raw
    ) = struct.unpack("!IHBB16s16s", ip_data[:40])

    version = (version_tc_fl >> 28) & 0xF        
    traffic_class = (version_tc_fl >> 20) & 0xFF    
    flow_label = (version_tc_fl & 0xFFFFF)
 
    return {
        "version": version,
        "traffic_class": traffic_class,
        "flow_label": flow_label,
        "payload_length": payload_length, 
        "next_header": next_header,     
        "hop_limit": hop_limit,       
        "src_ip": socket.inet_ntop(socket.AF_INET6, src_ip_raw),
        "dst_ip": socket.inet_ntop(socket.AF_INET6, dst_ip_raw),
    }