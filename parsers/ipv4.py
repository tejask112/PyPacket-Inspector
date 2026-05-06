import struct
import socket

def parse_ipv4(ip_data: bytes) -> dict:
    """
    Parses the IPv4 header from raw packet data.
    Returns:
        version = ip version number
        ihl = internet header length in bytes
        dscp_ecn = differentiated services and explicit congestion notification field
        total_length = total ip packet length in bytes
        identification = packet identification value used for fragmentation
        flags = ip fragmentation flags
        fragment_offset = fragment offset value
        ttl = time to live value
        protocol = encapsulated transport-layer protocol number
        checksum = ipv4 header checksum
        src_ip = source ip address
        dst_ip = destination ip address
    """

    if len(ip_data) < 20:
        raise ValueError(f"Captured IP Datagram too short. Expected Minimum Length 20, Got Minimum Length {len(ip_data)}")
    
    (
        version_ihl,    # ihl = internet header length
        dscp_ecn,    # dscp = differentiated services code point, ecn = explicit congestion notification
        total_length,
        identification,
        flags_fragment,
        ttl,    # ttl = time to live
        protocol,
        checksum,
        src_ip_raw,
        dst_ip_raw
    ) = struct.unpack("!BBHHHBBH4s4s", ip_data[:20])

    version = (version_ihl >> 4)
    ihl = (version_ihl & 0x0F) * 4

    flags = (flags_fragment >> 13)
    fragment_offset = (flags_fragment & 0x1FFF)


    return {
        "version": version,
        "ihl": ihl,
        "dscp_ecn": dscp_ecn,
        "total_length": total_length,
        "identification": identification,
        "flags": flags,
        "fragment_offset": fragment_offset,
        "ttl": ttl,
        "protocol": protocol,  
        "checksum": checksum,
        "src_ip": socket.inet_ntoa(src_ip_raw),
        "dst_ip": socket.inet_ntoa(dst_ip_raw),
    }