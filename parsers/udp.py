import struct

def parse_udp(transport_data: bytes) -> dict:
    """
    Parse a UDP header from transport_data.
    UDP header is always exactly 8 bytes, everything after is payload.
    """

    if len(transport_data) < 8:
        raise ValueError(f"Captured UDP Header too short. Expected Minimum Length 8, Got Length {len(transport_data)}")

    src_port, dst_port, length, checksum = struct.unpack("!HHHH", transport_data[:8])

    return {
        "src_port": src_port,
        "dst_port": dst_port,
        "length": length,   
        "checksum": checksum,
        "payload": transport_data[8:]
    } 