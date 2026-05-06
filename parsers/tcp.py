import struct

def parse_tcp(transport_data: bytes) -> dict:
    """
    Parse a TCP header from transport_data.
    Data offset field determines header length, everything after is payload.
    """

    if len(transport_data) < 20:
        raise ValueError(f"Captured TCP Header too short. Expected Minimum Length 20, Got Length {len(transport_data)}")

    (
        src_port,
        dst_port,
        sequence,
        acknowledgement,
        offset_reserved,
        flags_raw,
        window_size,
        checksum,
        urgent_pointer
    ) = struct.unpack("!HHIIBBHHH", transport_data[:20])

    data_offset = (offset_reserved >> 4) * 4

    return {
        "src_port": src_port,
        "dst_port": dst_port,
        "sequence": sequence,
        "acknowledgement": acknowledgement,
        "data_offset": data_offset,
        "flags": _parse_flags(flags_raw),
        "window_size": window_size,
        "checksum": checksum,
        "urgent_pointer": urgent_pointer,
        "payload": transport_data[data_offset:] 
    }


def _parse_flags(flags_raw: int) -> dict:
    return {
        "URG": bool(flags_raw & 0x20),
        "ACK": bool(flags_raw & 0x10),
        "PSH": bool(flags_raw & 0x08),
        "RST": bool(flags_raw & 0x04),
        "SYN": bool(flags_raw & 0x02),
        "FIN": bool(flags_raw & 0x01),
    }