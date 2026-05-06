import struct

from core.utils.NetworkLookupStore import NetworkLookupStore

def parse_icmp(transport_data: bytes) -> dict:
    """
    Parse an ICMP header from transport_data.
    First 4 bytes are always type/code/checksum, remaining fields vary by type.
    """

    if len(transport_data) < 4:
        raise ValueError(f"Captured ICMP Header too short. Expected Minimum Length 4, Got Length {len(transport_data)}")

    icmp_type, code, checksum = struct.unpack("!BBH", transport_data[:4])

    result = {
        "type": icmp_type,
        "type_label": _type_label(icmp_type),
        "code": code,
        "checksum": checksum,
    }

    ECHO_REQUEST = NetworkLookupStore.ICMP_CODES.get("ECHO_REQUEST")
    ECHO_REPLY = NetworkLookupStore.ICMP_CODES.get("ECHO_REPLY")
    DEST_UNREACH = NetworkLookupStore.ICMP_CODES.get("DEST_UNREACH")
    TIME_EXCEEDED = NetworkLookupStore.ICMP_CODES.get("TIME_EXCEEDED")

    if icmp_type in (ECHO_REQUEST, ECHO_REPLY) and len(transport_data) >= 8:
        identifier, sequence = struct.unpack("!HH", transport_data[4:8])
        result["identifier"] = identifier
        result["sequence"] = sequence
        result["payload"] = transport_data[8:]

    elif icmp_type in (DEST_UNREACH, TIME_EXCEEDED) and len(transport_data) >= 8:
        result["original_ip_header"] = transport_data[8:]

    else:
        result["payload"] = transport_data[4:]

    return result


def _type_label(icmp_type: int) -> str:
    return {
        NetworkLookupStore.ICMP_CODES.get("ECHO_REPLY"): "ECHO REPLY",
        NetworkLookupStore.ICMP_CODES.get("ECHO_REQUEST"): "ECHO REQUEST",
        NetworkLookupStore.ICMP_CODES.get("DEST_UNREACH"): "DESTINATION UNREACHABLE",
        NetworkLookupStore.ICMP_CODES.get("TIME_EXCEEDED"): "TIME EXCEEDED",
    }.get(icmp_type, f"UNKNOWN({icmp_type})")