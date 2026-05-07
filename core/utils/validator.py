import struct
import socket

def validate_ipv4_address(address):
    try:
        parts = address.split('.')
        return len(parts) == 4 and all(0 <= int(p) <= 255 and str(int(p)) == p for p in parts)
    except (ValueError, AttributeError):
        return False
    
def validate_ipv6_address(address):
    try:
        parts = address.split(':')
        if len(parts) != 8:
            return False
        return all(1 <= len(p) <= 4 and all(c in '0123456789abcdefABCDEF' for c in p) for p in parts)
    except AttributeError:
        return False
    
def validate_ipv4_cidr(address):
    try:
        ip, prefix = address.split('/')
        prefix = int(prefix)
        return validate_ipv4_address(ip) and 0 <= prefix <= 32
    except (ValueError, AttributeError):
        return False
    
def validate_ipv6_cidr(address):
    try:
        ip, prefix = address.split('/')
        prefix = int(prefix)
        return validate_ipv6_address(ip) and 0 <= prefix <= 128
    except (ValueError, AttributeError):
        return False
    
def validate_interfaces(active_interfaces):
    if len(active_interfaces) == 0:
        raise ConnectionError("No Network Interfaces identified. PyPacket Inspector cannot run.")

def ones_complement_sum(data):
    if len(data) % 2 != 0:
        data += b'\x00'

    total = 0
    for i in range(0, len(data), 2):
        total += (data[i] << 8) + data[i + 1]

    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)

    return ~total & 0xFFFF


def validate_ipv4_checksum(ip_data):
    ihl = (ip_data[0] & 0x0F) * 4
    header = ip_data[:ihl]
    return ones_complement_sum(header) == 0


def validate_icmp_checksum(transport_data):
    return ones_complement_sum(transport_data) == 0


def _build_ipv4_pseudo_header(network: dict, transport_length: int, protocol: int) -> bytes:
    src = socket.inet_aton(network["src_ip"])
    dst = socket.inet_aton(network["dst_ip"])
    return struct.pack("!4s4sBBH", src, dst, 0, protocol, transport_length)


def _build_ipv6_pseudo_header(network: dict, transport_length: int, protocol: int) -> bytes:
    src = socket.inet_pton(socket.AF_INET6, network["src_ip"])
    dst = socket.inet_pton(socket.AF_INET6, network["dst_ip"])
    return struct.pack("!16s16sI3xB", src, dst, transport_length, protocol)


def _detect_ip_version(network: dict) -> int:
    version = network.get("version")

    if version in (4, "4", "IPv4"):
        return 4

    if version in (6, "6", "IPv6"):
        return 6

    src_ip = network.get("src_ip", "")
    dst_ip = network.get("dst_ip", "")

    if ":" in src_ip or ":" in dst_ip:
        return 6

    if "." in src_ip or "." in dst_ip:
        return 4

    raise ValueError(f"Could not detect IP version from network dict: {network}")


def _build_pseudo_header(network: dict, transport_length: int, protocol: int) -> bytes:
    ip_version = _detect_ip_version(network)

    if ip_version == 4:
        return _build_ipv4_pseudo_header(network, transport_length, protocol)

    if ip_version == 6:
        return _build_ipv6_pseudo_header(network, transport_length, protocol)

    raise ValueError(f"Unsupported IP version: {ip_version}")


def validate_tcp_checksum(network: dict, transport_data: bytes) -> bool:
    pseudo = _build_pseudo_header(network, len(transport_data), 6)
    return ones_complement_sum(pseudo + transport_data) == 0


def validate_udp_checksum(network: dict, transport_data: bytes) -> bool:
    ip_version = _detect_ip_version(network)

    if ip_version == 4 and transport_data[6:8] == b'\x00\x00':
        return True

    pseudo = _build_pseudo_header(network, len(transport_data), 17)
    return ones_complement_sum(pseudo + transport_data) == 0