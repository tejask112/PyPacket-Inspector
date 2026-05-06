import struct

def parse_ethernet(raw_data: bytes) -> dict:
    """
    Parses the first 14 bytes of a raw packet data to capture Ethernet frame headers
    Returns:
        dst_mac = destination mac address
        src_mac = source mac address
        ethertype = ether type
    """ 

    if len(raw_data) < 14:
        raise ValueError(f"Captured Data Packet too short to be an Ethernet Frame. Expected Minimum Length 14, Got Minimum Length {len(raw_data)}")
    
    dst_mac_raw, src_mac_raw, ethertype = struct.unpack("!6s6sH", raw_data[:14])
    # print(f"dst: {dst_mac_raw}, src: {src_mac_raw}, ethertype: {hex(ethertype)}")

    return {
        "dst_mac": _mac_to_str(dst_mac_raw),
        "src_mac": _mac_to_str(src_mac_raw),
        "ethertype": ethertype
    }

def _mac_to_str(mac_bytes):
    return ':'.join(f'{byte:02x}' for byte in mac_bytes)