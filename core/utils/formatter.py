
def mac_to_str(mac_bytes):
    return ':'.join(f'{b:02x}' for b in mac_bytes)