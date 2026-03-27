
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