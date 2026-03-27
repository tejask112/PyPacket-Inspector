import psutil

def get_network_info(socket, subprocess):
    hostname = socket.gethostname()
    ipv4 = get_local_ipv4(socket)
    ipv6 = get_local_ipv6(socket)
    ssid = get_ssid(subprocess)

    print(f"\nHostname: {hostname}")
    print(f"SSID: {ssid}")
    print(f"IPv4 Address: {ipv4}")
    print(f"IPv6 Address: {ipv6} (global)\n")
    
def get_local_ipv4(socket):
    open_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        open_socket.connect(("8.8.8.8", 80))
        return open_socket.getsockname()[0]
    except Exception as e:
        print("Could not get IPv4 Address")
    finally:
        open_socket.close()

def get_local_ipv6(socket):
    open_socket = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    try:
        open_socket.connect(("2001:4860:4860::8888", 80))
        return open_socket.getsockname()[0]
    except Exception as e:
        print("Could not get IPv6 Address")
    finally:
        open_socket.close()

def get_ssid(subprocess):
    try:
        return subprocess.check_output(["iwgetid", "-r"], text=True).strip()
    except Exception:
        print("Could not get SSID")

def get_active_interfaces():
    interface_map_status = psutil.net_if_stats()
    interface_address_map = psutil.net_if_addrs()
    active_interfaces = []

    for name, status in interface_map_status.items():
        if name in interface_address_map and status.isup:
            active_interfaces.append(f" {name}")

    return active_interfaces