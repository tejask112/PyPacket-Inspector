
from datetime import datetime
import subprocess

from .network_info import get_network_info

def start_sniffing(socket):
    interface="wlo1"
    
    open_socket = socket.socket(
        socket.AF_PACKET,
        socket.SOCK_RAW,
        socket.htons(0x0003)
    )

    open_socket.bind((interface, 0))
    open_socket.setsockopt(socket.SOL_SOCKET, 8, 1)

    print("\nSniffing...")

    while True:
        raw_data, address = open_socket.recvfrom(65535)
        timestamp = datetime.now().strftime('%H:%M:%S.%f')[:-3]

        print(f"[{timestamp}] | {address} | {raw_data}")