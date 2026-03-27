import socket
from datetime import datetime


def start_sniffing():
    interface="wlo1"
    
    open_socket = socket.socket(
        socket.AF_PACKET,
        socket.SOCK_RAW,
        socket.htons(0x0003)
    )

    open_socket.bind((interface, 0))
    open_socket.setsockopt(socket.SOL_SOCKET, 8, 1)

    print("Sniffing...")

    while True:
        raw_data, address = open_socket.recvfrom(65535)
        timestamp = datetime.now().strftime('%H:%M:%S.%f')[:-3]

        print(f"[{timestamp}] | {address} | {raw_data}")