from datetime import datetime

from .utils.parser import parse_address
from .NetworkLookupStore import NetworkLookupStore

class Sniffer:

    def __init__(self, interface):
        self.interface = interface
        self.NetworkLookupStore = NetworkLookupStore

    def start_sniffing(self, socket):
        open_socket = socket.socket(
            socket.AF_PACKET,
            socket.SOCK_RAW,
            socket.htons(0x0003)
        )

        open_socket.bind((self.interface, 0))
        open_socket.setsockopt(socket.SOL_SOCKET, 8, 1)

        print("\nSniffing...")

        while True: 
            raw_data, address = open_socket.recvfrom(65535)
            timestamp = datetime.now().strftime('%H:%M:%S.%f')[:-3]

            # print(f"[{timestamp}] | {address} | {raw_data}")

            


    
