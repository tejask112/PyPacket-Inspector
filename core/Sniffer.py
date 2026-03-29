from datetime import datetime

from .utils.parser import parse_address, parse_raw_data
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

        counter = 0

        while True: 
            counter += 1
            raw_data, address = open_socket.recvfrom(65535)
            timestamp = datetime.now().strftime('%H:%M:%S.%f')[:-3]

            ## TODO: turn it into a class so it returns an object so i can individually access each part rather
            ## than having a function that returns lots of messy variables
            destination_mac_addr, source_mac_addr, ether_type = parse_raw_data(raw_data, NetworkLookupStore)

            # print(f"[{timestamp}] | {address} | {raw_data}")
            print(f"[{timestamp}] | {counter} ")
            print(f"    Source MAC Address: {source_mac_addr}")
            print(f"    Destination MAC Address: {destination_mac_addr}")
            print(f"    Ether Type: {ether_type}")


            


    
