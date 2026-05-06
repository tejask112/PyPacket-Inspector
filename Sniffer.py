from datetime import datetime

from core.utils.parser import parse_raw_data
from core.utils.NetworkLookupStore import NetworkLookupStore
from core.RawPacket import RawPacket


class Sniffer:
    """Sniff raw network packets from a given network interface."""

    def __init__(self, interface):
        """Instantiates a Sniffer object fixed to a specified network interface."""
        self.interface = interface
        self.NetworkLookupStore = NetworkLookupStore

    def start_sniffing(self, socket):
        """Opens a raw socket and continuously captures and prints each packet to terminal."""

        open_socket = socket.socket(
            socket.AF_PACKET,           # family: configures socket using Linux packet socket address family
            socket.SOCK_RAW,           # type: configures socket to capture raw packet data with headers included
            socket.htons(0x0003)           # protocol: configures socket to capture all ethernet packet types
        )
        open_socket.bind((self.interface, 0))
        open_socket.setsockopt(socket.SOL_SOCKET, 8, 1)

        print("\nSniffing...")    
        counter = 0

        try:    
            while True:
                raw_data, _ = open_socket.recvfrom(65535)
                timestamp = datetime.now()
                counter += 1

                raw_packet = RawPacket(
                    packet_number=counter,
                    timestamp=timestamp,
                    raw_data=raw_data
                )

                # parsed_packet = analyzer.analyze(raw_packet)
                # renderer.render(parsed_packet)  ← next step

                

        except KeyboardInterrupt:
            print("SUMMARY GOES HERE")
        finally:
            open_socket.close()