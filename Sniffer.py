from datetime import datetime

from core.RawPacket import RawPacket
from core.Analyser import Analyser
from core.Render import Renderer
from core.PacketFilter import PacketFilter
from core.SessionStatistics import SessionStatistics
from core.AnomalyDetector import AnomalyDetector

class Sniffer:
    """Sniff raw network packets from a given network interface."""

    def __init__(self, interface, ip_filter, address_type_filter, address_type_value, show_detailed_info):
        """Instantiates a Sniffer object fixed to a specified network interface."""
        self.interface = interface
        self.packet_filter = PacketFilter(ip_filter=ip_filter, address_type_filter=address_type_filter, address_type_value=address_type_value)
        self.analyser = Analyser()
        self.renderer = Renderer(show_detailed_info=show_detailed_info)
        self.stats = SessionStatistics()
        self.detector = AnomalyDetector(scan_window=5, scan_threshold=10, length_subdomain_threshold=35, high_entropy_threshold=3.5)

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

                parsed_packet = self.analyser.analyse(raw_packet)

                if self.packet_filter.validate(parsed_packet):
                    self.renderer.render(parsed_packet)
                    self.stats.record_packet(parsed_packet)
                    self.detector.run_scan(parsed_packet)
                
        except KeyboardInterrupt:
            self.stats.render_statistics()
        finally:
            open_socket.close()