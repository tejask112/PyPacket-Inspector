from datetime import datetime

from core.utils.NetworkLookupStore import NetworkLookupStore

class Renderer:

    def render(self, packet) -> None:
        self._render_header(packet)
        self._render_network(packet)
        # self._render_transport(packet)
        # self._render_application(packet)

    def _render_header(self, packet) -> None:
        timestamp = packet.timestamp.strftime("%H:%M:%S.%f")[:-3]
        
        eth = packet.ethernet
        ethertype = eth.get("ethertype")
        ethertype_str = NetworkLookupStore.ETHER_CODES.get(ethertype, "")
        ethertype_disp = f"0x{ethertype:04X}" if ethertype is not None else "Unknown"

        print(f"[{timestamp}] Packet #{packet.packet_number} | MAC {eth.get("src_mac")} \u2192 {eth.get("dst_mac")} (EtherType: {ethertype_disp} {ethertype_str})")   

