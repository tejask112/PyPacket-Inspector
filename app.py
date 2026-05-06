import socket
import subprocess

from visuals.title_text import display_title

from core.filters import input_filters
from core.network_info import print_network_info, get_active_interfaces
from Sniffer import Sniffer

def start_app():
    """Entry-point to app."""

    display_title()
    print_network_info(socket, subprocess)

    active_interfaces = get_active_interfaces()
    interface_filter, ip_filter, address_type_filter, address_type_value, show_detailed_info = input_filters(active_interfaces)

    try:
        

        sniffer = Sniffer('wlo1')
        sniffer.start_sniffing(socket)
    except Exception:
        print("Exception Occured")


if __name__ == "__main__":
    start_app()