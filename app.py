import socket
import subprocess

from visuals.title_text import display_title

from core.filters import input_filters
from core.network_info import get_network_info, get_active_interfaces
from core.sniffer import start_sniffing

def start_app():

    display_title()
    get_network_info(socket, subprocess)

    active_interfaces = get_active_interfaces()
    input_filters(active_interfaces)

    try:
        start_sniffing(socket)
    except KeyboardInterrupt:
        print("Goodbye!")


if __name__ == "__main__":
    start_app()