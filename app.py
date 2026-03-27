from visuals.title_text import display_title

from core.filters import input_filters
from core.sniffer import start_sniffing

def start_app():

    display_title()
    input_filters()

    start_sniffing()


if __name__ == "__main__":
    start_app()