class NetworkLookupStore:
    
    ADDRESS_PART = {
        "proto": {
            2048: "IPv4",
            34525: "IPv6",
            2054: "ARP",
            33024: "VLAN"
        },
        "pkt_type": {
            0: "Incoming (to us)",
            1: "Broadcast",
            2: "Multicast",
            3: "Other (Promiscuous)",
            4: "Outgoing (from us)"
        },
        "hatype": {
            1: "Ethernet/WiFi",
            772: "Loopback",
            512: "PPP"
        }
    }

    def __init__(self):
        pass