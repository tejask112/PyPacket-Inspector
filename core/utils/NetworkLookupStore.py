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
        },
        "eth_type": {
            "IPV4": 0x0800,
            "IPV6": 0x86DD,
            "ARP": 0x0806
        }
    },

    TRANSPORT_PROTOCOL = {
        "TCP": 6,
        "UDP": 17,
        "ICMP": 1
    }

    ARP_CODES = {
        "REQUEST": 1,
        "REPLY": 2
    }

    DNS_CODES = {
        "PORTS": {53}
    }

    DNS_RECORDS = {
        "TYPES": {
            1:   "A",
            2:   "NS",
            5:   "CNAME",
            6:   "SOA",
            12:  "PTR",
            15:  "MX",
            16:  "TXT",
            28:  "AAAA",
            33:  "SRV",
            255: "ANY",
        },
        "CLASSES": {
            1: "IN",
            3: "CH", 
            4: "HS", 
        }
    }

    ICMP_CODES = {
        "ECHO_REPLY": 0,
        "ECHO_REQUEST": 8,
        "DEST_UNREACH": 3,
        "TIME_EXCEEDED": 11
    }

    def __init__(self):
        pass