from dataclasses import dataclass, field
from datetime import datetime

@dataclass
class ParsedPacket:
    """Holds a fully parsed Packet obj with all decoded layers attached."""

    packet_number: int
    timestamp: datetime
    raw_data: bytes

    ethernet: dict = field(default_factory=dict)
    network: dict = field(default_factory=dict)
    transport: dict = field(default_factory=dict)
    application: dict = field(default_factory=dict)

    network_protocol: str = ""
    transport_protocol: str = ""
    application_protocol: str = ""
