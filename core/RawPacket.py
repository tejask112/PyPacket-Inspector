from dataclasses import dataclass, field
from datetime import datetime

@dataclass
class RawPacket:
    """Holds a raw packet captured directly from the socket"""

    packet_number: int
    timestamp: datetime
    raw_data: bytes
