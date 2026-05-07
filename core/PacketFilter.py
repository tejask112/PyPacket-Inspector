import ipaddress


class PacketFilter:
    """Validates whether a parsed packet should be displayed based on active filters."""

    def __init__(self, ip_filter, address_type_filter, address_type_value):
        self.ip_filter = ip_filter          # None, "IPv4", "IPv6"
        self.address_type_filter = address_type_filter          # None, "Single IP", "Subnet"
        self.address_type_value  = address_type_value          # None, "192.168.1.1", "192.168.1.0/24"

    def validate(self, packet) -> bool:
        if not self._check_ip_version(packet):
            return False

        if not self._check_address(packet):
            return False

        return True

    def _check_ip_version(self, packet) -> bool:
        if self.ip_filter is None:
            return True
        return packet.network_protocol == self.ip_filter

    def _check_address(self, packet) -> bool:
        if self.address_type_filter in (None, "None"):
            return True

        src_ip = packet.network.get("src_ip")
        dst_ip = packet.network.get("dst_ip")

        if not src_ip or not dst_ip:
            return False

        if self.address_type_filter == "Single IP":
            return self.address_type_value in (src_ip, dst_ip)

        elif self.address_type_filter == "Subnet":
            try:
                subnet = ipaddress.ip_network(self.address_type_value, strict=False)
                return (ipaddress.ip_address(src_ip) in subnet or ipaddress.ip_address(dst_ip) in subnet)
            except ValueError:
                return False

        return True