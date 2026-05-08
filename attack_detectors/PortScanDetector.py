from collections import defaultdict

class PortScanDetector:

    def __init__(self, scan_window, scan_threshold):
        """Instantiates an object with fixed window and threshold"""
        self.tracker = defaultdict(dict)  # { src_ip: { (dst_ip, dst_port): timestamp } }
        self.fired = set()
        self.scan_window = scan_window
        self.scan_threshold = scan_threshold

    def run_scan(self, packet) -> None:
        """Updates sliding window with new packet then checks for port scan attack"""
        if packet.network_protocol not in ("IPv4", "IPv6"):
            return
        if packet.transport_protocol not in ("UDP", "TCP"):
            return
        
        curr_time = packet.timestamp
        src_ip = packet.network.get("src_ip")
        dst_port = packet.network.get("dst_port")

        if not (src_ip and dst_port):
            return
    
        self._update_tracker(curr_time, src_ip, dst_port)
        self._check_port_scan(src_ip)
        self._check_dns_tunnelling()
        

    def _update_tracker(self, curr_time, src_ip, dst_port) -> None:
        """Updates tracker dictionary with new object, and removes data from older timestamps"""
        
        kept = {
            port: timestamp for port, timestamp in self.tracker[src_ip].items() 
            if (curr_time - timestamp).total_seconds() < self.scan_window
        }

        if len(kept) < self.scan_threshold:
            self.fired.discard(src_ip)

        kept[dst_port] = curr_time
        self.tracker[src_ip] = kept

    def _check_port_scan(self, src_ip) -> None:
        unique_ports = len(set(port for _, port in self.tracker[src_ip]))

        if unique_ports >= self.scan_threshold and src_ip not in self.fired:
            print(f" ⚠️  [ANOMALY] PORT SCAN ATTACK DETECTED: {src_ip} probed {unique_ports} ports in {self.scan_window}s")
            self.fired.add(src_ip)