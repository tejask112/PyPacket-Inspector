from attack_detectors.PortScanDetector import PortScanDetector
from attack_detectors.DnsTunnellingDetector import DnsTunnellingDetector
from attack_detectors.BeaconingDetector import BeaconingDetector

class AnomalyDetector:

    def __init__(self, scan_window, scan_threshold, high_entropy_threshold, length_subdomain_threshold):
        self.port_scan_detector = PortScanDetector(scan_window=scan_window, scan_threshold=scan_threshold)
        self.dns_tunnelling_detector = DnsTunnellingDetector(high_entropy_threshold=high_entropy_threshold, length_subdomain_threshold=length_subdomain_threshold)
        self.beaconing_detector = BeaconingDetector()

    def run_scan(self, packet) -> None:
        self.port_scan_detector.run_scan(packet)
        self.dns_tunnelling_detector.run_scan(packet)
        self.beaconing_detector.run_scan(packet)