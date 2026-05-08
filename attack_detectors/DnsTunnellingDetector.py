import math
from collections import Counter

class DnsTunnellingDetector:

    def __init__(self, high_entropy_threshold, length_subdomain_threshold):
        self.high_entropy_threshold = high_entropy_threshold
        self.length_subdomain_threshold = length_subdomain_threshold

    def run_scan(self, packet) -> None:
        if packet.application_protocol != "DNS":
            return
 
        questions = packet.application.get("questions") or []
        if not questions:
            return
 
        query = questions[0].get("name")
        if not query:
            return
 
        parts = query.rstrip('.').split('.')
        if len(parts) < 3:
            return
        
        subdomain = '.'.join(parts[:-2])
        entropy = self._shannon_entropy(subdomain.replace('.', ''))

        if len(subdomain) > self.length_subdomain_threshold:
            print(f" ⚠️  [ANOMALY] DNS TUNNEL SUSPECTED: {query} subdomain exceeds {self.length_subdomain_threshold} characters. Device may be compromised")

        if entropy > self.high_entropy_threshold:
            print(f" ⚠️  [ANOMALY] DNS TUNNEL SUSPECTED: {query} entropy ({round(entropy, 2)}) exceeds {self.high_entropy_threshold} threshold. Device may be compromised")


    def _shannon_entropy(self, query) -> float:
        if not query:
            return 0
        
        counts = Counter(query)
        length = len(query)
        return -sum((count / length) * math.log2(count / length) for count in counts.values())