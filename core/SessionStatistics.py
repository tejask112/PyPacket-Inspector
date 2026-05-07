from collections import defaultdict, Counter
from datetime import datetime

from core.ParsedPacket import ParsedPacket


class SessionStatistics:
    """
    Passively collects packet-capture statistics throughout a session and
    renders a formatted summary report on demand.

    The class accepts ParsedPacket objects directly — the caller does not
    need to extract anything. Just hand the packet over with record_packet()
    and call render_statistics() at the end (typically on Ctrl-C).
    """

    def __init__(self):
        self.start_time = None
        self.end_time = None

        self.total_packets = 0
        self.total_bytes = 0

        self.protocol_counts = defaultdict(int)

        self.bytes_sent = defaultdict(int)
        self.bytes_received = defaultdict(int)
        self.packets_per_ip = defaultdict(int)

        self.dns_query_count = 0
        self.dns_queries = defaultdict(int)
        self.dns_resolved = defaultdict(set)
        self.dns_query_log = []   # list of (domain, timestamp, src_port)

    def record_packet(self, packet: ParsedPacket) -> None:
        """Record a ParsedPacket. All field extraction happens here."""
        ts = self._to_epoch(packet.timestamp)
        if self.start_time is None:
            self.start_time = ts
        self.end_time = ts

        length = len(packet.raw_data) if packet.raw_data else 0
        network = packet.network or {}
        transport = packet.transport or {}
        application = packet.application or {}

        protocol = packet.transport_protocol or packet.network_protocol or "UNKNOWN"

        src_ip = network.get("src_ip") or network.get("sender_ip")
        dst_ip = network.get("dst_ip") or network.get("target_ip")

        self.total_packets += 1
        self.total_bytes += length
        self.protocol_counts[protocol] += 1

        if src_ip:
            self.bytes_sent[src_ip] += length
            self.packets_per_ip[src_ip] += 1
        if dst_ip:
            self.bytes_received[dst_ip] += length
            self.packets_per_ip[dst_ip] += 1

        if packet.application_protocol == "DNS" and application:
            self._record_dns(application, transport, ts)

    @staticmethod
    def _to_epoch(value) -> float:
        if isinstance(value, datetime):
            return value.timestamp()
        return float(value)

    def _record_dns(self, application: dict, transport: dict, ts: float) -> None:
        flags = application.get("flags")     or {}
        questions = application.get("questions") or []
        answers = application.get("answers")   or []

        domain = questions[0].get("name") if questions else None
        if not domain:
            return

        if flags.get("is_response", False):
            for ans in answers:
                ans_type = ans.get("type")
                rdata = ans.get("rdata")
                if rdata and ans_type in ("A", "AAAA", 1, 28):
                    self.dns_resolved[domain].add(rdata)
        else:
            self.dns_query_count += 1
            self.dns_queries[domain] += 1
            self.dns_query_log.append((domain, ts, transport.get("src_port")))

    def _detect_parallel_queries(self, window_ms: int = None):
        """
        For each domain, find the largest cluster of queries that fall
        within window_ms of each other. Returns:
            [(domain, parallel_count, span_ms), ...]
        sorted by parallel_count desc. Only clusters of 2+ are included.
        """
        if window_ms is None:
            window_ms = 50

        by_domain = defaultdict(list)
        for domain, ts, _port in self.dns_query_log:
            by_domain[domain].append(ts)

        window_s = window_ms / 1000.0
        results = []

        for domain, timestamps in by_domain.items():
            timestamps.sort()

            best_count = 0
            best_span_ms = 0.0

            left = 0
            for right in range(len(timestamps)):
                while timestamps[right] - timestamps[left] > window_s:
                    left += 1
                count = right - left + 1
                if count > best_count:
                    best_count   = count
                    best_span_ms = (timestamps[right] - timestamps[left]) * 1000

            if best_count >= 2:
                results.append((domain, best_count, best_span_ms))

        results.sort(key=lambda x: x[1], reverse=True)
        return results

    @staticmethod
    def _human_bytes(n: int) -> str:
        if n < 1024:
            return f"{n} B"
        if n < 1024 * 1024:
            return f"{n / 1024:.2f} KB"
        return f"{n / (1024 * 1024):.2f} MB"


    def render_statistics(self) -> None:
        if self.start_time is None:
            print("\nNo packets captured.")
            return

        duration = round(self.end_time - self.start_time, 2)

        if duration > 0:
            avg_pps = round(self.total_packets / duration, 2)
            avg_kbps = round((self.total_bytes / duration) / 1024, 2)
        else:
            avg_pps = 0
            avg_kbps = 0

        start_str = datetime.fromtimestamp(self.start_time).strftime("%H:%M:%S")
        end_str = datetime.fromtimestamp(self.end_time).strftime("%H:%M:%S")

        print(" Interupt Identified")

        print("\n\nSession summary")
        print("--------------------------------------------------")
        print(f"Start time:          {start_str}")
        print(f"End time:            {end_str}")
        print(f"Duration:            {duration} seconds")
        print(f"Total packets:       {self.total_packets}")
        print(f"Total data:          {self._human_bytes(self.total_bytes)}")
        print(f"Average packets/sec: {avg_pps}")
        print(f"Average throughput:  {avg_kbps} KB/s")
        print()

        print("Protocol breakdown")
        print("--------------------------------------------------")
        self._print_protocol_table()
        print()

        print("Top talkers")
        print("--------------------------------------------------")
        self._print_top_talkers()
        print()

        print("DNS analysis")
        print("--------------------------------------------------")
        self._print_dns_analysis()


    def _print_protocol_table(self) -> None:
        sorted_protos = sorted(
            self.protocol_counts.items(),
            key=lambda kv: kv[1],
            reverse=True,
        )

        if not sorted_protos:
            print("No protocols found.")
            return

        for proto, count in sorted_protos:
            pct = (count / self.total_packets * 100) if self.total_packets else 0
            print(f"{proto}: {count} packets ({pct:.2f}%)")


    def _print_top_talkers(self) -> None:
        sections = [
            ("Bytes sent", Counter(self.bytes_sent).most_common(5), "bytes"),
            ("Bytes received", Counter(self.bytes_received).most_common(5), "bytes"),
            ("Total packets", Counter(self.packets_per_ip).most_common(5), "packets"),
        ]

        for title, items, kind in sections:
            print(title)

            if not items:
                print("  None")
            else:
                for i, (ip, value) in enumerate(items, 1):
                    if kind == "bytes":
                        value = self._human_bytes(value)
                    else:
                        value = f"{value} packets"

                    print(f"  {i}. {ip} - {value}")

            print()


    def _print_dns_analysis(self) -> None:
        print(f"Total queries:  {self.dns_query_count}")
        print(f"Unique domains: {len(self.dns_queries)}")
        print()

        print("Top queried domains")
        top_domains = Counter(self.dns_queries).most_common(10)

        if not top_domains:
            print("  None")
        else:
            for i, (domain, count) in enumerate(top_domains, 1):
                print(f"  {i}. {domain} - {count} queries")

        print()

        print("Parallel duplicate queries")
        parallel = self._detect_parallel_queries()

        if not parallel:
            print("  None detected")
        else:
            for domain, count, span_ms in parallel:
                print(f"  {domain} - {count} queries within {span_ms:.0f}ms")

        print()

        print("Resolved domains")
        resolved_domains = sorted(
            self.dns_resolved.keys(),
            key=lambda d: self.dns_queries.get(d, 0),
            reverse=True,
        )[:10]

        if not resolved_domains:
            print("  None found")
        else:
            for domain in resolved_domains:
                ips = ", ".join(sorted(self.dns_resolved[domain]))
                print(f"  {domain} -> {ips}")