import math
from collections import defaultdict
from datetime import datetime


class BeaconingDetector:

    def __init__(self, min_samples: int = 10, max_interval_seconds: float = 300.0, jitter_tolerance: float = 0.3, max_history: int = 100):
        self.min_samples = min_samples
        self.max_interval_seconds = max_interval_seconds
        self.jitter_tolerance = jitter_tolerance
        self.max_history = max_history

        self._connection_times: dict[str, list[float]] = defaultdict(list)
        self._fired: set[str] = set()

    def run_scan(self, packet) -> None:
        if packet.network_protocol not in ("IPv4", "IPv6"):
            return

        dst_ip = packet.network.get("dst_ip")
        if not dst_ip:
            return

        ts = self._to_epoch(packet.timestamp)
        history = self._connection_times[dst_ip]
        history.append(ts)

        if len(history) > self.max_history:
            del history[:len(history) - self.max_history]

        if len(history) < self.min_samples:
            return

        if dst_ip in self._fired:
            return

        self._analyse(dst_ip, history)

    def _analyse(self, dst_ip: str, timestamps: list[float]) -> None:
        sorted_ts = sorted(timestamps)
        intervals = [sorted_ts[i + 1] - sorted_ts[i] for i in range(len(sorted_ts) - 1)]

        intervals = [d for d in intervals if d <= self.max_interval_seconds]
        if len(intervals) < self.min_samples - 1:
            return

        mean = self._mean(intervals)
        if mean == 0:
            return

        std_dev = self._std_dev(intervals, mean)
        cov = std_dev / mean

        if cov <= self.jitter_tolerance:
            self._alert(dst_ip, mean, std_dev, cov, len(timestamps))
            print(f" ⚠️  [ANOMALY] BEACONING DETECTED: {dst_ip} contacted {len(timestamps)} times at suspicious intervals")
            print(f"      Avg interval {round(mean, 2)}s, Std Deviation {round(std_dev, 2)}, Jitter (CoV) {round(cov, 2)}")
            self._fired.add(dst_ip)

    def _to_epoch(self, value) -> float:
        if isinstance(value, datetime):
            return value.timestamp()
        return float(value)

    def _mean(self, values: list[float]) -> float:
        return sum(values) / len(values)

    def _std_dev(self, values: list[float], mean: float) -> float:
        variance = sum((x - mean) ** 2 for x in values) / len(values)
        return math.sqrt(variance)