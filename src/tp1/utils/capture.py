import threading
import time
from collections import defaultdict

from scapy.all import sniff
from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import ARP

from tp1.utils.lib import choose_interface, choose_duration, choose_packet_count, proto_name
from tp1.utils.config import logger

SQL_KEYWORDS = [b"SELECT", b"INSERT", b"DROP", b"UNION", b"DELETE"]


class Capture:
    """Main capture class - handles sniffing, protocol stats and basic IDS detection."""

    def __init__(self) -> None:
        self.interface = choose_interface() or "eth0"
        self.duration = choose_duration()
        self.packet_count = choose_packet_count()

        self.packets = []
        self.proto_counter = defaultdict(int)
        self.ip_counter = defaultdict(int)
        self.ip_proto_map = defaultdict(set)
        self.ip_proto_counts = defaultdict(lambda: defaultdict(int))

        self.alerts = []
        self.alerts_by_proto = defaultdict(list)
        self.summary = ""

    def _track_ip(self, packet) -> None:
        """Update counters for an IP packet."""
        proto = proto_name(packet[IP].proto)
        self.proto_counter[proto] += 1
        for addr in (packet[IP].src, packet[IP].dst):
            self.ip_counter[addr] += 1
            self.ip_proto_map[addr].add(proto)
            self.ip_proto_counts[addr][proto] += 1

    def _track_arp(self, packet) -> None:
        """Update counters for an ARP packet."""
        self.proto_counter["ARP"] += 1
        for addr in (packet[ARP].psrc, packet[ARP].pdst):
            self.ip_counter[addr] += 1
            self.ip_proto_map[addr].add("ARP")
            self.ip_proto_counts[addr]["ARP"] += 1

    def _handle_packet(self, packet) -> None:
        """Per-packet callback: routes to tracker and runs IDS checks."""
        self.packets.append(packet)
        if IP in packet:
            self._track_ip(packet)
        elif ARP in packet:
            self._track_arp(packet)
        else:
            self.proto_counter["UNKNOWN"] += 1

        self._check_sqli(packet)
        self._check_arp_spoof(packet)

    def _check_sqli(self, packet) -> None:
        """Look for SQL injection keywords in TCP payloads."""
        if not packet.haslayer(TCP):
            return
        raw = bytes(packet[TCP].payload)
        if any(kw in raw.upper() for kw in SQL_KEYWORDS):
            src = packet[IP].src if IP in packet else "?"
            msg = f"[TCP] Possible SQLi depuis {src}"
            self.alerts.append(msg)
            self.alerts_by_proto["TCP"].append(msg)

    def _check_arp_spoof(self, packet) -> None:
        """Flag ARP packets where source IP equals destination IP."""
        if ARP in packet and packet[ARP].psrc == packet[ARP].pdst:
            msg = f"[ARP] Spoofing detecte - MAC {packet[ARP].hwsrc}  IP {packet[ARP].psrc}"
            self.alerts.append(msg)
            self.alerts_by_proto["ARP"].append(msg)

    def _show_progress(self, stop_evt: threading.Event) -> None:
        """Print live capture progress until stop event is set."""
        start = time.time()
        while not stop_evt.is_set():
            elapsed = time.time() - start
            left = max(0.0, float(self.duration) - elapsed)

            if left >= 3600:
                t = f"{int(left // 3600)}h{int((left % 3600) // 60)}m"
            elif left >= 60:
                t = f"{int(left // 60)}m{int(left % 60)}s"
            else:
                t = f"{int(left)}s"

            pkts = len(self.packets)
            limit = f"/{self.packet_count}" if self.packet_count > 0 else ""
            print(f"\r[*] {t} restant  -  {pkts}{limit} paquets  ", end="", flush=True)
            time.sleep(0.5)
        print()

    def capture_traffic(self) -> None:
        """Start packet capture on the selected interface."""
        logger.info(f"Capture sur {self.interface}")
        stop_evt = threading.Event()
        t = threading.Thread(target=self._show_progress, args=(stop_evt,), daemon=True)
        t.start()
        try:
            sniff(
                iface=self.interface,
                prn=self._handle_packet,
                count=self.packet_count,
                timeout=self.duration,
            )
        finally:
            stop_evt.set()
            t.join()

    def sort_network_protocols(self) -> dict:
        """Return protocol counts sorted by volume, descending."""
        return dict(sorted(self.proto_counter.items(), key=lambda x: x[1], reverse=True))

    def get_all_protocols(self) -> dict:
        """Return the raw protocol counter dict."""
        return dict(self.proto_counter)

    def get_proto_analysis(self) -> dict:
        """Return per-protocol status (OK or SUSPICIOUS) with associated alerts."""
        return {
            proto: {
                "count": count,
                "status": "SUSPICIOUS" if self.alerts_by_proto.get(proto) else "OK",
                "alerts": self.alerts_by_proto.get(proto, []),
            }
            for proto, count in self.proto_counter.items()
        }

    def analyse(self, protocols: str = "") -> None:
        """Run post-capture analysis and generate the summary text."""
        logger.debug(f"Protocoles detectes : {self.get_all_protocols()}")
        self.summary = self._gen_summary()

    def get_summary(self) -> str:
        """Return summary built by analyse()."""
        return self.summary

    def _gen_summary(self) -> str:
        """Build a readable text overview of the capture results."""
        lines = [
            "=== RAPPORT IDS ===\n",
            f"Interface : {self.interface}",
            f"Paquets captures : {len(self.packets)}\n",
            "Protocoles detectes :",
            f"{'Protocole':<12} {'Paquets':>8}",
            "-" * 22,
        ]

        for proto, count in self.sort_network_protocols().items():
            lines.append(f"{proto:<12} {count:>8}")

        lines += [
            "\nRepartition par IP :",
            f"{'Adresse IP':<20} {'Paquets':>8}  Protocoles",
            "-" * 52,
        ]
        for ip, count in sorted(self.ip_counter.items(), key=lambda x: x[1], reverse=True):
            details = ", ".join(
                f"{p}:{c}" for p, c in sorted(self.ip_proto_counts.get(ip, {}).items())
            )
            lines.append(f"{ip:<20} {count:>8}  {details}")

        lines.append("\nAnalyse du trafic :")
        if self.alerts:
            lines.extend(self.alerts)
        else:
            lines.append("Aucune activite suspecte detectee.")

        return "\n".join(lines) + "\n"
