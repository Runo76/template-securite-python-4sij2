def hello_world() -> str:
    """Hello world test function."""
    return "hello world"


def choose_interface() -> str:
    """Prompt user for a network interface, defaults to eth0."""
    try:
        iface = input("Interface reseau (defaut eth0): ").strip()
        return iface or "eth0"
    except Exception:
        return "eth0"


def choose_duration() -> int:
    """Ask for capture duration with h/min/m/s suffix support. Returns seconds."""
    try:
        raw = input("Duree de capture (ex: 30s, 2min, 1h) [defaut 60s]: ").strip().lower()
        if not raw:
            return 60
        if raw.endswith("h"):
            return int(raw[:-1]) * 3600
        if raw.endswith("min"):
            return int(raw[:-3]) * 60
        if raw.endswith("m"):
            return int(raw[:-1]) * 60
        if raw.endswith("s"):
            return int(raw[:-1])
        return int(raw) * 60
    except (ValueError, Exception):
        return 60


def choose_packet_count() -> int:
    """Ask how many packets to capture. 0 = no limit."""
    try:
        raw = input("Nombre max de paquets (0 = illimite) [defaut 0]: ").strip()
        return int(raw) if raw else 0
    except (ValueError, Exception):
        return 0


PROTO_MAP = {
    1: "ICMP",
    2: "IGMP",
    6: "TCP",
    17: "UDP",
    47: "GRE",
}


def proto_name(proto_num) -> str:
    """Convert protocol number to readable name. Returns UNKNOWN for unmapped values."""
    try:
        return PROTO_MAP.get(int(proto_num), "UNKNOWN")
    except (ValueError, TypeError):
        return "UNKNOWN"
