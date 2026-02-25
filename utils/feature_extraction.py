# utils/feature_extraction.py — Feature extraction from network data
import random
import datetime

PROTOCOLS  = ["TCP", "UDP", "ICMP"]
SERVICES   = ["http", "ftp", "ssh", "smtp", "dns", "telnet", "https"]
FLAGS      = ["SF", "S0", "REJ", "RSTO", "SH"]
ATTACK_POOL = (
    ["normal"] * 50 +
    ["dos"] * 15 +
    ["probe"] * 10 +
    ["r2l"] * 8 +
    ["u2r"] * 4 +
    ["ddos"] * 8 +
    ["brute_force"] * 5
)

FEATURE_COLUMNS = [
    "duration", "protocol_type", "service", "flag", "src_bytes",
    "dst_bytes", "land", "wrong_fragment", "urgent", "hot",
    "num_failed_logins", "logged_in", "num_compromised", "root_shell",
    "su_attempted", "num_root", "num_file_creations", "num_shells",
    "num_access_files", "num_outbound_cmds", "is_host_login",
    "is_guest_login", "count", "srv_count", "serror_rate",
    "srv_serror_rate", "rerror_rate", "srv_rerror_rate", "same_srv_rate",
    "diff_srv_rate", "srv_diff_host_rate", "dst_host_count",
    "dst_host_srv_count", "dst_host_same_srv_rate", "dst_host_diff_srv_rate",
    "dst_host_same_src_port_rate", "dst_host_srv_diff_host_rate",
    "dst_host_serror_rate", "dst_host_srv_serror_rate",
    "dst_host_rerror_rate", "dst_host_srv_rerror_rate",
]


def simulate_packet():
    """Generate a realistic simulated network packet dict."""
    return {
        "source_ip":   f"192.168.{random.randint(1,5)}.{random.randint(1,254)}",
        "dest_ip":     f"10.0.0.{random.randint(1,10)}",
        "source_port": random.randint(1024, 65535),
        "dest_port":   random.choice([80, 443, 22, 21, 23, 3306, 8080]),
        "protocol":    random.choice(PROTOCOLS),
        "timestamp":   datetime.datetime.utcnow(),
    }


def packet_to_features(packet: dict) -> list:
    """Convert packet dict → feature vector for ML model."""
    import numpy as np
    feat = [0.0] * len(FEATURE_COLUMNS)
    proto_map = {"TCP": 0, "UDP": 2, "ICMP": 1}
    feat[1] = float(proto_map.get(packet.get("protocol", "TCP"), 0))
    feat[4] = float(random.randint(0, 50000))   # src_bytes
    feat[5] = float(random.randint(0, 50000))   # dst_bytes
    feat[22] = float(random.randint(0, 512))    # count
    feat[23] = float(random.randint(0, 512))    # srv_count
    return feat
