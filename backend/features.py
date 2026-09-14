"""
Shared feature schema for the CICIDS2017-based intrusion detection model.

CICIDS2017 (CICFlowMeter output) has 78-84 flow-level columns depending on
which CSV you pull. Using all of them makes for a great model but an
unusable web form, so this project trains on a curated subset of the
features that are known (from the original CICIDS2017 paper and follow-up
feature-importance studies) to carry most of the signal. If you retrain on
the full column set, just update FEATURES below and both the training
script and the API will pick up the change automatically.
"""

# Column name -> (human label, unit hint, example benign value, example attack value)
FEATURES = {
    "Flow Duration":            ("Flow Duration",            "microseconds", 1200000, 45),
    "Total Fwd Packets":        ("Total Fwd Packets",        "packets",      12,      2000),
    "Total Backward Packets":   ("Total Backward Packets",   "packets",      10,      0),
    "Total Length of Fwd Packets": ("Total Fwd Bytes",        "bytes",        1500,    120000),
    "Total Length of Bwd Packets": ("Total Bwd Bytes",        "bytes",        1400,    0),
    "Fwd Packet Length Max":    ("Fwd Packet Length Max",    "bytes",        512,     60),
    "Fwd Packet Length Mean":   ("Fwd Packet Length Mean",   "bytes",        200,     60),
    "Bwd Packet Length Max":    ("Bwd Packet Length Max",    "bytes",        512,     0),
    "Bwd Packet Length Mean":   ("Bwd Packet Length Mean",   "bytes",        180,     0),
    "Flow Bytes/s":             ("Flow Bytes/s",             "bytes/sec",    2500,    950000),
    "Flow Packets/s":           ("Flow Packets/s",           "packets/sec",  18,      42000),
    "Flow IAT Mean":            ("Flow Inter-Arrival Mean",  "microseconds", 95000,   2),
    "Flow IAT Std":             ("Flow Inter-Arrival Std",   "microseconds", 40000,   1),
    "Fwd IAT Mean":             ("Fwd Inter-Arrival Mean",   "microseconds", 100000,  1),
    "Bwd IAT Mean":             ("Bwd Inter-Arrival Mean",   "microseconds", 105000,  0),
    "Fwd PSH Flags":            ("Fwd PSH Flags",            "count",        1,       0),
    "SYN Flag Count":           ("SYN Flag Count",           "count",        1,       1),
    "RST Flag Count":           ("RST Flag Count",           "count",        0,       1),
    "PSH Flag Count":           ("PSH Flag Count",           "count",        2,       0),
    "ACK Flag Count":           ("ACK Flag Count",           "count",        8,       0),
    "Average Packet Size":      ("Average Packet Size",      "bytes",        260,     58),
    "Down/Up Ratio":            ("Down/Up Ratio",            "ratio",        1,       0),
    "Fwd Header Length":        ("Fwd Header Length",        "bytes",        240,     40000),
    "Bwd Header Length":        ("Bwd Header Length",        "bytes",        200,     0),
    "Subflow Fwd Bytes":        ("Subflow Fwd Bytes",        "bytes",        1500,    120000),
}

FEATURE_ORDER = list(FEATURES.keys())

LABEL_COLUMN_CANDIDATES = ["Label", " Label", "label"]

# CICIDS2017 has ~15 fine-grained labels; we collapse to binary for the demo
# (BENIGN vs everything else). Multiclass is left as a documented extension.
BENIGN_LABEL = "BENIGN"
