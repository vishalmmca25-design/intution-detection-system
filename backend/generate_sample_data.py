"""
Generates a synthetic CSV shaped like CICIDS2017 flow data, so the training
pipeline can be demoed end-to-end without downloading the real ~6GB dataset.

This is ONLY a stand-in. For a real, defensible model, download the actual
CICIDS2017 CSVs (see backend/data/README.md) and drop them in backend/data/ -
train_model.py will use those automatically instead of this synthetic set.

The synthetic generator draws benign flows and attack flows from different
distributions that mimic real CICIDS2017 tendencies (attacks: many small
packets, tiny inter-arrival times, high packets/sec, near-zero backward
traffic for DoS/PortScan-style floods) so the resulting demo model behaves
sensibly, but it is NOT a substitute for training on real traffic captures.
"""
import numpy as np
import pandas as pd
from pathlib import Path

from features import FEATURE_ORDER, BENIGN_LABEL

RNG = np.random.default_rng(42)
OUT_PATH = Path(__file__).parent / "data" / "sample_cicids2017.csv"


def _benign_rows(n):
    return {
        "Flow Duration": RNG.normal(1_000_000, 300_000, n).clip(1000),
        "Total Fwd Packets": RNG.poisson(14, n) + 1,
        "Total Backward Packets": RNG.poisson(12, n) + 1,
        "Total Length of Fwd Packets": RNG.normal(1600, 500, n).clip(40),
        "Total Length of Bwd Packets": RNG.normal(1500, 500, n).clip(0),
        "Fwd Packet Length Max": RNG.normal(520, 120, n).clip(20),
        "Fwd Packet Length Mean": RNG.normal(210, 60, n).clip(20),
        "Bwd Packet Length Max": RNG.normal(520, 120, n).clip(0),
        "Bwd Packet Length Mean": RNG.normal(190, 60, n).clip(0),
        "Flow Bytes/s": RNG.normal(3000, 1500, n).clip(1),
        "Flow Packets/s": RNG.normal(20, 8, n).clip(0.1),
        "Flow IAT Mean": RNG.normal(90_000, 30_000, n).clip(1),
        "Flow IAT Std": RNG.normal(38_000, 15_000, n).clip(0),
        "Fwd IAT Mean": RNG.normal(95_000, 30_000, n).clip(0),
        "Bwd IAT Mean": RNG.normal(100_000, 30_000, n).clip(0),
        "Fwd PSH Flags": RNG.integers(0, 2, n),
        "SYN Flag Count": RNG.integers(0, 2, n),
        "RST Flag Count": np.zeros(n),
        "PSH Flag Count": RNG.integers(0, 4, n),
        "ACK Flag Count": RNG.integers(2, 12, n),
        "Average Packet Size": RNG.normal(260, 70, n).clip(20),
        "Down/Up Ratio": RNG.normal(1.0, 0.3, n).clip(0),
        "Fwd Header Length": RNG.normal(240, 60, n).clip(20),
        "Bwd Header Length": RNG.normal(200, 60, n).clip(0),
        "Subflow Fwd Bytes": RNG.normal(1600, 500, n).clip(40),
    }


def _dos_hulk_rows(n):
    # High-volume flood: huge packet counts, large payloads, short duration
    return {
        "Flow Duration": RNG.normal(400, 300, n).clip(1),
        "Total Fwd Packets": RNG.poisson(1400, n) + 100,
        "Total Backward Packets": RNG.poisson(3, n),
        "Total Length of Fwd Packets": RNG.normal(600_000, 200_000, n).clip(500),
        "Total Length of Bwd Packets": RNG.normal(80, 100, n).clip(0),
        "Fwd Packet Length Max": RNG.normal(1400, 200, n).clip(40),
        "Fwd Packet Length Mean": RNG.normal(420, 100, n).clip(40),
        "Bwd Packet Length Max": RNG.normal(15, 15, n).clip(0),
        "Bwd Packet Length Mean": RNG.normal(8, 8, n).clip(0),
        "Flow Bytes/s": RNG.normal(1_500_000, 400_000, n).clip(1),
        "Flow Packets/s": RNG.normal(3500, 1200, n).clip(1),
        "Flow IAT Mean": RNG.normal(4, 4, n).clip(0),
        "Flow IAT Std": RNG.normal(3, 3, n).clip(0),
        "Fwd IAT Mean": RNG.normal(3, 3, n).clip(0),
        "Bwd IAT Mean": RNG.normal(2, 3, n).clip(0),
        "Fwd PSH Flags": RNG.integers(0, 2, n),
        "SYN Flag Count": np.zeros(n),
        "RST Flag Count": np.zeros(n),
        "PSH Flag Count": RNG.integers(1, 3, n),
        "ACK Flag Count": RNG.integers(0, 2, n),
        "Average Packet Size": RNG.normal(410, 100, n).clip(20),
        "Down/Up Ratio": RNG.normal(0.02, 0.03, n).clip(0),
        "Fwd Header Length": RNG.normal(28_000, 8_000, n).clip(20),
        "Bwd Header Length": RNG.normal(20, 30, n).clip(0),
        "Subflow Fwd Bytes": RNG.normal(600_000, 200_000, n).clip(500),
    }


def _ddos_rows(n):
    # Distributed flood: even more extreme packet rate, near-zero backward
    return {
        "Flow Duration": RNG.normal(150, 150, n).clip(1),
        "Total Fwd Packets": RNG.poisson(2600, n) + 200,
        "Total Backward Packets": RNG.poisson(1, n),
        "Total Length of Fwd Packets": RNG.normal(150_000, 60_000, n).clip(200),
        "Total Length of Bwd Packets": RNG.normal(5, 10, n).clip(0),
        "Fwd Packet Length Max": RNG.normal(70, 25, n).clip(1),
        "Fwd Packet Length Mean": RNG.normal(58, 15, n).clip(1),
        "Bwd Packet Length Max": RNG.normal(2, 4, n).clip(0),
        "Bwd Packet Length Mean": RNG.normal(1, 2, n).clip(0),
        "Flow Bytes/s": RNG.normal(1_100_000, 350_000, n).clip(1),
        "Flow Packets/s": RNG.normal(60_000, 20_000, n).clip(1),
        "Flow IAT Mean": RNG.normal(0.6, 0.8, n).clip(0),
        "Flow IAT Std": RNG.normal(0.4, 0.5, n).clip(0),
        "Fwd IAT Mean": RNG.normal(0.4, 0.5, n).clip(0),
        "Bwd IAT Mean": RNG.normal(0.2, 0.3, n).clip(0),
        "Fwd PSH Flags": np.zeros(n),
        "SYN Flag Count": RNG.integers(0, 2, n),
        "RST Flag Count": RNG.integers(0, 2, n),
        "PSH Flag Count": np.zeros(n),
        "ACK Flag Count": np.zeros(n),
        "Average Packet Size": RNG.normal(56, 15, n).clip(1),
        "Down/Up Ratio": RNG.normal(0.01, 0.02, n).clip(0),
        "Fwd Header Length": RNG.normal(52_000, 18_000, n).clip(20),
        "Bwd Header Length": RNG.normal(4, 6, n).clip(0),
        "Subflow Fwd Bytes": RNG.normal(150_000, 60_000, n).clip(200),
    }


def _portscan_rows(n):
    # Reconnaissance: many tiny probes, roughly symmetric tiny fwd/bwd, RST-heavy
    return {
        "Flow Duration": RNG.normal(2000, 3000, n).clip(1),
        "Total Fwd Packets": RNG.poisson(2, n) + 1,
        "Total Backward Packets": RNG.poisson(1, n),
        "Total Length of Fwd Packets": RNG.normal(60, 30, n).clip(0),
        "Total Length of Bwd Packets": RNG.normal(20, 20, n).clip(0),
        "Fwd Packet Length Max": RNG.normal(40, 15, n).clip(0),
        "Fwd Packet Length Mean": RNG.normal(35, 12, n).clip(0),
        "Bwd Packet Length Max": RNG.normal(15, 12, n).clip(0),
        "Bwd Packet Length Mean": RNG.normal(10, 10, n).clip(0),
        "Flow Bytes/s": RNG.normal(400, 500, n).clip(0),
        "Flow Packets/s": RNG.normal(8, 10, n).clip(0.1),
        "Flow IAT Mean": RNG.normal(1500, 2000, n).clip(0),
        "Flow IAT Std": RNG.normal(600, 800, n).clip(0),
        "Fwd IAT Mean": RNG.normal(1500, 2000, n).clip(0),
        "Bwd IAT Mean": RNG.normal(1500, 2000, n).clip(0),
        "Fwd PSH Flags": np.zeros(n),
        "SYN Flag Count": RNG.integers(0, 2, n),
        "RST Flag Count": RNG.integers(0, 2, n),
        "PSH Flag Count": np.zeros(n),
        "ACK Flag Count": RNG.integers(0, 2, n),
        "Average Packet Size": RNG.normal(28, 12, n).clip(1),
        "Down/Up Ratio": RNG.normal(0.5, 0.4, n).clip(0),
        "Fwd Header Length": RNG.normal(50, 25, n).clip(20),
        "Bwd Header Length": RNG.normal(35, 25, n).clip(0),
        "Subflow Fwd Bytes": RNG.normal(60, 30, n).clip(0),
    }


def _ftp_patator_rows(n):
    # Brute force login attempts: moderate duration, repeated small packets, ACK-heavy
    return {
        "Flow Duration": RNG.normal(300_000, 150_000, n).clip(1000),
        "Total Fwd Packets": RNG.poisson(20, n) + 4,
        "Total Backward Packets": RNG.poisson(18, n) + 4,
        "Total Length of Fwd Packets": RNG.normal(900, 300, n).clip(60),
        "Total Length of Bwd Packets": RNG.normal(700, 250, n).clip(40),
        "Fwd Packet Length Max": RNG.normal(60, 20, n).clip(10),
        "Fwd Packet Length Mean": RNG.normal(45, 12, n).clip(5),
        "Bwd Packet Length Max": RNG.normal(55, 20, n).clip(10),
        "Bwd Packet Length Mean": RNG.normal(38, 12, n).clip(5),
        "Flow Bytes/s": RNG.normal(6000, 3000, n).clip(1),
        "Flow Packets/s": RNG.normal(120, 60, n).clip(1),
        "Flow IAT Mean": RNG.normal(8000, 4000, n).clip(0),
        "Flow IAT Std": RNG.normal(3000, 2000, n).clip(0),
        "Fwd IAT Mean": RNG.normal(9000, 4000, n).clip(0),
        "Bwd IAT Mean": RNG.normal(9000, 4000, n).clip(0),
        "Fwd PSH Flags": RNG.integers(0, 2, n),
        "SYN Flag Count": RNG.integers(0, 2, n),
        "RST Flag Count": RNG.integers(0, 2, n),
        "PSH Flag Count": RNG.integers(2, 8, n),
        "ACK Flag Count": RNG.integers(10, 30, n),
        "Average Packet Size": RNG.normal(42, 12, n).clip(5),
        "Down/Up Ratio": RNG.normal(0.9, 0.2, n).clip(0),
        "Fwd Header Length": RNG.normal(400, 150, n).clip(40),
        "Bwd Header Length": RNG.normal(380, 150, n).clip(40),
        "Subflow Fwd Bytes": RNG.normal(900, 300, n).clip(60),
    }


def _bot_rows(n):
    # C2 beaconing: small, very regular periodic packets over a long-lived flow
    return {
        "Flow Duration": RNG.normal(2_500_000, 800_000, n).clip(10_000),
        "Total Fwd Packets": RNG.poisson(8, n) + 2,
        "Total Backward Packets": RNG.poisson(7, n) + 2,
        "Total Length of Fwd Packets": RNG.normal(500, 150, n).clip(40),
        "Total Length of Bwd Packets": RNG.normal(450, 150, n).clip(40),
        "Fwd Packet Length Max": RNG.normal(80, 20, n).clip(10),
        "Fwd Packet Length Mean": RNG.normal(60, 15, n).clip(5),
        "Bwd Packet Length Max": RNG.normal(75, 20, n).clip(10),
        "Bwd Packet Length Mean": RNG.normal(55, 15, n).clip(5),
        "Flow Bytes/s": RNG.normal(400, 200, n).clip(1),
        "Flow Packets/s": RNG.normal(0.8, 0.5, n).clip(0.05),
        "Flow IAT Mean": RNG.normal(300_000, 60_000, n).clip(1000),
        "Flow IAT Std": RNG.normal(20_000, 10_000, n).clip(0),
        "Fwd IAT Mean": RNG.normal(300_000, 60_000, n).clip(1000),
        "Bwd IAT Mean": RNG.normal(300_000, 60_000, n).clip(1000),
        "Fwd PSH Flags": RNG.integers(0, 2, n),
        "SYN Flag Count": RNG.integers(0, 2, n),
        "RST Flag Count": np.zeros(n),
        "PSH Flag Count": RNG.integers(0, 3, n),
        "ACK Flag Count": RNG.integers(2, 10, n),
        "Average Packet Size": RNG.normal(58, 15, n).clip(5),
        "Down/Up Ratio": RNG.normal(1.0, 0.15, n).clip(0),
        "Fwd Header Length": RNG.normal(180, 60, n).clip(20),
        "Bwd Header Length": RNG.normal(170, 60, n).clip(20),
        "Subflow Fwd Bytes": RNG.normal(500, 150, n).clip(40),
    }


ATTACK_GENERATORS = {
    "DoS Hulk": _dos_hulk_rows,
    "DDoS": _ddos_rows,
    "PortScan": _portscan_rows,
    "FTP-Patator": _ftp_patator_rows,
    "Bot": _bot_rows,
}


def generate(n_benign=9000, n_per_attack=1600):
    benign = pd.DataFrame(_benign_rows(n_benign))
    benign["Label"] = BENIGN_LABEL

    attack_frames = []
    for label, gen_fn in ATTACK_GENERATORS.items():
        frame = pd.DataFrame(gen_fn(n_per_attack))
        frame["Label"] = label
        attack_frames.append(frame)

    df = pd.concat([benign] + attack_frames, ignore_index=True)
    df = df.sample(frac=1, random_state=42).reset_index(drop=True)
    df = df[FEATURE_ORDER + ["Label"]]
    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(OUT_PATH, index=False)
    print(f"Wrote synthetic dataset: {OUT_PATH} ({len(df)} rows)")
    return OUT_PATH


if __name__ == "__main__":
    generate()
