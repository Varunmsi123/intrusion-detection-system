"""
predict.py — Load trained IDS model and classify network connections

This file is used by the live capture system (capture.py / app.py).
It loads the artifacts saved by train.py and provides a simple classify() API.

Usage:
    from predict import IDSPredictor
    ids = IDSPredictor("models/")
    label, confidence = ids.classify(feature_vector)   # feature_vector = list of 41 floats
"""

import joblib
import numpy as np

ATTACK_COLORS = {
    "Normal": "#22c55e",
    "DoS":    "#ef4444",
    "Probe":  "#3b82f6",
    "R2L":    "#f59e0b",
    "U2R":    "#ec4899",
}


class IDSPredictor:
    """
    Wraps the trained Random Forest model.
    Call classify() with a 41-element feature vector to get a prediction.
    """

    def __init__(self, models_dir: str = "models"):
        print(f"[IDSPredictor] Loading artifacts from '{models_dir}/'...")

        self.model         = joblib.load(f"{models_dir}/random_forest.pkl")
        self.scaler        = joblib.load(f"{models_dir}/scaler.pkl")
        self.label_encoder = joblib.load(f"{models_dir}/label_encoder.pkl")
        self.cat_encoders  = joblib.load(f"{models_dir}/cat_encoders.pkl")
        self.feature_names = joblib.load(f"{models_dir}/feature_names.pkl")

        print(f"  Model      : {type(self.model).__name__}")
        print(f"  Classes    : {list(self.label_encoder.classes_)}")
        print(f"  Features   : {len(self.feature_names)}")
        print(f"  Ready.\n")

    # ──────────────────────────────────────────────────────────────────────
    def classify(self, features: list) -> tuple[str, float]:
        """
        Classify a single connection.

        Args:
            features: list of 41 numeric values in NSL-KDD column order.
                      Categorical columns (protocol_type, service, flag) must
                      already be integer-encoded using cat_encoders.

        Returns:
            (label: str, confidence: float)
            e.g. ("DoS", 0.97)
        """
        X    = np.array(features, dtype=float).reshape(1, -1)
        X    = self.scaler.transform(X)
        pred = self.model.predict(X)[0]
        conf = float(self.model.predict_proba(X).max())
        label = self.label_encoder.inverse_transform([pred])[0]
        return label, conf

    # ──────────────────────────────────────────────────────────────────────
    def classify_batch(self, feature_matrix: np.ndarray) -> list[tuple[str, float]]:
        """
        Classify multiple connections at once (faster than looping classify()).

        Args:
            feature_matrix: numpy array of shape (N, 41)

        Returns:
            list of (label, confidence) tuples
        """
        X      = self.scaler.transform(feature_matrix.astype(float))
        preds  = self.model.predict(X)
        confs  = self.model.predict_proba(X).max(axis=1)
        labels = self.label_encoder.inverse_transform(preds)
        return list(zip(labels, confs.tolist()))

    # ──────────────────────────────────────────────────────────────────────
    def encode_categorical(self, protocol_type: str,
                           service: str, flag: str) -> tuple[int, int, int]:
        """
        Helper: encode the 3 categorical fields using saved encoders.
        Call this before building your feature vector from a live packet.

        Args:
            protocol_type : "tcp" | "udp" | "icmp"
            service       : "http" | "ftp" | "ssh" | ... (see NSL-KDD docs)
            flag          : "SF" | "S0" | "REJ" | "RSTO" | ...

        Returns:
            (proto_enc, service_enc, flag_enc) as ints
        """
        def safe_encode(le, val):
            val = str(val).lower()
            if val in le.classes_:
                return int(le.transform([val])[0])
            return 0   # fallback to first known class

        proto_enc   = safe_encode(self.cat_encoders["protocol_type"], protocol_type)
        service_enc = safe_encode(self.cat_encoders["service"],       service)
        flag_enc    = safe_encode(self.cat_encoders["flag"],          flag)
        return proto_enc, service_enc, flag_enc

    # ──────────────────────────────────────────────────────────────────────
    def result_dict(self, features: list, src_ip="", dst_ip="",
                    service="", protocol="", **meta) -> dict:
        """
        Full result dict suitable for sending over Socket.IO to the dashboard.
        """
        from datetime import datetime
        label, conf = self.classify(features)
        return {
            "label":      label,
            "confidence": round(conf, 4),
            "color":      ATTACK_COLORS.get(label, "#888"),
            "is_attack":  label != "Normal",
            "src_ip":     src_ip,
            "dst_ip":     dst_ip,
            "service":    service,
            "protocol":   protocol,
            "time":       datetime.now().strftime("%H:%M:%S"),
            "timestamp":  datetime.now().isoformat(),
            **meta,
        }


# ── Standalone test ───────────────────────────────────────────────────────
if __name__ == "__main__":
    import sys

    models_dir = sys.argv[1] if len(sys.argv) > 1 else "models"
    ids = IDSPredictor(models_dir)

    # Build a dummy "normal" feature vector (all zeros — just tests the pipeline)
    dummy_features = [0.0] * len(ids.feature_names)
    label, conf = ids.classify(dummy_features)
    print(f"Dummy prediction → label={label}  confidence={conf:.4f}")

    # Test categorical encoding
    p, s, f = ids.encode_categorical("tcp", "http", "SF")
    print(f"Encoded tcp/http/SF → {p}, {s}, {f}")