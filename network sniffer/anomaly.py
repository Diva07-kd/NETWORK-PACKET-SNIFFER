"""Anomaly detection helper used by sniffer.py.

Standalone, minimal implementation: loads a joblib model if present and
provides analyze_packet and train_model. If no model exists analyze_packet
is a no-op so the sniffer can run without ML.
"""
import os
import joblib
import numpy as np

MODEL_PATH = "anomaly_model.pkl"
model = None
if os.path.exists(MODEL_PATH):
    try:
        model = joblib.load(MODEL_PATH)
    except Exception:
        model = None

def train_model(X_train, model_path=MODEL_PATH):
    """Train and save an IsolationForest model.

    X_train should be array-like (n_samples, n_features).
    """
    from sklearn.ensemble import IsolationForest
    m = IsolationForest(contamination='auto', random_state=42)
    m.fit(X_train)
    joblib.dump(m, model_path)
    return m

def analyze_packet(info):
    """Analyze a packet info dict using the loaded model if available.

    Expected keys: proto, sport, dport, length, src
    """
    global model
    if model is None:
        return
    try:
        features = np.array([[
            info.get('proto', 0), info.get('sport', 0),
            info.get('dport', 0), info.get('length', 0)
        ]])
        pred = model.predict(features)
        if int(pred[0]) == -1:
            print(f"ALERT: Anomaly detected from {info.get('src','?')}:{info.get('sport','?')}")
    except Exception as e:
        print(f"[!] Error in analyze_packet: {e}")

__all__ = ["train_model", "analyze_packet", "model"]
"""Anomaly helper used by sniffer.py (clean standalone implementation).

Provides train_model and analyze_packet with safe fallbacks. This module
does NOT import from `Anomaly` (capital A) to avoid ModuleNotFoundError.
"""
import os
import joblib
import numpy as np

MODEL_PATH = "anomaly_model.pkl"
# Try to load a pre-trained model; if missing, keep model=None
model = None
if os.path.exists(MODEL_PATH):
    try:
        model = joblib.load(MODEL_PATH)
    except Exception:
        model = None


def train_model(X_train, model_path=MODEL_PATH):
    """Train and save an IsolationForest model.

    X_train: array-like of shape (n_samples, n_features).
    """
    from sklearn.ensemble import IsolationForest
    m = IsolationForest(contamination='auto', random_state=42)
    m.fit(X_train)
    joblib.dump(m, model_path)
    return m


def analyze_packet(info):
    """Analyze a single packet info dict for anomalies using the model.

    info: dict with keys proto, sport, dport, length, src, dst, etc.
    If no model is available the function returns immediately.
    """
    global model
    if model is None:
        return

    # Build feature vector in the expected order
    features = np.array([[
        info.get('proto', 0),
        info.get('sport', 0),
        info.get('dport', 0),
        info.get('length', 0)
    ]])

    try:
        prediction = model.predict(features)
        if prediction[0] == -1:
            print(f"ALERT: Anomaly detected from {info.get('src','?')}:{info.get('sport','?')}!")
    except Exception as e:
        print(f"[!] Error during anomaly prediction: {e}")


__all__ = ["train_model", "analyze_packet", "model"]