# ============================================================
#  SentiNet — classifier.py
#  Trains the ML model and classifies scanned devices
#  University of Nairobi — Hawatif Abdisalam
#
#  Run directly to train:
#      python3 classifier.py
# ============================================================

import os
import joblib

from sklearn.ensemble        import RandomForestClassifier
from sklearn.preprocessing   import LabelEncoder
from sklearn.model_selection import train_test_split
from sklearn.metrics         import classification_report, accuracy_score

from feature_extraction import (
    extract_features,
    features_to_vector,
    FEATURE_ORDER,          # fixed order — ensures train/predict consistency
)
from dataset_builder import build_dataset, generate_synthetic_data

# ────────────────────────────────────────
#  PATHS
# ────────────────────────────────────────
MODEL_PATH   = "model/sentinet_model.pkl"
ENCODER_PATH = "model/label_encoder.pkl"

# ────────────────────────────────────────
#  CONFIDENCE THRESHOLD
#  Predictions below this % are returned
#  as "unknown" instead of a risky guess.
# ────────────────────────────────────────
CONFIDENCE_THRESHOLD = 60.0

# Devices in this set are NOT IoT
NON_IOT_TYPES = {"computer", "unknown"}


# ════════════════════════════════════════
#  TRAIN
# ════════════════════════════════════════

def train_model(real_devices: list = None):
    """
    Trains the Random Forest classifier.

    Always starts from synthetic data (40 samples).
    If real_devices is provided (list from nmap_scanner.py),
    those are labelled and added to the training set too.

    Saves trained model + label encoder to /model/

    Args:
        real_devices: optional list of raw device dicts from scan_network()

    Returns:
        model, le  — trained classifier and label encoder
                     (or None, None on failure)
    """

    print()
    print("=" * 50)
    print("  SentiNet — ML Classifier Training")
    print("=" * 50)

    # ── Step 1: Synthetic data (always included) ──
    print("\n[*] Generating synthetic training data...")
    X_syn, y_syn = generate_synthetic_data()

    # ── Step 2: Real scan data (optional) ──
    X_real, y_real = [], []
    if real_devices:
        print(f"[*] Processing {len(real_devices)} real scanned devices...")
        X_real, y_real = build_dataset(real_devices)
        print(f"[+] Added {len(X_real)} real samples to training set")

    # ── Step 3: Combine ──
    X = X_syn + X_real
    y = y_syn + y_real

    if len(X) == 0:
        print("[!] No training data. Aborting.")
        return None, None

    print(f"\n[+] Total training samples : {len(X)}")
    print(f"[+] Feature vector length  : {len(FEATURE_ORDER)}")
    print(f"[+] Classes found          : {sorted(set(y))}")

    # ── Step 4: Encode string labels → integers ──
    le        = LabelEncoder()
    y_encoded = le.fit_transform(y)

    # ── Step 5: Train / test split ──
    # Need at least 2 samples per class to stratify
    class_counts = {c: y.count(c) for c in set(y)}
    can_split    = all(v >= 2 for v in class_counts.values()) and len(X) >= 10

    if can_split:
        X_train, X_test, y_train, y_test = train_test_split(
            X, y_encoded,
            test_size=0.2,
            random_state=42,
            stratify=y_encoded,
        )
        print(f"[+] Train size: {len(X_train)}  |  Test size: {len(X_test)}")
    else:
        print("[!] Too few samples to split — training on full dataset")
        X_train, y_train = X, y_encoded
        X_test,  y_test  = X, y_encoded

    # ── Step 6: Train Random Forest ──
    print("\n[*] Training Random Forest (100 trees)...")
    model = RandomForestClassifier(
        n_estimators=100,
        max_depth=10,
        random_state=42,
        class_weight="balanced",   # handles unequal class sizes
    )
    model.fit(X_train, y_train)

    # ── Step 7: Evaluate ──
    y_pred   = model.predict(X_test)
    accuracy = accuracy_score(y_test, y_pred)

    print(f"\n[+] Training accuracy: {accuracy * 100:.1f}%")
    print()
    print("  NOTE: Accuracy is measured on rule-labelled / synthetic data.")
    print("        It shows how well the model learned the patterns,")
    print("        not guaranteed real-world performance.")
    print("        Report this as 'training set accuracy'.")
    print()
    print("[+] Classification report:")
    print(classification_report(
        y_test, y_pred,
        target_names=le.classes_,
        zero_division=0,
    ))

    # ── Step 8: Feature importance (top 5) ──
    importances  = list(zip(FEATURE_ORDER, model.feature_importances_))
    top_features = sorted(importances, key=lambda x: x[1], reverse=True)[:5]
    print("[+] Top 5 most important features:")
    for name, score in top_features:
        print(f"    {name:30s}  importance: {score:.3f}")

    # ── Step 9: Save ──
    os.makedirs("model", exist_ok=True)
    joblib.dump(model, MODEL_PATH)
    joblib.dump(le,    ENCODER_PATH)
    print(f"\n[+] Model saved   → {MODEL_PATH}")
    print(f"[+] Encoder saved → {ENCODER_PATH}")

    return model, le


# ════════════════════════════════════════
#  LOAD
# ════════════════════════════════════════

def load_model():
    """
    Loads the saved model and label encoder from disk.
    Returns (None, None) if not trained yet.
    """
    if not os.path.exists(MODEL_PATH) or not os.path.exists(ENCODER_PATH):
        print("[!] No saved model found. Run train_model() first.")
        return None, None

    model = joblib.load(MODEL_PATH)
    le    = joblib.load(ENCODER_PATH)
    return model, le


# ════════════════════════════════════════
#  CLASSIFY A SINGLE DEVICE
# ════════════════════════════════════════

def classify_device(device: dict, model=None, le=None) -> dict:
    """
    Classifies one raw device dict from nmap_scanner.py.

    Uses FEATURE_ORDER from feature_extraction.py to guarantee
    the same column order as during training.

    If confidence < CONFIDENCE_THRESHOLD → returns "unknown"
    instead of making a low-confidence guess.

    Returns:
        {
            "device_type":   "camera",    # string label
            "ml_confidence": 94.0,        # percentage 0-100
            "is_iot":        True         # bool
        }
    """
    if model is None or le is None:
        model, le = load_model()

    if model is None:
        return {
            "device_type":   "unknown",
            "ml_confidence": 0.0,
            "is_iot":        False,
        }

    # Build feature vector using fixed FEATURE_ORDER
    features = extract_features(device)
    vector   = features_to_vector(features)   # guaranteed consistent order ✓

    # Get probability for each class
    proba      = model.predict_proba([vector])[0]
    class_idx  = proba.argmax()
    confidence = round(float(proba[class_idx]) * 100, 2)
    label      = le.inverse_transform([class_idx])[0]

    # Low confidence → don't guess
    if confidence < CONFIDENCE_THRESHOLD:
        label = "unknown"

    return {
        "device_type":   label,
        "ml_confidence": confidence,
        "is_iot":        label not in NON_IOT_TYPES,
    }


# ════════════════════════════════════════
#  CLASSIFY A FULL LIST OF DEVICES
# ════════════════════════════════════════

def classify_all(devices: list, model=None, le=None) -> list:
    """
    Classifies every device in the list returned by scan_network().

    Loads the model once then runs classify_device() on each.
    Returns the same list with prediction fields merged in:
        device_type, ml_confidence, is_iot

    Usage:
        devices = scan_network("192.168.1.0/24")
        results = classify_all(devices)
    """
    if model is None or le is None:
        model, le = load_model()

    if model is None:
        print("[!] Cannot classify — no model loaded.")
        return devices

    print(f"\n[*] Classifying {len(devices)} device(s)...\n")

    results = []
    for device in devices:
        prediction = classify_device(device, model, le)

        # Merge prediction into device dict
        enriched = {**device, **prediction}
        results.append(enriched)

        # Pretty print
        conf_str = f"{prediction['ml_confidence']}%"
        iot_str  = "IoT" if prediction["is_iot"] else "Non-IoT"
        print(
            f"  {device.get('ip', '?'):16s}"
            f"  {prediction['device_type']:10s}"
            f"  confidence: {conf_str:8s}"
            f"  [{iot_str}]"
        )

    # Summary
    iot_count  = sum(1 for r in results if r["is_iot"])
    type_counts = {}
    for r in results:
        t = r["device_type"]
        type_counts[t] = type_counts.get(t, 0) + 1

    print(f"\n[+] Classification complete:")
    print(f"    Total   : {len(results)}")
    print(f"    IoT     : {iot_count}")
    print(f"    Non-IoT : {len(results) - iot_count}")
    for t, count in sorted(type_counts.items()):
        print(f"    {t:10s}: {count}")

    return results


# ════════════════════════════════════════
#  ENTRY POINT
#  Run this file directly to train:
#      python3 classifier.py
# ════════════════════════════════════════

if __name__ == "__main__":
    train_model()