from scanner import scan_network
from feature_extraction import extract_features

# Step 1: scan network
devices = scan_network("192.168.1.0/24")

# Step 2: test feature extraction
for d in devices:
    print("\n--- DEVICE ---")
    print("IP:", d["ip"])

    features = extract_features(d)
    print("FEATURES:", features)