#!/usr/bin/env python3
"""
Hawkeye risk model trainer (optional).

Step 1 (extract): turn a folder of APKs into a CSV of features
    folder layout:   apks/benign/*.apk   apks/malware/*.apk
    command:         python train_model.py extract apks features.csv
    needs:           pip install androguard

Step 2 (train): learn weights from the CSV and write model.json
    command:         python train_model.py train features.csv model.json
    needs:           pip install numpy

Then upload model.json somewhere with a direct link (for example a public GitHub repo's raw link)
and paste that link in the app: Update Settings > Risk model link.

Only features that can be read from an APK file are learned here. The runtime signals
(accessibility ON now, overlay ON now, etc.) keep working through the app's rules.
"""
import csv, glob, json, os, sys

FEATURES = ["read_sms", "recv_sms", "send_sms", "install_pkgs", "acc_perm", "overlay_perm", "admin_perm",
            "listener_perm", "all_files", "mic", "camera", "contacts", "call_log", "location",
            "debuggable", "old_sdk", "hidden"]
PERM = {
    "read_sms": "READ_SMS", "recv_sms": "RECEIVE_SMS", "send_sms": "SEND_SMS",
    "install_pkgs": "REQUEST_INSTALL_PACKAGES", "acc_perm": "BIND_ACCESSIBILITY_SERVICE",
    "overlay_perm": "SYSTEM_ALERT_WINDOW", "admin_perm": "BIND_DEVICE_ADMIN",
    "listener_perm": "BIND_NOTIFICATION_LISTENER_SERVICE", "all_files": "MANAGE_EXTERNAL_STORAGE",
    "mic": "RECORD_AUDIO", "camera": "CAMERA", "contacts": "READ_CONTACTS", "call_log": "READ_CALL_LOG",
    "location": "ACCESS_FINE_LOCATION",
}


def extract(folder, out):
    try:
        from androguard.core.apk import APK
    except ImportError:
        from androguard.core.bytecodes.apk import APK
    rows = []
    for label, sub in ((0, "benign"), (1, "malware")):
        for path in glob.glob(os.path.join(folder, sub, "*.apk")):
            try:
                a = APK(path)
                perms = {p.split(".")[-1] for p in a.get_permissions()}
                row = {f: 1 if PERM[f] in perms else 0 for f in PERM}
                try:
                    row["old_sdk"] = 1 if int(a.get_target_sdk_version() or 0) < 23 else 0
                except Exception:
                    row["old_sdk"] = 0
                try:
                    row["debuggable"] = 1 if str(a.get_attribute_value("application", "debuggable")).lower() == "true" else 0
                except Exception:
                    row["debuggable"] = 0
                try:
                    mains = a.get_main_activities() if hasattr(a, "get_main_activities") else [a.get_main_activity()]
                    row["hidden"] = 0 if [m for m in mains if m] else 1
                except Exception:
                    row["hidden"] = 0
                row["label"] = label
                rows.append(row)
            except Exception as e:
                print("skip", path, e)
    with open(out, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=FEATURES + ["label"])
        w.writeheader()
        w.writerows(rows)
    print("wrote", len(rows), "rows to", out)


def train(csv_path, out):
    import numpy as np
    with open(csv_path) as f:
        rows = list(csv.DictReader(f))
    X = np.array([[float(r[k]) for k in FEATURES] for r in rows])
    y = np.array([float(r["label"]) for r in rows])
    n = len(y)
    if n < 200 or y.sum() < 50 or (n - y.sum()) < 50:
        print("WARNING: very little data (%d rows). The model will be unreliable." % n)
    rng = np.random.default_rng(1)
    idx = rng.permutation(n)
    cut = int(n * 0.8)
    tr, te = idx[:cut], idx[cut:]
    w = np.zeros(X.shape[1]); b = 0.0
    pos_w = (n - y.sum()) / max(y.sum(), 1)  # balance classes
    for _ in range(4000):
        z = X[tr] @ w + b
        p = 1 / (1 + np.exp(-z))
        sw = np.where(y[tr] == 1, pos_w, 1.0)
        g = (p - y[tr]) * sw
        w -= 0.05 * (X[tr].T @ g / len(tr) + 0.001 * w)
        b -= 0.05 * g.mean()
    p = 1 / (1 + np.exp(-(X[te] @ w + b)))
    pred = p >= 0.5
    tp = int(((pred == 1) & (y[te] == 1)).sum()); fp = int(((pred == 1) & (y[te] == 0)).sum())
    fn = int(((pred == 0) & (y[te] == 1)).sum()); tn = int(((pred == 0) & (y[te] == 0)).sum())
    print("test rows %d | caught malware %d, missed %d | false alarms %d, correct benign %d" % (len(te), tp, fn, fp, tn))
    print("precision %.2f recall %.2f" % (tp / max(tp + fp, 1), tp / max(tp + fn, 1)))
    json.dump({"bias": float(b), "weights": {k: float(v) for k, v in zip(FEATURES, w)}}, open(out, "w"), indent=1)
    print("wrote", out)


if __name__ == "__main__":
    if len(sys.argv) == 4 and sys.argv[1] == "extract":
        extract(sys.argv[2], sys.argv[3])
    elif len(sys.argv) == 4 and sys.argv[1] == "train":
        train(sys.argv[2], sys.argv[3])
    else:
        print(__doc__)
