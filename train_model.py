#!/usr/bin/env python3
"""
Hawkeye risk model trainer (optional).

Step 1 (extract): python train_model.py extract apks features.csv
Step 2 (train):   python train_model.py train features.csv model.json
"""
import csv, glob, json, os, sys, time

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
    # androguard prints tens of thousands of DEBUG lines per APK, which makes the job extremely slow. Turn it off.
    try:
        from loguru import logger
        logger.remove()
        logger.add(sys.stderr, level="ERROR")
    except Exception:
        pass
    import logging
    logging.disable(logging.CRITICAL)
    try:
        from androguard.core.apk import APK
    except ImportError:
        from androguard.core.bytecodes.apk import APK
    t0 = time.time()
    rows = []
    for label, sub in ((0, "benign"), (1, "malware")):
        for path in glob.glob(os.path.join(folder, sub, "*.apk")):
            if time.time() - t0 > 12 * 60:
                print("extract: time budget reached, using what is done so far")
                break
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
    if n < 200 or y.sum() < 50 or (n - y.sum())
