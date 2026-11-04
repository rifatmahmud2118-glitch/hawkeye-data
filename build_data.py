#!/usr/bin/env python3
"""Data builder for Rifat's Hawkeye. Runs on GitHub Actions.
Usage: python build_data.py lists   -> apk_hashes.txt, bad_urls.txt, stats.json
       python build_data.py model   -> model.json (trained risk model)
Samples are only opened as zip files to read manifest data. They are never run, and are deleted at the end."""
import io, json, os, random, re, shutil, subprocess, sys, time, zipfile
import requests

KEY = os.environ.get("ABUSE_KEY", "").strip()
H = {"Auth-Key": KEY}
SHA = re.compile(r"\b[0-9a-fA-F]{64}\b")
MAX_SAMPLES = int(os.environ.get("MAX_SAMPLES", "100"))


def log(*a):
    print(*a, flush=True)


def load_lines(path):
    try:
        with open(path, encoding="utf-8") as f:
            return [l.strip() for l in f if l.strip()]
    except FileNotFoundError:
        return []


def stats_update(**kw):
    s = {}
    try:
        with open("stats.json") as f:
            s = json.load(f)
    except Exception:
        pass
    s.update(kw)
    s["updated"] = int(time.time())
    with open("stats.json", "w") as f:
        json.dump(s, f)


def mb_api(data):
    return requests.post("https://mb-api.abuse.ch/api/v1/", data=data, headers=H, timeout=30)


def recent_hashes():
    out = []
    try:
        j = mb_api({"query": "get_file_type", "file_type": "apk", "limit": "1000"}).json()
        if j.get("query_status") == "ok":
            for d in j.get("data", []):
                h = str(d.get("sha256_hash", "")).lower()
                if len(h) == 64:
                    out.append(h)
        else:
            log("get_file_type status:", j.get("query_status"))
    except Exception as e:
        log("api failed:", type(e).__name__)
    return out


def apk_hashes():
    old = set(load_lines("apk_hashes.txt"))
    new = set(recent_hashes())
    url = os.environ.get("FULL_URL", "").strip()
    if url:
        try:
            import tempfile
            buf = tempfile.TemporaryFile()
            with requests.get(url, stream=True, timeout=(30, 120)) as r:
                r.raise_for_status()
                for chunk in r.iter_content(1 << 20):
                    buf.write(chunk)
            buf.seek(0)
            z = zipfile.ZipFile(buf)
            with z.open(z.namelist()[0]) as f:
                for raw in io.TextIOWrapper(f, encoding="utf-8", errors="ignore"):
                    low = raw.lower()
                    if "package-archive" in low or re.search(r'(^|[",;])apk([",;]|$)', low):
                        m = SHA.search(raw)
                        if m:
                            new.add(m.group(0).lower())
        except Exception as e:
            log("full dump failed:", type(e).__name__)
    allh = sorted(old | new)
    with open("apk_hashes.txt", "w") as f:
        f.write("\n".join(allh) + "\n")
    # অ্যাপ এটা RAM-এ না রেখে সরাসরি বাইনারি সার্চ করে, তাই কমপ্যাক্ট বাইনারি ফর্মও রাখা হয় (৩২ বাইট/হ্যাশ)
    with open("apk_hashes.bin", "wb") as f:
        for h in allh:
            try:
                f.write(bytes.fromhex(h))
            except ValueError:
                pass
    log("apk hashes total:", len(allh), "new:", len(new - old))
    return len(allh)


def bad_urls():
    new = set()
    try:
        j = requests.get("https://urlhaus-api.abuse.ch/v1/urls/recent/limit/1000/", headers=H, timeout=90).json()
        for d in j.get("urls", []):
            if d.get("url_status") != "online":
                continue
            u = re.sub(r"^https?://", "", str(d.get("url", "")).strip().lower()).rstrip("/")
            if not u:
                continue
            new.add("u:" + u)
            host = u.split("/")[0].split(":")[0]
            if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", host):
                new.add("h:" + host)
    except Exception as e:
        log("urlhaus failed:", type(e).__name__)
    merged = list(dict.fromkeys(load_lines("bad_urls.txt") + sorted(new)))[-60000:]
    with open("bad_urls.txt", "w") as f:
        f.write("\n".join(merged) + "\n")
    log("bad urls total:", len(merged))
    return len(merged)


def get_malware(hashes, folder, deadline):
    import pyzipper
    os.makedirs(folder, exist_ok=True)
    hashes = list(hashes)
    random.shuffle(hashes)
    got = tried = 0
    why = {}
    for h in hashes:
        if got >= MAX_SAMPLES or tried >= 250 or time.time() > deadline:
            break
        tried += 1
        try:
            r = mb_api({"query": "get_file", "sha256_hash": h})
            if r.status_code != 200 or r.content[:2] != b"PK":
                k = "http%d" % r.status_code if r.status_code != 200 else "notzip:" + r.content[:60].decode("utf-8", "ignore").replace("\n", " ")
                why[k] = why.get(k, 0) + 1
                if tried <= 3:
                    log("get_file reply:", k)
                continue
            with pyzipper.AESZipFile(io.BytesIO(r.content)) as z:
                z.setpassword(b"infected")
                data = z.read(z.namelist()[0])
            if data[:2] != b"PK":
                continue
            with open(os.path.join(folder, h + ".apk"), "wb") as f:
                f.write(data)
            got += 1
        except Exception as e:
            k = "error:" + type(e).__name__
            why[k] = why.get(k, 0) + 1
        time.sleep(0.3)
    log("malware tried:", tried, "got:", got, "reasons:", why)
    return got


def get_benign(folder, n, deadline):
    os.makedirs(folder, exist_ok=True)
    try:
        idx = requests.get("https://f-droid.org/repo/index-v1.json", timeout=300).json()
    except Exception as e:
        log("f-droid index failed:", type(e).__name__)
        return 0
    names = [v[0]["apkName"] for v in idx.get("packages", {}).values() if v and v[0].get("apkName")]
    random.shuffle(names)
    got = tried = 0
    for name in names:
        if got >= n or tried >= 250 or time.time() > deadline:
            break
        tried += 1
        try:
            r = requests.get("https://f-droid.org/repo/" + name, timeout=30)
            if r.status_code == 200 and len(r.content) < 60 * 1024 * 1024:
                with open(os.path.join(folder, name), "wb") as f:
                    f.write(r.content)
                got += 1
        except Exception:
            pass
        time.sleep(0.1)
    log("benign tried:", tried, "got:", got)
    return got


def _hex(v, n):
    v = str(v).strip().lower().replace(":", "")
    return v if len(v) == n and all(c in "0123456789abcdef" for c in v) else ""


def _dom(v):
    v = re.sub(r"^[a-z]+://", "", str(v).strip().lower()).split("/")[0].split(":")[0].strip(".")
    return v if "." in v and " " not in v and len(v) < 120 else ""


def parse_stalkerware(text):
    """ioc.yaml of AssoEchap/stalkerware-indicators -> IOC lines (pkg:, domain:, cert: for 64-hex, sha256:)."""
    import yaml
    out = set()
    for e in (yaml.safe_load(text) or []):
        if not isinstance(e, dict):
            continue
        for p in e.get("packages") or []:
            p = str(p).strip().lower()
            if re.fullmatch(r"[a-z0-9_]+(\.[a-z0-9_]+)+", p):
                out.add("pkg:" + p)
        for c in e.get("certificates") or []:
            h = _hex(c, 64)
            if h:
                out.add("cert:" + h)
        for w in e.get("websites") or []:
            d = _dom(w)
            if d:
                out.add("domain:" + d)
        c2 = e.get("c2") or {}
        for d in (c2.get("domains") or []) + (c2.get("ips") or []):
            d = _dom(d)
            if d:
                out.add("domain:" + d)
        for h in e.get("distribution") or []:
            d = _dom(h)
            if d:
                out.add("domain:" + d)
    return out


def threatfox_domains():
    """Recent ThreatFox domain/IP IOCs (needs the abuse.ch Auth-Key). Capped so the phone list stays small."""
    out = set()
    try:
        r = requests.post("https://threatfox-api.abuse.ch/api/v1/", json={"query": "get_iocs", "days": 7},
                          headers=H, timeout=60)
        j = r.json()
        for d in j.get("data") or []:
            t = str(d.get("ioc_type", ""))
            v = str(d.get("ioc", ""))
            if t == "domain":
                x = _dom(v)
            elif t == "ip:port":
                x = v.split(":")[0]
            else:
                continue
            if x:
                out.add("domain:" + x)
    except Exception as e:
        log("threatfox failed:", type(e).__name__)
    return out


def build_ioc():
    """ioc.txt = stalkerware + ThreatFox lines the app loads through IocDb.
    Rebuilt from scratch each week (keeps the list small); if a source fails, last week's lines are kept."""
    old = set(l for l in load_lines("ioc.txt") if not l.startswith("#"))
    new = set()
    ok = True
    try:
        r = requests.get("https://raw.githubusercontent.com/AssoEchap/stalkerware-indicators/master/ioc.yaml", timeout=60)
        if r.status_code == 200:
            got = parse_stalkerware(r.text)
            log("stalkerware lines:", len(got))
            new |= got
            ok = ok and len(got) > 0
        else:
            log("stalkerware http", r.status_code)
            ok = False
    except Exception as e:
        log("stalkerware failed:", type(e).__name__)
        ok = False
    tf = threatfox_domains()
    log("threatfox lines:", len(tf))
    new |= tf
    ok = ok and len(tf) > 0
    merged = sorted(new if ok else (new | old))[:40000]
    if not merged:
        return 0
    with open("ioc.txt", "w", encoding="utf-8") as f:
        f.write("\n".join(merged) + "\n")
    try:
        subprocess.call(["git", "add", "ioc.txt"])
    except Exception:
        pass
    log("ioc total:", len(merged))
    return len(merged)


def build_lists():
    total = apk_hashes()
    urls = bad_urls()
    try:
        iocs = build_ioc()
    except Exception as e:
        log("ioc failed:", type(e).__name__)
        iocs = 0
    stats_update(apk_hashes=total, bad_urls=urls, ioc_lines=iocs)


def build_model():
    try:
        _build_model()
    finally:
        # samples must never stay on disk, even after an error (they must never be committed)
        shutil.rmtree("apks", ignore_errors=True)
        for junk in ("features.csv", "model_new.json"):
            if os.path.exists(junk):
                os.remove(junk)


DEFAULT_WEIGHTS = {"read_sms": 1.5, "recv_sms": 1.0, "send_sms": 1.2, "install_pkgs": 1.0, "acc_perm": 1.5,
                   "overlay_perm": 1.0, "admin_perm": 1.0, "listener_perm": 0.8, "all_files": 0.6, "mic": 0.3,
                   "camera": 0.2, "contacts": 0.2, "call_log": 0.4, "location": 0.2, "debuggable": 0.5,
                   "old_sdk": 0.5, "hidden": 1.0}


def ensure_valid_model():
    """If training did not work, make sure model.json is still a valid file (the app's built-in weights),
    so the app never sees an empty or broken model."""
    try:
        with open("model.json", encoding="utf-8") as f:
            if json.load(f).get("weights"):
                return
    except Exception:
        pass
    with open("model.json", "w", encoding="utf-8") as f:
        json.dump({"bias": -3.0, "weights": DEFAULT_WEIGHTS, "source": "default (training had too few samples)"}, f, indent=1)
    log("model.json was missing or empty: wrote default weights")


def _build_model():
    start = time.time()
    pool = recent_hashes() or load_lines("apk_hashes.txt")[-1000:]
    shutil.rmtree("apks", ignore_errors=True)
    m = get_malware(pool, "apks/malware", start + 10 * 60)
    b = get_benign("apks/benign", max(m, 50), start + 18 * 60)
    log("samples malware/benign:", m, b)
    trained = False
    if m >= 30 and b >= 30:
        try:
            subprocess.check_call([sys.executable, "train_model.py", "extract", "apks", "features.csv"])
            subprocess.check_call([sys.executable, "train_model.py", "train", "features.csv", "model_new.json"])
            with open("model_new.json", encoding="utf-8") as f:
                j = json.load(f)
            j["weights"]
            os.replace("model_new.json", "model.json")
            trained = True
        except Exception as e:
            log("training failed:", type(e).__name__)
    if not trained:
        ensure_valid_model()
    shutil.rmtree("apks", ignore_errors=True)
    for junk in ("features.csv", "model_new.json"):
        if os.path.exists(junk):
            os.remove(junk)
    stats_update(malware_samples=m, benign_samples=b, model_trained=trained)
    log("model done. trained:", trained)


def main():
    if not KEY:
        log("ABUSE_KEY secret is missing")
        sys.exit(1)
    mode = sys.argv[1] if len(sys.argv) > 1 else "all"
    if mode in ("lists", "all"):
        build_lists()
    if mode in ("model", "all"):
        build_model()


if __name__ == "__main__":
    main()
