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
    return requests.post("https://mb-api.abuse.ch/api/v1/", data=data, headers=H, timeout=90)


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
            with requests.get(url, stream=True, timeout=900) as r:
                r.raise_for_status()
                buf = io.BytesIO()
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
    for h in hashes:
        if got >= MAX_SAMPLES or tried >= 400 or time.time() > deadline:
            break
        tried += 1
        try:
            r = mb_api({"query": "get_file", "sha256_hash": h})
            if r.status_code != 200 or r.content[:2] != b"PK":
                continue
            with pyzipper.AESZipFile(io.BytesIO(r.content)) as z:
                z.setpassword(b"infected")
                data = z.read(z.namelist()[0])
            if data[:2] != b"PK":
                continue
            with open(os.path.join(folder, h + ".apk"), "wb") as f:
                f.write(data)
            got += 1
        except Exception:
            pass
        time.sleep(0.3)
    log("malware tried:", tried, "got:", got)
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
        if got >= n or tried >= 400 or time.time() > deadline:
            break
        tried += 1
        try:
            r = requests.get("https://f-droid.org/repo/" + name, timeout=90)
            if r.status_code == 200 and len(r.content) < 60 * 1024 * 1024:
                with open(os.path.join(folder, name), "wb") as f:
                    f.write(r.content)
                got += 1
        except Exception:
            pass
        time.sleep(0.1)
    log("benign tried:", tried, "got:", got)
    return got


def build_lists():
    total = apk_hashes()
    urls = bad_urls()
    stats_update(apk_hashes=total, bad_urls=urls)


def build_model():
    try:
        _build_model()
    finally:
        # samples must never stay on disk, even after an error (they must never be committed)
        shutil.rmtree("apks", ignore_errors=True)
        for junk in ("features.csv", "model_new.json"):
            if os.path.exists(junk):
                os.remove(junk)


def _build_model():
    start = time.time()
    pool = recent_hashes() or load_lines("apk_hashes.txt")[-1000:]
    shutil.rmtree("apks", ignore_errors=True)
    m = get_malware(pool, "apks/malware", start + 30 * 60)
    b = get_benign("apks/benign", max(m, 50), start + 40 * 60)
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
