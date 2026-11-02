#!/usr/bin/env python3
"""Weekly data builder for Rifat's Hawkeye. Runs on GitHub Actions.
Outputs: apk_hashes.txt, bad_urls.txt, model.json, stats.json
Samples are only opened as zip files to read their manifest data. They are never run, and are deleted at the end."""
import io, json, os, random, re, shutil, subprocess, sys, time, zipfile
import requests

KEY = os.environ.get("ABUSE_KEY", "").strip()
H = {"Auth-Key": KEY}
SHA = re.compile(r"\b[0-9a-fA-F]{64}\b")
MAX_SAMPLES = int(os.environ.get("MAX_SAMPLES", "150"))


def log(*a):
    print(*a, flush=True)


def load_lines(path):
    try:
        with open(path, encoding="utf-8") as f:
            return [l.strip() for l in f if l.strip()]
    except FileNotFoundError:
        return []


def mb_api(data):
    return requests.post("https://mb-api.abuse.ch/api/v1/", data=data, headers=H, timeout=120)


def apk_hashes():
    old = set(load_lines("apk_hashes.txt"))
    new, recent = set(), []
    try:
        j = mb_api({"query": "get_file_type", "file_type": "apk", "limit": "1000"}).json()
        if j.get("query_status") == "ok":
            for d in j.get("data", []):
                h = str(d.get("sha256_hash", "")).lower()
                if len(h) == 64:
                    new.add(h)
                    recent.append(h)
        else:
            log("get_file_type status:", j.get("query_status"))
    except Exception as e:
        log("api failed:", type(e).__name__)
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
    return recent, len(allh)


def bad_urls():
    new = set()
    try:
        j = requests.get("https://urlhaus-api.abuse.ch/v1/urls/recent/limit/1000/", headers=H, timeout=120).json()
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


def get_malware(hashes, folder):
    import pyzipper
    os.makedirs(folder, exist_ok=True)
    random.shuffle(hashes)
    got = 0
    for h in hashes:
        if got >= MAX_SAMPLES:
            break
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
        time.sleep(0.4)
    return got


def get_benign(folder, n):
    os.makedirs(folder, exist_ok=True)
    idx = requests.get("https://f-droid.org/repo/index-v1.json", timeout=300).json()
    names = [v[0]["apkName"] for v in idx.get("packages", {}).values() if v and v[0].get("apkName")]
    random.shuffle(names)
    got = 0
    for name in names:
        if got >= n:
            break
        try:
            r = requests.get("https://f-droid.org/repo/" + name, timeout=120)
            if r.status_code == 200 and len(r.content) < 80 * 1024 * 1024:
                with open(os.path.join(folder, name), "wb") as f:
                    f.write(r.content)
                got += 1
        except Exception:
            pass
        time.sleep(0.2)
    return got


def main():
    if not KEY:
        log("ABUSE_KEY secret is missing")
        sys.exit(1)
    recent, total = apk_hashes()
    urls = bad_urls()
    pool = recent or load_lines("apk_hashes.txt")[-1000:]
    shutil.rmtree("apks", ignore_errors=True)
    m = get_malware(list(pool), "apks/malware")
    b = get_benign("apks/benign", max(m, 50))
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
    with open("stats.json", "w") as f:
        json.dump({"updated": int(time.time()), "apk_hashes": total, "bad_urls": urls,
                   "malware_samples": m, "benign_samples": b, "model_trained": trained}, f)
    log("done. trained:", trained)


if __name__ == "__main__":
    main()
