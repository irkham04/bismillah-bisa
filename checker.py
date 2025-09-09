import socket
import base64
import json
import re
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed

def fetch_subscription(url):
    try:
        r = requests.get(url, timeout=10)
        r.raise_for_status()
        data = r.text.strip()
        try:
            # coba decode base64
            decoded = base64.b64decode(data).decode()
            return [line.strip() for line in decoded.splitlines() if line.strip()]
        except:
            # kalau bukan base64, berarti langsung daftar akun
            return [line.strip() for line in data.splitlines() if line.strip()]
    except Exception as e:
        print(f"[!] Gagal fetch {url}: {e}")
        return []

def parse_vmess(link):
    try:
        data = base64.b64decode(link.replace("vmess://", "")).decode()
        return json.loads(data)
    except:
        return {}

def check_tcp(host, port, timeout=8):
    try:
        s = socket.create_connection((host, port), timeout=timeout)
        s.close()
        return True
    except:
        return False

def check_account(link):
    host, port = None, None
    if link.startswith("vmess://"):
        cfg = parse_vmess(link)
        host, port = cfg.get("add"), int(cfg.get("port", 0) or 0)
    elif link.startswith("vless://") or link.startswith("trojan://"):
        m = re.match(r".*?@([^:]+):(\d+)", link)
        if m: host, port = m.group(1), int(m.group(2))
    elif link.startswith("ss://"):
        m = re.match(r"ss://.*?@([^:]+):(\d+)", link)
        if m: host, port = m.group(1), int(m.group(2))

    if not host or not port:
        return (link, False)
    return (link, check_tcp(host, port))

if __name__ == "__main__":
    accounts = []

    # baca isi akun.txt
    with open("akun.txt") as f:
        raw = [line.strip() for line in f if line.strip()]

    # kalau isinya URL, fetch sub-akun
    for item in raw:
        if item.startswith("http://") or item.startswith("https://"):
            accounts.extend(fetch_subscription(item))
        else:
            accounts.append(item)

    print(f"🔍 Total akun/sub-akun yang dicek: {len(accounts)}")

    active = []
    with ThreadPoolExecutor(max_workers=50) as executor:
        futures = [executor.submit(check_account, acc) for acc in accounts]
        for future in as_completed(futures):
            acc, status = future.result()
            if status:
                active.append(acc)

    with open("active_all.txt", "w") as f:
        f.write("\n".join(active))

    print(f"\n✅ Total aktif: {len(active)} / {len(accounts)}")
