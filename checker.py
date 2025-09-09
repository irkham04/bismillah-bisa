import socket
import ssl
import base64
import json
import re
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed

def fetch_subscription(url):
    try:
        r = requests.get(url, timeout=15)
        r.raise_for_status()
        data = r.text.strip()
        try:
            decoded = base64.b64decode(data).decode()
            return [line.strip() for line in decoded.splitlines() if line.strip()]
        except:
            return [line.strip() for line in data.splitlines() if line.strip()]
    except Exception as e:
        print(f"[!] Gagal fetch {url}: {e}")
        return []

def parse_vmess(link):
    try:
        raw = link[8:]
        data = base64.b64decode(raw + "=" * (-len(raw) % 4)).decode()
        return json.loads(data)
    except Exception as e:
        print(f"[!] Gagal parse vmess: {e}")
        return {}

def check_connection(host, port, use_tls=False, timeout=8):
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        if use_tls:
            context = ssl.create_default_context()
            sock = context.wrap_socket(sock, server_hostname=host)
        sock.close()
        return True
    except:
        return False

def check_account(link):
    host, port, use_tls = None, None, False

    if link.startswith("vmess://"):
        cfg = parse_vmess(link)
        host = cfg.get("add")
        port = int(cfg.get("port", 0) or 0)
        # Fix: TLS bisa string "tls" atau boolean true
        if str(cfg.get("tls", "")).lower() in ["tls", "true"]:
            use_tls = True

    elif link.startswith("vless://") or link.startswith("trojan://"):
        m = re.match(r".*?@([^:]+):(\d+)", link)
        if m:
            host, port = m.group(1), int(m.group(2))
            use_tls = True

    elif link.startswith("ss://"):
        m = re.match(r"ss://.*?@([^:]+):(\d+)", link)
        if m:
            host, port = m.group(1), int(m.group(2))

    if not host or not port:
        return (link, False)

    status = check_connection(host, port, use_tls)
    return (link, status)

if __name__ == "__main__":
    accounts = []

    with open("akun.txt") as f:
        raw = [line.strip() for line in f if line.strip()]

    for item in raw:
        if item.startswith("http://") or item.startswith("https://"):
            accounts.extend(fetch_subscription(item))
        else:
            accounts.append(item)

    print(f"🔍 Total akun/sub-akun dicek: {len(accounts)}")

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
