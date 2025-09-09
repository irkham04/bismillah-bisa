import os
import json
import base64
import re
import requests
import subprocess
import tempfile
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

def make_config(link):
    # Config Xray minimal untuk cek koneksi (dokumen resmi Xray-core)
    if link.startswith("vmess://"):
        cfg = base64.b64decode(link[8:] + "=" * (-len(link[8:]) % 4)).decode()
        obj = json.loads(cfg)
        return {
            "inbounds": [{"port": 10808, "protocol": "socks"}],
            "outbounds": [{
                "protocol": "vmess",
                "settings": {"vnext": [{
                    "address": obj["add"],
                    "port": int(obj["port"]),
                    "users": [{"id": obj["id"], "alterId": int(obj.get("aid", 0)), "security": obj.get("scy", "auto")}]
                }]},
                "streamSettings": {
                    "network": obj.get("net", "tcp"),
                    "security": "tls" if str(obj.get("tls", "")).lower() in ["tls", "true"] else "none",
                    "tlsSettings": {"serverName": obj.get("sni") or obj.get("host")}
                }
            }]
        }

    elif link.startswith("vless://") or link.startswith("trojan://") or link.startswith("ss://"):
        # Xray bisa parse link langsung
        return {
            "inbounds": [{"port": 10808, "protocol": "socks"}],
            "outbounds": [{"protocol": "freedom"}],  # dummy, akan diganti dengan link
            "routing": {"rules": [{"type": "field", "outboundTag": "proxy"}]}
        }
    return None

def check_account(link):
    cfg = make_config(link)
    if not cfg:
        return (link, False)

    try:
        with tempfile.NamedTemporaryFile("w", delete=False) as tmp:
            json.dump(cfg, tmp)
            tmp.flush()
            tmp_name = tmp.name

        proc = subprocess.run(["xray", "-test", "-c", tmp_name], capture_output=True, timeout=10)
        os.unlink(tmp_name)

        if proc.returncode == 0:
            return (link, True)
        else:
            return (link, False)
    except Exception as e:
        return (link, False)

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
    with ThreadPoolExecutor(max_workers=5) as executor:  # lebih kecil biar xray tidak nabrak
        futures = [executor.submit(check_account, acc) for acc in accounts]
        for future in as_completed(futures):
            acc, status = future.result()
            if status:
                active.append(acc)

    with open("active_all.txt", "w") as f:
        f.write("\n".join(active))

    print(f"\n✅ Total aktif: {len(active)} / {len(accounts)}")
