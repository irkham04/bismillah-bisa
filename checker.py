import base64
import json
import subprocess
import tempfile
import time
import os
import re

AKUN_FILE = "akun.txt"
OUTPUT_FILE = "active_all.txt"

def decode_vmess(link):
    try:
        raw = link.replace("vmess://", "")
        data = base64.urlsafe_b64decode(raw + "==").decode("utf-8")
        return json.loads(data)
    except Exception as e:
        print(f"[VMESS] Gagal decode: {e}")
        return None

def make_outbound(link):
    if link.startswith("vmess://"):
        vmess = decode_vmess(link)
        if not vmess:
            return None
        return {
            "protocol": "vmess",
            "settings": {
                "vnext": [{
                    "address": vmess["add"],
                    "port": int(vmess["port"]),
                    "users": [{
                        "id": vmess["id"],
                        "alterId": int(vmess.get("aid", 0)),
                        "security": vmess.get("scy", "auto")
                    }]
                }]
            },
            "streamSettings": {
                "network": vmess.get("net", "tcp"),
                "security": "tls" if vmess.get("tls", "") == "tls" else "none",
                "tlsSettings": {"allowInsecure": True}
            }
        }

    elif link.startswith("vless://"):
        # format: vless://uuid@server:port?encryption=none&security=tls#name
        m = re.match(r"vless://(.+)@([\w\.\-]+):(\d+)\??(.*)", link)
        if not m:
            return None
        uuid, addr, port, params = m.groups()
        return {
            "protocol": "vless",
            "settings": {
                "vnext": [{
                    "address": addr,
                    "port": int(port),
                    "users": [{
                        "id": uuid,
                        "encryption": "none"
                    }]
                }]
            },
            "streamSettings": {
                "network": "tcp",
                "security": "tls",
                "tlsSettings": {"allowInsecure": True}
            }
        }

    elif link.startswith("trojan://"):
        # format: trojan://password@server:port?peer=xxx#name
        m = re.match(r"trojan://(.+)@([\w\.\-]+):(\d+)", link)
        if not m:
            return None
        passwd, addr, port = m.groups()
        return {
            "protocol": "trojan",
            "settings": {
                "servers": [{
                    "address": addr,
                    "port": int(port),
                    "password": passwd
                }]
            },
            "streamSettings": {
                "security": "tls",
                "tlsSettings": {"allowInsecure": True}
            }
        }

    elif link.startswith("ss://"):
        # untuk simplicity, skip detail parsing, asumsi ss:// sudah benar
        return {
            "protocol": "shadowsocks",
            "settings": {
                "servers": [{
                    "address": "127.0.0.1",  # harus parsing detail base64, bisa ditambah nanti
                    "port": 8388,
                    "method": "aes-256-gcm",
                    "password": "test"
                }]
            }
        }
    return None

def check_delay(outbound):
    cfg = {
        "log": {"loglevel": "warning"},
        "inbounds": [{
            "port": 10808,
            "listen": "127.0.0.1",
            "protocol": "socks"
        }],
        "outbounds": [outbound]
    }

    tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".json")
    with open(tmp.name, "w") as f:
        json.dump(cfg, f)

    start = time.time()
    try:
        proc = subprocess.Popen(
            ["xray", "-c", tmp.name],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        time.sleep(1.5)  # kasih waktu xray boot

        test = subprocess.run(
            ["curl", "-x", "socks5h://127.0.0.1:10808", "-m", "8", "-o", "/dev/null", "-s", "-w", "%{http_code}", "https://www.google.com"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        code = test.stdout.decode().strip()
        if code == "200":
            delay = int((time.time() - start) * 1000)
            return delay
        else:
            return None
    except Exception:
        return None
    finally:
        proc.kill()
        os.unlink(tmp.name)

def main():
    with open(AKUN_FILE, "r") as f:
        accounts = [x.strip() for x in f if x.strip()]

    results = []
    for acc in accounts:
        outbound = make_outbound(acc)
        if not outbound:
            continue
        delay = check_delay(outbound)
        if delay:
            print(f"✅ {acc[:40]}... aktif, {delay} ms")
            results.append(f"{acc}    ✅ {delay}ms")
        else:
            print(f"❌ {acc[:40]}... gagal")

    with open(OUTPUT_FILE, "w") as f:
        f.write("\n".join(results))

    print(f"\n🔍 Total dicek: {len(accounts)}")
    print(f"✅ Total aktif: {len(results)}")

if __name__ == "__main__":
    main()
