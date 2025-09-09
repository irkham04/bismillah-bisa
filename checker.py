import base64
import json
import subprocess
import tempfile
import time
import os
import re
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed

AKUN_FILE = "akun.txt"
OUTPUT_FILE = "active_all.txt"
MAX_WORKERS = 10  # jumlah akun dicek paralel
TIMEOUT = 10      # timeout per akun
RETRY = 1         # retry kalau gagal

# ================== LOAD AKUN ==================
def load_accounts(filename):
    accounts = []
    with open(filename, "r") as f:
        lines = [x.strip() for x in f if x.strip()]

    for line in lines:
        if line.startswith("http://") or line.startswith("https://"):
            try:
                r = requests.get(line, timeout=TIMEOUT)
                if r.status_code == 200:
                    subs = r.text.strip().splitlines()
                    for s in subs:
                        if s.startswith(("vmess://", "vless://", "trojan://", "ss://")):
                            accounts.append(s.strip())
            except Exception:
                continue
        else:
            parts = re.split(r"\s+", line)
            for p in parts:
                if p.startswith(("vmess://", "vless://", "trojan://", "ss://")):
                    accounts.append(p.strip())
    return accounts

# ================== DECODE VMESS ==================
def decode_vmess(link):
    try:
        raw = link.replace("vmess://", "")
        data = base64.urlsafe_b64decode(raw + "==").decode("utf-8")
        return json.loads(data)
    except:
        return None

# ================== BUILD OUTBOUND ==================
def make_outbound(link):
    if link.startswith("vmess://"):
        vmess = decode_vmess(link)
        if not vmess:
            return None
        network = vmess.get("net", "tcp")
        tls = "tls" if vmess.get("tls", "").lower() == "tls" else "none"
        return {
            "protocol": "vmess",
            "settings": {"vnext":[{"address": vmess["add"], "port": int(vmess["port"]), "users":[{"id": vmess["id"], "alterId": int(vmess.get("aid",0))}]}]},
            "streamSettings": {"network": network, "security": tls, "tlsSettings":{"allowInsecure":True}}
        }
    elif link.startswith("vless://"):
        m = re.match(r"vless://(.+)@([\w\.\-]+):(\d+)\??(.*)", link)
        if not m:
            return None
        uuid, addr, port, params = m.groups()
        network = "tcp"
        tls = "tls"
        return {
            "protocol": "vless",
            "settings": {"vnext":[{"address": addr,"port": int(port),"users":[{"id": uuid,"encryption":"none"}]}]},
            "streamSettings":{"network": network,"security": tls,"tlsSettings":{"allowInsecure":True}}
        }
    elif link.startswith("trojan://"):
        m = re.match(r"trojan://(.+)@([\w\.\-]+):(\d+)", link)
        if not m:
            return None
        passwd, addr, port = m.groups()
        return {
            "protocol": "trojan",
            "settings":{"servers":[{"address": addr,"port":int(port),"password":passwd}]},
            "streamSettings":{"security":"tls","tlsSettings":{"allowInsecure":True}}
        }
    elif link.startswith("ss://"):
        return {
            "protocol":"shadowsocks",
            "settings":{"servers":[{"address":"127.0.0.1","port":8388,"method":"aes-256-gcm","password":"test"}]}
        }
    return None

# ================== CHECK DELAY ==================
def check_account(link):
    outbound = make_outbound(link)
    if not outbound:
        return None
    for _ in range(RETRY+1):
        tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".json")
        json.dump({"log":{"loglevel":"warning"},"inbounds":[{"port":10808,"listen":"127.0.0.1","protocol":"socks"}],"outbounds":[outbound]}, open(tmp.name,'w'))
        try:
            proc = subprocess.Popen(["xray","-c",tmp.name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            time.sleep(1.5)
            test = subprocess.run(
                ["curl","-x","socks5h://127.0.0.1:10808","-m", str(TIMEOUT), "-s", "-o","/dev/null","-w","%{http_code}","https://www.gstatic.com/generate_204"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            code = test.stdout.decode().strip()
            proc.kill()
            os.unlink(tmp.name)
            if code == "204":
                delay = int(time.time()*1000)
                return f"{link} ✅ {delay}ms"
        except:
            proc.kill()
            os.unlink(tmp.name)
            continue
    return None

# ================== MAIN ==================
def main():
    accounts = load_accounts(AKUN_FILE)
    results = []

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        future_to_acc = {executor.submit(check_account, acc): acc for acc in accounts}
        for future in as_completed(future_to_acc):
            res = future.result()
            if res:
                print(res)
                results.append(res)

    with open(OUTPUT_FILE,"w") as f:
        f.write("\n".join(results))

    print(f"\n🔍 Total dicek: {len(accounts)}")
    print(f"✅ Total aktif: {len(results)}")

if __name__=="__main__":
    main()
