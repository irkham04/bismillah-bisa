import socket
import base64
import json
import re

def parse_vmess(link):
    try:
        data = base64.b64decode(link.replace("vmess://", "")).decode()
        return json.loads(data)
    except:
        return {}

def check_tcp(host, port, timeout=5):
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
        host, port = cfg.get("add"), int(cfg.get("port", 0))
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
    with open("akun.txt") as f:
        accounts = [line.strip() for line in f if line.strip()]

    active = []
    for acc in accounts:
        acc, status = check_account(acc)
        if status:
            active.append(acc)

    with open("active_all.txt", "w") as f:
        f.write("\n".join(active))

    print(f"✅ Total aktif: {len(active)} / {len(accounts)}")
