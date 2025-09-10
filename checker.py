import os, json, tempfile, socket, time, random, re, base64, requests, yaml
from concurrent.futures import ThreadPoolExecutor
import subprocess

# ===================== Konfigurasi =====================
AKUN_FILE = "akun.txt"
OUTPUT_DIR = "output"
OUTPUT_FILE = os.path.join(OUTPUT_DIR, "active_all.txt")
CLASH_FILE = os.path.join(OUTPUT_DIR, "clash_config.yaml")
MAX_WORKERS = 50
TIMEOUT = 20
RETRY = 2
BASE_PORT = 10808
NEW_ADDR = "quiz.vidio.com"
V2RAY_BINARY = "./v2rayN/v2rayN-linux-arm64/bin/xray/xray"

# ===================== Load akun =====================
def load_accounts(filename):
    accounts = []
    with open(filename) as f:
        for line in f:
            line = line.strip()
            if not line: continue
            if line.startswith(("vmess://","vless://","trojan://","ss://")):
                accounts.append(line)
            elif line.startswith("http"):
                try:
                    resp = requests.get(line, timeout=15)
                    resp.raise_for_status()
                    for subline in resp.text.splitlines():
                        subline = subline.strip()
                        if subline.startswith(("vmess://","vless://","trojan://","ss://")):
                            accounts.append(subline)
                except Exception as e:
                    print(f"Gagal ambil sub dari {line}: {e}")
    return accounts

# ===================== Decode Vmess =====================
def decode_vmess(link):
    try:
        raw = link.replace("vmess://","")
        b64 = raw + "=" * (-len(raw)%4)
        return json.loads(base64.urlsafe_b64decode(b64).decode())
    except:
        return None

# ===================== Make outbound =====================
def make_outbound(link):
    if link.startswith("vmess://"):
        vmess = decode_vmess(link)
        if not vmess: return None
        return {"protocol":"vmess","settings":{"vnext":[{"address":vmess["add"],"port":int(vmess["port"]),
            "users":[{"id":vmess["id"],"alterId":int(vmess.get("aid",0)),"flow":vmess.get("flow",""),"security":"auto"}]}]}}
    elif link.startswith("vless://"):
        m = re.match(r"vless://(.+)@([\w\.\-]+):(\d+)\??(.*)", link)
        if not m: return None
        uid, addr, port, _ = m.groups()
        return {"protocol":"vless","settings":{"vnext":[{"address":addr,"port":int(port),
            "users":[{"id":uid,"encryption":"none"}]}]}}
    elif link.startswith("trojan://"):
        m = re.match(r"trojan://(.+)@([\w\.\-]+):(\d+)", link)
        if not m: return None
        passwd, addr, port = m.groups()
        return {"protocol":"trojan","settings":{"servers":[{"address":addr,"port":int(port),"password":passwd}]}}
    elif link.startswith("ss://"):
        try:
            ss = link[5:].split('#')[0]
            if '@' in ss:
                method_pass, server_port = ss.split('@')
                method, password = base64.urlsafe_b64decode(method_pass+"==").decode().split(':',1)
                server, port = server_port.split(':')
                return {"protocol":"shadowsocks","settings":{"servers":[{"address":server,"port":int(port),
                        "method":method,"password":password}]}}
        except:
            return None
    return None

# ===================== Check port =====================
def is_port_in_use(port):
    with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as s:
        return s.connect_ex(('127.0.0.1',port)) == 0

# ===================== Replace address =====================
def replace_address(link):
    if link.startswith("vmess://"):
        try:
            raw = link[7:]
            b64 = raw + "=" * (-len(raw)%4)
            data = base64.urlsafe_b64decode(b64).decode()
            vmess = json.loads(data)
            vmess["add"] = NEW_ADDR
            new_b64 = base64.urlsafe_b64encode(json.dumps(vmess).encode()).decode()
            return "vmess://" + new_b64
        except: return link
    elif link.startswith(("vless://","trojan://")):
        m = re.match(r"(.+@)([^:/]+)(:\d+.*)", link)
        if m: return m.group(1)+NEW_ADDR+m.group(3)
    elif link.startswith("ss://"):
        try:
            ss = link[5:]
            if '@' in ss:
                method_pass, server_port = ss.split('@')
                server_port = server_port.split(':')
                server_port[0] = NEW_ADDR
                return "ss://"+method_pass+"@"+":".join(server_port)
        except: return link
    return link

# ===================== Convert ke Clash =====================
def to_clash(link, name="Proxy"):
    if link.startswith("vmess://"):
        vmess = decode_vmess(link)
        if not vmess: return None
        return {"name":name,"type":"vmess","server":vmess["add"],"port":int(vmess["port"]),
                "uuid":vmess["id"],"alterId":int(vmess.get("aid",0)),"cipher":"auto",
                "tls": True if vmess.get("tls","")=="tls" else False,
                "network": vmess.get("net","ws"),"ws-opts":{"path":vmess.get("path","/")}}
    elif link.startswith("vless://"):
        m = re.match(r"vless://(.+)@([\w\.\-]+):(\d+)", link)
        if not m: return None
        uid, addr, port = m.groups()
        return {"name":name,"type":"vless","server":addr,"port":int(port),"uuid":uid,"tls":True,"network":"ws"}
    elif link.startswith("trojan://"):
        m = re.match(r"trojan://(.+)@([\w\.\-]+):(\d+)", link)
        if not m: return None
        pwd, addr, port = m.groups()
        return {"name":name,"type":"trojan","server":addr,"port":int(port),"password":pwd,"sni":addr}
    elif link.startswith("ss://"):
        return {"name":name,"type":"ss","server":NEW_ADDR,"port":443,"cipher":"aes-128-gcm","password":"password123"}
    return None

def save_clash(pr_
