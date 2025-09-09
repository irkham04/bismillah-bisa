import requests, subprocess, tempfile, json, time, os, re, base64, socket, random
from concurrent.futures import ThreadPoolExecutor, as_completed

AKUN_FILE = "akun.txt"
OUTPUT_FILE = "active_all.txt"
OUTPUT_QUIZ_FILE = "active_quiz.txt"
MAX_WORKERS = 5
TIMEOUT = 10
SLEEP_TIME = 3
RETRY = 3
BASE_PORT = 10808
ENDPOINTS = ["http://cp.cloudflare.com/generate_204", "http://www.google.com/generate_204"]
NEW_ADDR = "quiz.vidio.com"

# Load akun / sub-link
def load_accounts(filename):
    accounts = []
    with open(filename) as f:
        for line in f:
            line = line.strip()
            if not line: continue
            if line.startswith("http"):
                try:
                    r = requests.get(line, timeout=TIMEOUT)
                    if r.status_code == 200:
                        for s in r.text.splitlines():
                            if s.startswith(("vmess://","vless://","trojan://","ss://")):
                                accounts.append(s.strip())
                except: continue
            else:
                if line.startswith(("vmess://","vless://","trojan://","ss://")):
                    accounts.append(line)
    return accounts

# decode vmess
def decode_vmess(link):
    try:
        b64 = link.replace("vmess://","")
        b64 += '=' * (-len(b64) % 4)
        data = base64.urlsafe_b64decode(b64).decode()
        vmess = json.loads(data)
        vmess["flow"] = vmess.get("flow", "")
        return vmess
    except: return None

# build outbound
def make_outbound(link):
    if link.startswith("vmess://"):
        vmess = decode_vmess(link)
        if not vmess: return None
        net = vmess.get("net","tcp")
        tls = "tls" if vmess.get("tls", False) else ""
        path = vmess.get("path","")
        flow = vmess.get("flow", "")
        stream = {"network": net, "security": tls}
        if net == "ws":
            stream["wsSettings"] = {"path": path}
        return {"protocol":"vmess",
                "settings":{"vnext":[{"address":vmess["add"],"port":int(vmess["port"]),
                                       "users":[{"id":vmess["id"],"alterId":int(vmess.get("aid",0)), "flow": flow, "security": "auto"}]}]},
                "streamSettings": stream}

    elif link.startswith("vless://"):
        m = re.match(r"vless://(.+)@([\w\.\-]+):(\d+)\??(.*)", link)
        if not m: return None
        uid, addr, port, params = m.groups()
        query = dict(x.split("=") for x in params.split("&") if "=" in x)
        net = query.get("type","tcp")
        path = query.get("path","")
        tls = "tls" if query.get("security","")=="tls" else ""
        host = query.get("host","")
        flow = query.get("flow", "")
        stream = {"network": net, "security": tls}
        if net == "ws":
            stream["wsSettings"] = {"path": path, "headers": {"Host": host}}
        elif net == "grpc":
            stream["grpcSettings"] = {"serviceName": path}
        return {"protocol":"vless",
                "settings":{"vnext":[{"address":addr,"port":int(port),
                                       "users":[{"id":uid,"encryption":"none", "flow": flow}]}]},
                "streamSettings": stream}

    elif link.startswith("trojan://"):
        m = re.match(r"trojan://(.+)@([\w\.\-]+):(\d+)\??(.*)", link)
        if not m: return None
        passwd, addr, port, params = m.groups()
        query = dict(x.split("=") for x in params.split("&") if "=" in x)
        net = query.get("type", "tcp")
        path = query.get("path","")
        sni = query.get("sni", addr)
        stream = {"network": net, "security": "tls", "tlsSettings": {"serverName": sni}}
        if net == "ws":
            stream["wsSettings"] = {"path": path, "headers": {"Host": sni}}
        return {"protocol":"trojan",
                "settings":{"servers":[{"address":addr,"port":int(port),"password":passwd}]},
                "streamSettings": stream}

    elif link.startswith("ss://"):
        try:
            part = link[5:].split('#')[0]
            if '@' in part:
                b64, server_port = part.split('@')
                method_pass = base64.urlsafe_b64decode(b64 + "==").decode()
                method, password = method_pass.split(':', 1)
                server, port = server_port.split(':')
                return {"protocol": "shadowsocks",
                        "settings": {"servers": [{"address": server, "port": int(port), "method": method, "password": password}]}}
            else:
                m = re.match(r"(.+):(.+)@(.+):(\d+)", part)
                if m:
                    method, password, server, port = m.groups()
                    return {"protocol": "shadowsocks",
                            "settings": {"servers": [{"address": server, "port": int(port), "method": method, "password": password}]}}
        except: return None
    return None

# check akun
def check_account(link):
    outbound = make_outbound(link)
    if not outbound:
        print(f"❌ Invalid config: {link[:50]}...")
        return None
    
    for attempt in range(RETRY + 1):
        port = BASE_PORT + random.randint(0, 1000)
        while is_port_in_use(port):
            port += 1
        
        tmp = None
        proc = None
        try:
            tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".json")
            cfg = {
                "log": {"loglevel": "info"},
                "inbounds": [{"port": port, "listen": "127.0.0.1", "protocol": "socks"}],
                "outbounds": [outbound, {"protocol": "freedom"}]
            }
            with open(tmp.name, 'w') as f:
                json.dump(cfg, f)
            
            print(f"🔄 Testing {link[:50]}... (attempt {attempt+1})")
            proc = subprocess.Popen(["xray", "-c", tmp.name], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
            time.sleep(SLEEP_TIME)
            
            success = False
            for endpoint in ENDPOINTS:
                test = subprocess.run(
                    ["curl", "-x", f"socks5h://127.0.0.1:{port}", "-m", str(TIMEOUT), "-s", "-o", "/dev/null",
                     "-w", "%{http_code} %{time_total}", endpoint],
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
                )
                output = test.stdout.strip()
                code, response_time = output.split() if ' ' in output else (output, "0")
                
                if code == "204" and float(response_time) < 10:
                    ip_test = subprocess.run(
                        ["curl", "-x", f"socks5h://127.0.0.1:{port}", "-m", "5", "-s", "http://ipinfo.io/ip"],
                        stdout=subprocess.PIPE, text=True
                    )
                    if ip_test.stdout.strip():
                        success = True
                    break
            
            if success:
                return link
        
        except Exception as e:
            print(f"   Error: {e}")
        finally:
            if proc:
                proc.kill()
                proc.wait()
            if tmp:
                os.unlink(tmp.name)
    
    print(f"❌ Failed after {RETRY+1} tries: {link[:50]}...")
    return None

def is_port_in_use(port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        return s.connect_ex(('127.0.0.1', port)) == 0

# Ganti address ke NEW_ADDR
def replace_address(line):
    line = line.strip()
    if line.startswith("vmess://"):
        b64 = line[7:]
        b64 += '=' * (-len(b64) % 4)
        data = base64.urlsafe_b64decode(b64).decode()
        vmess = json.loads(data)
        vmess["add"] = NEW_ADDR
        new_data = json.dumps(vmess)
        new_b64 = base64.urlsafe_b64encode(new_data.encode()).decode()
        return "vmess://" + new_b64

    elif line.startswith("vless://"):
        m = re.match(r"(vless://.+@)([^:/]+)(:\d+.*)", line)
        if m:
            return m.group(1) + NEW_ADDR + m.group(3)
    
    elif line.startswith("trojan://"):
        m = re.match(r"(trojan://.+@)([^:/]+)(:\d+.*)", line)
        if m:
            return m.group(1) + NEW_ADDR + m.group(3)

    elif line.startswith("ss://"):
        try:
            ss = line[5:]
            if '@' in ss:
                method_pass, server_port = ss.split('@')
                server_port = server_port.split(':')
                server_port[0] = NEW_ADDR
                return "ss://" + method_pass + "@" + ":".join(server_port)
        except:
            return line
    return line

def main():
    accounts = load_accounts(AKUN_FILE)
    results = []
    results_quiz = []

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        future_to_acc = {executor.submit(check_account, acc): acc for acc in accounts}
        for future in as_completed(future_to_acc):
            res = future.result()
            if res:
                print(f"🎉 Active: {res}")
                results.append(res)
                results_quiz.append(replace_address(res))

    # Simpan akun aktif asli
    with open(OUTPUT_FILE, "w") as f:
        f.write("\n".join(results))

    # Simpan akun aktif dengan address diganti
    with open(OUTPUT_QUIZ_FILE, "w") as f:
        f.write("\n".join(results_quiz))

    print(f"\n🔍 Total dicek: {len(accounts)}")
    print(f"✅ Total aktif: {len(results)}")
    print(f"✅ Total aktif dengan address diganti: {len(results_quiz)}")

if __name__ == "__main__":
    main()
