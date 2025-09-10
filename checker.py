import asyncio, json, tempfile, os, re, base64, random, socket, time
from concurrent.futures import ThreadPoolExecutor

AKUN_FILE = "akun.txt"
OUTPUT_FILE = "active_all.txt"
OUTPUT_QUIZ_FILE = "active_quiz.txt"
MAX_WORKERS = 50
TIMEOUT = 10
BASE_PORT = 10808
NEW_ADDR = "quiz.vidio.com"

def load_accounts(filename):
    accounts = []
    with open(filename) as f:
        for line in f:
            line = line.strip()
            if not line: continue
            if line.startswith(("vmess://","vless://","trojan://","ss://")):
                accounts.append(line)
    return accounts

def decode_vmess(link):
    try:
        b64 = link.replace("vmess://","") + '=' * (-len(link)%4)
        data = base64.urlsafe_b64decode(b64).decode()
        vmess = json.loads(data)
        vmess["flow"] = vmess.get("flow","")
        return vmess
    except:
        return None

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
                b64, server_port = ss.split('@')
                method_pass = base64.urlsafe_b64decode(b64 + "==").decode()
                method, password = method_pass.split(':',1)
                server, port = server_port.split(':')
                return {"protocol":"shadowsocks","settings":{"servers":[{"address":server,"port":int(port),
                        "method":method,"password":password}]}}
        except:
            return None
    return None

def is_port_in_use(port):
    with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as s:
        return s.connect_ex(('127.0.0.1',port)) == 0

def replace_address_all(line):
    line = line.strip().split('#')[0]
    delay = line.split('#')[1] if '#' in line else None
    if line.startswith("vmess://"):
        try:
            b64 = line[7:] + '=' * (-len(line)%4)
            data = base64.urlsafe_b64decode(b64).decode()
            vmess = json.loads(data)
            vmess["add"] = NEW_ADDR
            new_b64 = base64.urlsafe_b64encode(json.dumps(vmess).encode()).decode()
            result = "vmess://" + new_b64
        except: result = line
    elif line.startswith(("vless://","trojan://")):
        m = re.match(r"(.+@)([^:/]+)(:\d+.*)", line)
        if m: result = m.group(1)+NEW_ADDR+m.group(3)
        else: result = line
    elif line.startswith("ss://"):
        try:
            ss = line[5:]
            if '@' in ss:
                method_pass, server_port = ss.split('@')
                server_port = server_port.split(':')
                server_port[0] = NEW_ADDR
                result = "ss://"+method_pass+"@"+":".join(server_port)
            else: result = line
        except: result=line
    else: result=line
    if delay: result += f"#{delay}"
    return result

def check_account(link):
    outbound = make_outbound(link)
    if not outbound: return None
    port = BASE_PORT + random.randint(0,1000)
    while is_port_in_use(port):
        port += 1
    tmp = tempfile.NamedTemporaryFile(delete=False,suffix=".json")
    cfg = {"log":{"loglevel":"none"},"inbounds":[{"port":port,"listen":"127.0.0.1","protocol":"socks"}],
           "outbounds":[outbound,{"protocol":"freedom"}]}
    with open(tmp.name,'w') as f: json.dump(cfg,f)
    import subprocess
    proc = subprocess.Popen(["xray","-c",tmp.name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    start = time.time()
    success = False
    try:
        sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        sock.settimeout(TIMEOUT)
        try:
            sock.connect(("127.0.0.1",port))
            success = True
        except:
            success = False
        finally:
            sock.close()
    except:
        success=False
    end = time.time()
    proc.kill()
    proc.wait()
    os.unlink(tmp.name)
    if success:
        latency = int((end-start)*1000)
        return latency, link
    return None

def main():
    accounts = load_accounts(AKUN_FILE)
    results=[]
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        future_to_acc={executor.submit(check_account,acc):acc for acc in accounts}
        for future in future_to_acc:
            try:
                r = future.result()
                if r: results.append(r)
            except: continue
    results.sort(key=lambda x:x[0])
    with open(OUTPUT_FILE,'w') as f, open(OUTPUT_QUIZ_FILE,'w') as fq:
        for latency,link in results:
            line=f"{link}#{latency}ms"
            f.write(line+"\n")
            fq.write(replace_address_all(line)+"\n")
    print(f"Total dicek: {len(accounts)}")
    print(f"Total aktif: {len(results)}")

if __name__=="__main__":
    main()
