import requests, subprocess, tempfile, json, time, os, re, base64
from concurrent.futures import ThreadPoolExecutor, as_completed

AKUN_FILE = "akun.txt"
OUTPUT_FILE = "active_all.txt"
MAX_WORKERS = 10
TIMEOUT = 5
RETRY = 1

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

# decode vmess link
def decode_vmess(link):
    try:
        data = base64.urlsafe_b64decode(link.replace("vmess://","") + "==").decode()
        return json.loads(data)
    except: return None

# build outbound sesuai akun
def make_outbound(link):
    if link.startswith("vmess://"):
        vmess = decode_vmess(link)
        if not vmess: return None
        net = vmess.get("net","tcp")
        tls = "tls" if vmess.get("tls","").lower()=="tls" else ""
        path = vmess.get("path","")
        return {"protocol":"vmess","settings":{"vnext":[{"address":vmess["add"],"port":int(vmess["port"]),"users":[{"id":vmess["id"],"alterId":int(vmess.get("aid",0))}]}]},"streamSettings":{"network":net,"security":tls,"wsSettings":{"path":path}}}
    elif link.startswith("vless://"):
        m = re.match(r"vless://(.+)@([\w\.\-]+):(\d+)\??(.*)", link)
        if not m: return None
        uid, addr, port, params = m.groups()
        query = dict(x.split("=") for x in params.split("&") if "=" in x)
        net = query.get("type","tcp")
        path = query.get("path","")
        tls = "tls" if query.get("security","")=="tls" else ""
        host = query.get("host","")
        return {"protocol":"vless","settings":{"vnext":[{"address":addr,"port":int(port),"users":[{"id":uid,"encryption":"none"}]}]},"streamSettings":{"network":net,"security":tls,"wsSettings":{"path":path,"headers":{"Host":host}}}}        
    elif link.startswith("trojan://"):
        m = re.match(r"trojan://(.+)@([\w\.\-]+):(\d+)\??(.*)", link)
        if not m: return None
        passwd, addr, port, params = m.groups()
        query = dict(x.split("=") for x in params.split("&") if "=" in x)
        path = query.get("path","")
        sni = query.get("sni","")
        return {"protocol":"trojan","settings":{"servers":[{"address":addr,"port":int(port),"password":passwd}]},"streamSettings":{"network":"ws","security":"tls","wsSettings":{"path":path,"headers":{"Host":sni}}}}
    elif link.startswith("ss://"):
        return {"protocol":"shadowsocks","settings":{"servers":[{"address":"127.0.0.1","port":8388,"method":"aes-256-gcm","password":"test"}]}}
    return None

# check akun
def check_account(link):
    outbound = make_outbound(link)
    if not outbound: return None
    for _ in range(RETRY+1):
        tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".json")
        cfg = {"log":{"loglevel":"warning"},"inbounds":[{"port":10808,"listen":"127.0.0.1","protocol":"socks"}],"outbounds":[outbound]}
        json.dump(cfg, open(tmp.name,'w'))
        try:
            proc = subprocess.Popen(["xray","-c",tmp.name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            time.sleep(1.5)
            test = subprocess.run(
                ["curl","-x","socks5h://127.0.0.1:10808","-m",str(TIMEOUT),"-s","-o","/dev/null","-w","%{http_code}","https://www.gstatic.com/generate_204"],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE
            )
            code = test.stdout.decode().strip()
            proc.kill()
            os.unlink(tmp.name)
            if code=="204":
                return link
        except:
            proc.kill()
            os.unlink(tmp.name)
    return None

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
