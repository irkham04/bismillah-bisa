import requests, subprocess, tempfile, json, time, os
from concurrent.futures import ThreadPoolExecutor, as_completed

AKUN_FILE = "akun.txt"
OUTPUT_FILE = "active_all.txt"
MAX_WORKERS = 10
TIMEOUT = 5
RETRY = 1

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

# Test akun dengan Xray + curl
def check_account(link):
    for _ in range(RETRY+1):
        tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".json")
        cfg = {"log":{"loglevel":"warning"},"inbounds":[{"port":10808,"listen":"127.0.0.1","protocol":"socks"}],"outbounds":[{"protocol":"freedom","settings":{}}]}
        json.dump(cfg, open(tmp.name,'w'))
        try:
            proc = subprocess.Popen(["xray","-c",tmp.name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            time.sleep(1.0)
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

# Main
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
