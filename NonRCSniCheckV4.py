import socket
import ssl
import requests
import time
import threading
import queue
import sys
import os

# Output lock for clean multithreaded printing
print_lock = threading.Lock()

# Bug score thresholds
SCORE_DNS_OK = 20
SCORE_TLS_OK = 30
SCORE_DATA_PASS = 50

# Global variables
result_list = []

def clear():
    os.system('cls' if os.name == 'nt' else 'clear')

def dns_check(host):
    try:
        socket.gethostbyname(host)
        return True
    except:
        return False

def tls_handshake(host):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((host, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=host):
                return True
    except:
        return False

def data_pass_check(host):
    try:
        url = f"https://{host}"
        response = requests.get(url, timeout=5)
        if response.status_code in [200, 301, 302]:
            return True, response.elapsed.total_seconds()
        else:
            return False, None
    except:
        return False, None

def bug_scan(domain):
    score = 0
    dns_status = dns_check(domain)
    tls_status = False
    data_status = False
    latency = None

    if dns_status:
        score += SCORE_DNS_OK
        tls_status = tls_handshake(domain)
        if tls_status:
            score += SCORE_TLS_OK
            data_status, latency = data_pass_check(domain)
            if data_status:
                score += SCORE_DATA_PASS

    with print_lock:
        print(f"\n[SCAN RESULT] {domain}")
        print(f"DNS: {'OK' if dns_status else 'FAIL'} | TLS: {'OK' if tls_status else 'FAIL'} | Data Pass: {'OK' if data_status else 'FAIL'}")
        if latency:
            print(f"Latency: {latency:.2f}s")
        print(f"Bug Score: {score}%")

        result_list.append({
            'domain': domain,
            'dns': dns_status,
            'tls': tls_status,
            'data': data_status,
            'latency': latency,
            'score': score
        })

def worker(q):
    while not q.empty():
        domain = q.get()
        bug_scan(domain)
        q.task_done()

def load_domains():
    clear()
    print("TSHACKER - SNI Bug Finder v8.0")
    print("[1] Enter domain manually")
    print("[2] Enter multiple domains (comma-separated)")
    print("[3] Load domains from file")
    print("[4] Exit")
    choice = input("\nYour choice: ").strip()

    domains = []

    if choice == '1':
        domain = input("Enter domain: ").strip()
        domains.append(domain)

    elif choice == '2':
        data = input("Enter domains (comma-separated): ").strip()
        domains = [d.strip() for d in data.split(',') if d.strip()]

    elif choice == '3':
        path = input("Enter file path (e.g. hosts.txt): ").strip()
        if os.path.isfile(path):
            with open(path) as f:
                domains = [line.strip() for line in f if line.strip()]
        else:
            print("❌ File not found.")
            sys.exit(1)

    elif choice == '4':
        print("Exiting...")
        sys.exit(0)

    else:
        print("❌ Invalid choice.")
        sys.exit(1)

    return domains

def main():
    domains = load_domains()
    q = queue.Queue()
    for d in domains:
        q.put(d)

    thread_count = int(input("Enter thread count (e.g. 10): ").strip())

    threads = []
    for _ in range(thread_count):
        t = threading.Thread(target=worker, args=(q,))
        t.start()
        threads.append(t)

    q.join()

    # Summary
    print("\n=== FINAL SCAN REPORT ===")
    for r in result_list:
        print(f"{r['domain']} | Score: {r['score']}% | DNS: {r['dns']} | TLS: {r['tls']} | Data: {r['data']} | Latency: {r['latency']}")

    # Save report
    with open("bug_scan_report.txt", "w") as f:
        for r in result_list:
            f.write(f"{r['domain']} | Score: {r['score']}% | DNS: {r['dns']} | TLS: {r['tls']} | Data: {r['data']} | Latency: {r['latency']}\n")

    print("\n✅ Report saved to bug_scan_report.txt")

if __name__ == "__main__":
    main()
