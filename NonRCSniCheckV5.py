import socket
import ssl
import requests
import time
import threading
import queue
import sys
import os
import subprocess

print_lock = threading.Lock()
SCORE_DNS_OK = 20
SCORE_TLS_OK = 20
SCORE_CURL_OK = 20
SCORE_DATA_PASS = 40

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

def curl_tls_debug(host):
    try:
        cmd = ["curl", "-vk", "--connect-timeout", "5", f"https://{host}"]
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=10)
        output = result.stdout
        if "SSL connection using" in output:
            return True, output
        else:
            return False, output
    except Exception as e:
        return False, str(e)

def data_pass_check(host):
    try:
        url = f"https://{host}"
        response = requests.get(url, timeout=5)
        if response.status_code in [200, 301, 302]:
            redirect = detect_isp_redirect(response.text, response.headers)
            return True, response.elapsed.total_seconds(), redirect
        else:
            return False, None, False
    except:
        return False, None, False

def detect_isp_redirect(text, headers):
    indicators = ["airtel", "jio", "vi", "vodafone", "recharge", "selfcare"]
    if any(ind in text.lower() for ind in indicators):
        return True
    if 'Location' in headers:
        loc = headers.get('Location')
        if any(ind in loc for ind in indicators):
            return True
    return False

def bug_scan(domain, result_list):
    score = 0
    dns_status = dns_check(domain)
    tls_status = False
    curl_status = False
    data_status = False
    latency = None
    isp_redirect = False

    if dns_status:
        score += SCORE_DNS_OK
        tls_status = tls_handshake(domain)
        if tls_status:
            score += SCORE_TLS_OK
            curl_status, curl_output = curl_tls_debug(domain)
            if curl_status:
                score += SCORE_CURL_OK
                data_status, latency, isp_redirect = data_pass_check(domain)
                if data_status and not isp_redirect:
                    score += SCORE_DATA_PASS

    with print_lock:
        print(f"\n[SCAN RESULT] {domain}")
        print(f"DNS: {'OK' if dns_status else 'FAIL'} | TLS: {'OK' if tls_status else 'FAIL'} | Curl TLS: {'OK' if curl_status else 'FAIL'} | Data: {'OK' if data_status else 'FAIL'}")
        if latency:
            print(f"Latency: {latency:.2f}s")
        print(f"ISP Redirect: {'Yes' if isp_redirect else 'No'}")
        print(f"Bug Score: {score}%")

        result_list.append({
            'domain': domain,
            'dns': dns_status,
            'tls': tls_status,
            'curl': curl_status,
            'data': data_status,
            'latency': latency,
            'redirect': isp_redirect,
            'score': score
        })

def worker(q, result_list):
    while not q.empty():
        domain = q.get()
        bug_scan(domain, result_list)
        q.task_done()

def load_domains():
    while True:
        clear()
        print("TSHACKER - SNI Bug Finder v8.5")
        print("[1] Enter domain manually")
        print("[2] Enter multiple domains (comma-separated)")
        print("[3] Load domains from file")
        print("[4] Exit")
        choice = input("\nYour choice: ").strip()

        domains = []

        if choice == '1':
            domain = input("Enter domain: ").strip()
            domains.append(domain)
            return domains
        elif choice == '2':
            data = input("Enter domains (comma-separated): ").strip()
            domains = [d.strip() for d in data.split(',') if d.strip()]
            return domains
        elif choice == '3':
            path = input("Enter file path (e.g. hosts.txt): ").strip()
            if os.path.isfile(path):
                with open(path) as f:
                    domains = [line.strip() for line in f if line.strip()]
                return domains
            else:
                print("❌ File not found. Press Enter to try again.")
                input()
        elif choice == '4':
            print("Exiting...")
            sys.exit(0)
        else:
            print("❌ Invalid choice. Press Enter to try again.")
            input()

def run_scan(domains):
    q = queue.Queue()
    result_list = []

    for d in domains:
        q.put(d)

    try:
        thread_count = int(input("Enter thread count (e.g. 10): ").strip())
    except:
        print("Invalid thread count. Defaulting to 5.")
        thread_count = 5

    threads = []
    for _ in range(thread_count):
        t = threading.Thread(target=worker, args=(q, result_list))
        t.start()
        threads.append(t)

    q.join()

    # Summary
    print("\n=== FINAL SCAN REPORT ===")
    for r in result_list:
        print(f"{r['domain']} | Score: {r['score']}% | DNS: {r['dns']} | TLS: {r['tls']} | Curl: {r['curl']} | Data: {r['data']} | Redirect: {r['redirect']} | Latency: {r['latency']}")

    # Save report
    with open("bug_scan_report.txt", "w") as f:
        for r in result_list:
            f.write(f"{r['domain']} | Score: {r['score']}% | DNS: {r['dns']} | TLS: {r['tls']} | Curl: {r['curl']} | Data: {r['data']} | Redirect: {r['redirect']} | Latency: {r['latency']}\n")

    print("\n✅ Report saved to bug_scan_report.txt")

    # Exit / Back choice
    while True:
        print("\nWhat do you want to do next?")
        print("[1] Back to main menu")
        print("[2] Exit")
        next_choice = input("Your choice: ").strip()

        if next_choice == '1':
            return
        elif next_choice == '2':
            print("Exiting... Thank you!")
            sys.exit(0)
        else:
            print("❌ Invalid choice. Try again.")

def main():
    while True:
        domains = load_domains()
        run_scan(domains)

if __name__ == "__main__":
    main()
