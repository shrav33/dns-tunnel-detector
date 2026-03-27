import time
import random
import base64
import os
from datetime import datetime

random.seed()

NORMAL_DOMAINS = [
    "mail.google.com", "www.google.com", "api.github.com",
    "docs.python.org", "login.microsoft.com", "cdn.cloudflare.com",
    "fonts.googleapis.com", "accounts.google.com", "storage.azure.com",
    "www.stackoverflow.com", "registry.npmjs.org", "pypi.org",
    "outlook.live.com", "teams.microsoft.com", "www.youtube.com",
    "smtp.gmail.com", "imap.gmail.com", "update.googleapis.com",
    "www.wikipedia.org", "static.cloudflareinsights.com"
]

C2_DOMAINS = [
    "evil-c2.net", "data-exfil.xyz", "tunnel.bad.io",
    "c2server.ru", "exfil.hidden.io", "secret-transfer.net"
]

def make_normal_query():
    return random.choice(NORMAL_DOMAINS)

def make_tunnel_query():
    payload = base64.b64encode(os.urandom(12)).decode()
    payload = payload.replace("=","").replace("+","x").replace("/","z")
    return f"{payload}.{random.choice(C2_DOMAINS)}"

LOG_FILE = "shared/dns_log.txt"

open(LOG_FILE, "w").close()

print("Attacker simulator started. Press Ctrl+C to stop.")
print(f"Writing queries to {LOG_FILE}")
print("-" * 50)

query_count = 0
tunnel_count = 0

try:
    while True:
        is_tunnel = random.random() < 0.25
        domain = make_tunnel_query() if is_tunnel else make_normal_query()
        timestamp = datetime.now().strftime("%H:%M:%S")
        line = f"{timestamp},{domain}\n"

        with open(LOG_FILE, "a") as f:
            f.write(line)

        query_count += 1

        if is_tunnel:
            tunnel_count += 1
            print(f"[{timestamp}] SENDING  {domain}  <-- tunnel")
        else:
            print(f"[{timestamp}] sending  {domain}")

        time.sleep(0.5)

except KeyboardInterrupt:
    print(f"\nStopped. Sent {query_count} queries ({tunnel_count} tunnels).")