import csv
import random
import math
import base64
import os

random.seed(42)

NORMAL_DOMAINS = [
    "mail.google.com", "www.google.com", "api.github.com",
    "docs.python.org", "login.microsoft.com", "cdn.cloudflare.com",
    "fonts.googleapis.com", "accounts.google.com", "storage.azure.com",
    "www.stackoverflow.com", "registry.npmjs.org", "pypi.org",
    "outlook.live.com", "teams.microsoft.com", "www.youtube.com",
    "static.cloudflareinsights.com", "www.wikipedia.org",
    "smtp.gmail.com", "imap.gmail.com", "update.googleapis.com"
]

C2_DOMAINS = [
    "evil-c2.net", "data-exfil.xyz", "tunnel.bad.io",
    "c2server.ru", "exfil.hidden.io", "secret-transfer.net"
]

def make_tunnel_query():
    payload = base64.b64encode(os.urandom(12)).decode()
    payload = payload.replace("=", "").replace("+", "x").replace("/", "z")
    c2 = random.choice(C2_DOMAINS)
    return f"{payload}.{c2}"

rows = []

for _ in range(700):
    rows.append({"domain": random.choice(NORMAL_DOMAINS), "label": 0})

for _ in range(300):
    rows.append({"domain": make_tunnel_query(), "label": 1})

random.shuffle(rows)

with open("data/dns_dataset.csv", "w", newline="") as f:
    writer = csv.DictWriter(f, fieldnames=["domain", "label"])
    writer.writeheader()
    writer.writerows(rows)

print(f"Dataset created: {len(rows)} rows")
print(f"Normal queries : {sum(1 for r in rows if r['label'] == 0)}")
print(f"Tunnel queries : {sum(1 for r in rows if r['label'] == 1)}")