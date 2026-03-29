"""
V3 — Evasion Attack Tester
Tests how well the model detects sneaky tunnel attacks
Save as: evasion_tester.py
Run from project root: python evasion_tester.py
"""

import os
import sys
import json
import random
import math
sys.path.insert(0, 'model')

import joblib
from features import extract_features

# ─────────────────────────────────────────────
# CONFIG
# ─────────────────────────────────────────────
MODEL_PATH  = "model/dns_rf_model.pkl"
OUTPUT_PATH = "model/evasion_results.json"

model = joblib.load(MODEL_PATH)

# ─────────────────────────────────────────────
# EVASION DOMAIN GENERATORS
# ─────────────────────────────────────────────

# Common dictionary words — low entropy, looks normal
WORDS = [
    "cat", "dog", "red", "blue", "green", "sun", "moon", "star",
    "login", "update", "sync", "data", "info", "api", "web", "app",
    "cloud", "mail", "news", "help", "home", "user", "admin", "test",
    "file", "store", "shop", "pay", "auth", "cdn", "img", "static"
]

LEGIT_TLDS = [
    "com", "net", "io", "co", "org", "info", "app", "dev"
]

TUNNEL_REGISTRARS = [
    "evil-c2.net", "secret-transfer.net", "tunnel.bad.io",
    "data-exfil.com", "c2server.net"
]

def random_word():
    return random.choice(WORDS)

def random_b64_chunk(length=16):
    import string
    chars = string.ascii_letters + string.digits + "+/"
    return ''.join(random.choices(chars, k=length))

def random_hex_chunk(length=12):
    return ''.join(random.choices('0123456789abcdef', k=length))

# ── Attack type generators ──

def obvious_tunnel():
    """Classic base64 tunnel — easy to detect"""
    sub = random_b64_chunk(random.randint(20, 32))
    return f"{sub}.{random.choice(TUNNEL_REGISTRARS)}"

def hex_tunnel():
    """Hex-encoded tunnel — still high entropy"""
    sub = random_hex_chunk(random.randint(16, 24))
    return f"{sub}.{random.choice(TUNNEL_REGISTRARS)}"

def short_word_tunnel():
    """Single dictionary word — very low entropy, hard to detect"""
    word = random_word()
    return f"{word}.{random.choice(TUNNEL_REGISTRARS)}"

def two_word_tunnel():
    """Two dictionary words — looks almost normal"""
    sub = f"{random_word()}-{random_word()}"
    return f"{sub}.{random.choice(TUNNEL_REGISTRARS)}"

def three_word_tunnel():
    """Three words mimicking real subdomain patterns"""
    sub = f"{random_word()}.{random_word()}.{random_word()}"
    return f"{sub}.{random.choice(TUNNEL_REGISTRARS)}"

def mimicry_tunnel():
    """Mimics real domain patterns (login.update.app.com style)"""
    parts = [random.choice(["login", "update", "sync", "api", "cdn", "static", "mail"])]
    parts.append(random.choice(["service", "server", "app", "web", "cloud", "data"]))
    sub = ".".join(parts)
    tld = random.choice(LEGIT_TLDS)
    # Uses a suspicious registrar but normal-looking subdomain
    base = random.choice(["analytics-hub", "sync-service", "update-cdn", "api-gateway"])
    return f"{sub}.{base}.{tld}"

def slow_drip_tunnel():
    """Very short subdomain — simulates slow exfiltration"""
    sub = random_b64_chunk(random.randint(4, 8))
    return f"{sub}.{random.choice(TUNNEL_REGISTRARS)}"

def numeric_tunnel():
    """Number-heavy subdomain — some tools encode as decimal"""
    sub = '.'.join([str(random.randint(100, 999)) for _ in range(3)])
    return f"{sub}.{random.choice(TUNNEL_REGISTRARS)}"

# ── Benign domains for baseline ──
BENIGN_DOMAINS = [
    "mail.google.com", "www.youtube.com", "login.microsoft.com",
    "cdn.cloudflare.com", "static.cloudflareinsights.com",
    "imap.gmail.com", "smtp.gmail.com", "api.github.com",
    "registry.npmjs.org", "storage.googleapis.com",
    "www.stackoverflow.com", "fonts.googleapis.com",
    "update.googleapis.com", "teams.microsoft.com",
    "outlook.live.com", "www.wikipedia.org"
]

# ─────────────────────────────────────────────
# ATTACK CATEGORIES
# ─────────────────────────────────────────────
ATTACK_TYPES = {
    "Obvious Base64 Tunnel":    (obvious_tunnel,      200, "Long random base64 subdomains — standard iodine/dnscat2 style"),
    "Hex Encoded Tunnel":       (hex_tunnel,          200, "Hex-encoded payloads — still high entropy but different charset"),
    "Short Word Tunnel":        (short_word_tunnel,   200, "Single dictionary word — minimal entropy, hardest to detect"),
    "Two Word Tunnel":          (two_word_tunnel,     200, "Two dictionary words joined — mimics real subdomains"),
    "Three Word Tunnel":        (three_word_tunnel,   200, "Three-level subdomain with real words — very stealthy"),
    "Mimicry Tunnel":           (mimicry_tunnel,      200, "Mimics real service domain patterns (login.update.app.com)"),
    "Slow Drip Tunnel":         (slow_drip_tunnel,    200, "Very short base64 chunks — slow exfiltration to avoid detection"),
    "Numeric Tunnel":           (numeric_tunnel,      200, "Decimal-encoded payloads — numeric subdomains"),
}

# ─────────────────────────────────────────────
# MAIN EVALUATION
# ─────────────────────────────────────────────
print("=" * 65)
print("  V3 — Evasion Attack Tester")
print("  Testing model against 8 attack styles")
print("=" * 65)

results = {}
all_examples = {}

# Test benign first
print("\n[Baseline] Testing benign domains...")
benign_correct = sum(
    1 for d in BENIGN_DOMAINS
    if int(model.predict([extract_features(d)])[0]) == 0
)
benign_acc = round(benign_correct / len(BENIGN_DOMAINS) * 100, 1)
print(f"  Benign accuracy: {benign_acc}% ({benign_correct}/{len(BENIGN_DOMAINS)} correctly identified)")

# Test each attack type
print("\n[Testing] Running evasion attacks...\n")
for attack_name, (generator, count, description) in ATTACK_TYPES.items():
    domains    = [generator() for _ in range(count)]
    detected   = 0
    examples   = []

    for domain in domains:
        try:
            features   = extract_features(domain)
            prediction = int(model.predict([features])[0])
            confidence = float(model.predict_proba([features])[0][1])
            if prediction == 1:
                detected += 1
            if len(examples) < 3:
                examples.append({
                    "domain":     domain,
                    "detected":   prediction == 1,
                    "confidence": round(confidence * 100, 1)
                })
        except Exception:
            continue

    detection_rate = round(detected / count * 100, 1)
    missed         = count - detected

    # Threat level
    if detection_rate >= 90:
        threat = "LOW"
    elif detection_rate >= 60:
        threat = "MEDIUM"
    elif detection_rate >= 30:
        threat = "HIGH"
    else:
        threat = "CRITICAL"

    results[attack_name] = {
        "description":    description,
        "total":          count,
        "detected":       detected,
        "missed":         missed,
        "detection_rate": detection_rate,
        "evasion_rate":   round(100 - detection_rate, 1),
        "threat_level":   threat,
        "examples":       examples
    }
    all_examples[attack_name] = examples

    threat_icon = {"LOW":"✅","MEDIUM":"⚠️","HIGH":"🔴","CRITICAL":"💀"}[threat]
    print(f"  {threat_icon} {attack_name}")
    print(f"     Detected: {detected}/{count} ({detection_rate}%) | Evaded: {missed} | Threat: {threat}")
    print(f"     {description}")
    print()

# ─────────────────────────────────────────────
# SUMMARY
# ─────────────────────────────────────────────
print("=" * 65)
print("  SUMMARY")
print("=" * 65)
avg_detection = sum(r["detection_rate"] for r in results.values()) / len(results)
hardest = min(results.items(), key=lambda x: x[1]["detection_rate"])
easiest = max(results.items(), key=lambda x: x[1]["detection_rate"])

print(f"\n  Average detection rate across all attack types: {avg_detection:.1f}%")
print(f"  Easiest to detect : {easiest[0]} ({easiest[1]['detection_rate']}%)")
print(f"  Hardest to detect : {hardest[0]} ({hardest[1]['detection_rate']}%)")
print(f"  Benign accuracy   : {benign_acc}%")

print("\n  Academic finding:")
print(f"  The model performs well against high-entropy attacks but shows")
print(f"  reduced detection on evasion-style attacks, particularly")
print(f"  '{hardest[0]}' with only {hardest[1]['detection_rate']}% detection rate.")
print(f"  This suggests future work should incorporate session-level")
print(f"  behavioural analysis beyond single-query feature extraction.")

# ─────────────────────────────────────────────
# SAVE RESULTS
# ─────────────────────────────────────────────
output = {
    "benign_accuracy":      benign_acc,
    "average_detection":    round(avg_detection, 1),
    "hardest_attack":       hardest[0],
    "easiest_attack":       easiest[0],
    "attacks":              results
}

with open(OUTPUT_PATH, "w") as f:
    json.dump(output, f, indent=2)

print(f"\n  Results saved to {OUTPUT_PATH}")
print("=" * 65)