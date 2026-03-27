import math

def calculate_entropy(text):
    if not text or len(text) == 0:
        return 0.0
    frequency = {}
    for char in text:
        frequency[char] = frequency.get(char, 0) + 1
    entropy = 0.0
    length = len(text)
    for count in frequency.values():
        probability = count / length
        entropy -= probability * math.log2(probability)
    return round(entropy, 4)

def extract_features(domain):
    domain = domain.strip().lower()
    parts = domain.split(".")
    subdomain = parts[0] if parts else ""
    total_length    = len(domain)
    entropy         = calculate_entropy(domain)
    subdomain_count = domain.count(".")
    digit_ratio     = round(sum(c.isdigit() for c in domain) / max(len(domain), 1), 4)
    subdomain_len   = len(subdomain)
    return [total_length, entropy, subdomain_count, digit_ratio, subdomain_len]

FEATURE_NAMES = [
    "total_length",
    "entropy",
    "subdomain_count",
    "digit_ratio",
    "subdomain_len"
]