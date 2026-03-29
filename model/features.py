import math
import re

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
    parts  = domain.split(".")
    # subdomain = everything except last 2 parts (e.g. 'google.com')
    subdomain = ".".join(parts[:-2]) if len(parts) > 2 else parts[0]

    vowels     = set("aeiou")
    consonants = set("bcdfghjklmnpqrstvwxyz")

    def max_consecutive(text, char_set):
        max_len = cur = 0
        for c in text:
            if c in char_set:
                cur += 1
                max_len = max(max_len, cur)
            else:
                cur = 0
        return max_len

    def max_consecutive_same(text):
        max_len = cur = 0
        prev = ""
        for c in text:
            if c == prev:
                cur += 1
                max_len = max(max_len, cur)
            else:
                cur = 1
            prev = c
        return max_len

    total_len     = len(domain)
    sub_len       = len(subdomain)
    num_pct       = round(sum(c.isdigit() for c in domain) / max(total_len, 1), 4)
    entropy       = calculate_entropy(domain)
    max_num       = max_consecutive(domain, set("0123456789"))
    max_alpha     = max_consecutive(domain, set("abcdefghijklmnopqrstuvwxyz"))
    max_cons      = max_consecutive(domain, consonants)
    max_same      = max_consecutive_same(domain)

    v_count = sum(c in vowels for c in domain)
    c_count = sum(c in consonants for c in domain)
    vowel_consonant_ratio = round(v_count / max(c_count, 1), 4)
    conv_freq = round((v_count + c_count) / max(total_len, 1), 4)

    # TTL features — not available from domain string alone, use defaults
    ttl_min  = 30
    ttl_max  = 300
    ttl_mean = 150
    ttl_var  = 1000.0
    ttl_std  = 31.6
    ttl_skew = 0.0
    distinct_ttl = 1

    # DNS record features — defaults for live inference
    distinct_a   = 1
    avg_answer   = 1.0
    avg_authority = 0.0

    return [
        total_len,
        sub_len,
        num_pct,
        entropy,
        max_num,
        max_alpha,
        max_cons,
        max_same,
        vowel_consonant_ratio,
        conv_freq,
        distinct_ttl,
        ttl_min,
        ttl_max,
        ttl_mean,
        ttl_var,
        ttl_std,
        ttl_skew,
        distinct_a,
        avg_answer,
        avg_authority,
    ]

FEATURE_NAMES = [
    "dns_domain_name_length",
    "dns_subdomain_name_length",
    "numerical_percentage",
    "character_entropy",
    "max_continuous_numeric_len",
    "max_continuous_alphabet_len",
    "max_continuous_consonants_len",
    "max_continuous_same_alphabet_len",
    "vowels_consonant_ratio",
    "conv_freq_vowels_consonants",
    "distinct_ttl_values",
    "ttl_values_min",
    "ttl_values_max",
    "ttl_values_mean",
    "ttl_values_variance",
    "ttl_values_standard_deviation",
    "ttl_values_skewness",
    "distinct_A_records",
    "average_answer_resource_records",
    "average_authority_resource_records",
]