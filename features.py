import re
import math
from urllib.parse import urlparse
import tldextract
import whois
from datetime import datetime
from typing import Tuple, List, Dict, Any

SUSPICIOUS_TLDS = {
    "cc", "xyz", "top", "club", "info", "ru", "tk", "ml", "ga", "cf", "gq", 
    "work", "buzz", "rest", "click", "link", "guru", "fit", "live", "vip"
}

SUSPICIOUS_KEYWORDS = [
    "verify", "login", "secure", "bank", "account", "update", "nasscom", 
    "internship", "stipend", "free", "kyc", "portal", "support", "billing", 
    "signin", "auth", "wallet", "crypto", "bonus", "claim"
]

def calculate_entropy(text: str) -> float:
    if not text:
        return 0.0
    prob = [float(text.count(c)) / len(text) for c in dict.fromkeys(list(text))]
    return -sum([p * math.log(p) / math.log(2.0) for p in prob])

def extract_all_features(url: str, check_whois: bool = True) -> Tuple[List[Any], Dict[str, str]]:
    if not url.startswith("http://") and not url.startswith("https://"):
        url = "http://" + url

    parsed = urlparse(url)
    ext = tldextract.extract(url)
    domain_name = ext.domain
    suffix = ext.suffix.lower()
    registered_domain = ext.registered_domain if ext.registered_domain else parsed.netloc

    # 1. Lexical & Domain Structure
    url_length = len(url)
    domain_length = len(registered_domain)
    has_at_symbol = 1 if "@" in url else 0
    has_hyphen_domain = 1 if "-" in domain_name else 0
    dot_count = url.count(".")
    subdomain_count = len(ext.subdomain.split('.')) if ext.subdomain else 0
    is_https = 1 if parsed.scheme == "https" else 0
    has_ip = 1 if re.search(r"^\d{1,3}(\.\d{1,3}){3}", parsed.netloc) else 0
    
    # 2. Advanced Threat Signals
    has_suspicious_tld = 1 if suffix in SUSPICIOUS_TLDS else 0
    digits_in_domain = sum(1 for c in domain_name if c.isdigit())
    digit_ratio = (digits_in_domain / len(domain_name)) if len(domain_name) > 0 else 0.0
    is_shortener = 1 if any(s in url.lower() for s in ["bit.ly", "tinyurl", "forms.gle", "t.co", "cutt.ly", "surl.li"]) else 0
    entropy = calculate_entropy(url)
    
    # 3. Phishing Keywords in Path & Subdomain
    full_url_lower = url.lower()
    keyword_count = sum(1 for term in SUSPICIOUS_KEYWORDS if term in full_url_lower)
    
    # Feature vector for ML Model
    feature_vector = [
        url_length, domain_length, has_at_symbol, has_hyphen_domain, 
        dot_count, subdomain_count, is_https, has_ip, is_shortener, 
        entropy, keyword_count, has_suspicious_tld, digit_ratio
    ]

    # 4. WHOIS Domain Age
    domain_age_days = -1
    if check_whois:
        try:
            w = whois.whois(registered_domain)
            creation = w.creation_date
            if isinstance(creation, list): 
                creation = creation[0]
            if creation:
                domain_age_days = (datetime.now() - creation).days
        except Exception:
            domain_age_days = -1

    detailed_report = {
        "URL Length": str(url_length),
        "Entropy (Randomness Score)": str(round(entropy, 2)),
        "High-Risk TLD (e.g. .cc, .xyz)": "Yes" if has_suspicious_tld else "No",
        "Domain Digit Ratio": f"{round(digit_ratio * 100, 1)}%",
        "Domain Age": f"{domain_age_days} days" if domain_age_days >= 0 else "Hidden / New Domain",
        "Uses URL Shortener": "Yes" if is_shortener else "No",
        "Has '@' Symbol": "Yes" if has_at_symbol else "No",
        "Subdomain Levels": str(subdomain_count),
        "HTTPS Enabled": "Yes" if is_https else "No",
        "Phishing Keyword Hits": str(keyword_count)
    }

    return feature_vector, detailed_report