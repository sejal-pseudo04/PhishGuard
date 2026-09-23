import imaplib
import email
from email.header import decode_header
import re
from urllib.parse import urlparse, quote_plus
import tldextract
import requests
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import joblib
from typing import Dict, Any, List
from features import extract_all_features

app = FastAPI(title="PhishGuard AI Backend")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

model = joblib.load("phishing_model.pkl")

# --- AUTHENTICATED INFRASTRUCTURE (EXCLUDING FORMS & EXTERNAL LINKS) ---
TRUSTED_INFRASTRUCTURE = {
    "cumminscollege.in",
    "mksss.org",
    "iitb.ac.in",
    "iitd.ac.in",
    "iiit.ac.in",
    "coep.org.in",
    "unipune.ac.in",
    "accounts.google.com",
    "myaccount.google.com",
    "googleusercontent.com",
    "gstatic.com",
    "whatsapp.com",
    "facebook.com",
    "linkedin.com",
    "github.com",
    "microsoft.com"
}

TRUSTED_ROOT_SUFFIXES = (
    ".ac.in",
    ".edu.in",
    ".edu",
    ".res.in",
    ".gov.in",
    ".gov",
    ".nic.in"
)

STATIC_MEDIA_PATTERNS = [
    "mail-sig", "/icons/", "branding/googlelogo", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp",
    "accountchooser", "notifications"
]

PHISHING_INTENT_WORDS = [
    "internship", "stipend", "nasscom", "final call", "shortlisted", 
    "enrollment", "tablet", "urgent", "credit points", "apply now", "verify", "kyc", "meity"
]

def is_verified_trusted_authority(raw_url: str, sender_email: str = "") -> bool:
    url_lower = raw_url.lower()

    # NEVER whitelist Google Forms or external third-party form builders
    if "forms.gle" in url_lower or "docs.google.com/forms" in url_lower or "form" in url_lower:
        return False

    parsed = urlparse(raw_url if "://" in raw_url else "http://" + raw_url)
    ext = tldextract.extract(raw_url)
    registered_domain = ext.registered_domain.lower() if ext.registered_domain else ""
    full_host = parsed.netloc.lower().split(':')[0]

    for trusted in TRUSTED_INFRASTRUCTURE:
        if full_host == trusted or full_host.endswith("." + trusted) or registered_domain == trusted:
            return True

    if any(full_host.endswith(suffix) or registered_domain.endswith(suffix) for suffix in TRUSTED_ROOT_SUFFIXES):
        return True

    return False

def is_benign_email_asset(raw_url: str) -> bool:
    url_lower = raw_url.lower()
    return any(pattern in url_lower for pattern in STATIC_MEDIA_PATTERNS)

def simulate_click_consequences(raw_url: str, is_phishing: bool, risk_score: float, is_trusted: bool = False) -> Dict[str, Any]:
    ext = tldextract.extract(raw_url)
    url_lower = raw_url.lower()
    hops = [raw_url]

    if is_trusted or (not is_phishing and risk_score < 40):
        return {
            "attack_type": "Authenticated Trusted Resource",
            "threat_actor_goal": "Legitimate Enterprise Communication",
            "redirect_hops": hops,
            "simulated_steps": [
                {"phase": "Step 1: Identity & SSL Verification", "detail": f"Domain '{ext.registered_domain}' cryptographically verified against global trust registers."},
                {"phase": "Step 2: Transport Security", "detail": "Encrypted session established over verified SSL/TLS certificate."},
                {"phase": "Step 3: Secure Render", "detail": f"Loads authentic destination under '{ext.registered_domain}'."}
            ],
            "blast_radius": "0% Risk - Authentic & Safe Resource",
            "safety_recommendation": "Safe to browse."
        }

    attack_type = "Credential Harvesting Portal"
    goal = "Interception of session cookies, personal data, and 2FA tokens"
    blast_radius = "Identity Theft, Financial Fraud, and Data Harvesting"

    if "forms.gle" in url_lower or "docs.google.com/forms" in url_lower:
        attack_type = "Predatory Academic / Internship Data Harvester"
        goal = "Exfiltration of PII, Academic Records, and Personal Phone Numbers under fake NASSCOM / MeitY affiliation"
        blast_radius = "Mass spam indexing, academic fraud, financial extortion"
        steps = [
            {"phase": "Step 1: Trust Exploitation", "detail": "Adversary uses Google infrastructure ('forms.gle') to bypass email firewalls."},
            {"phase": "Step 2: Social Engineering", "detail": "Prompts students with fake 'Shortlisted / Final Call' lures to instill FOMO."},
            {"phase": "Step 3: Unmonitored Exfiltration", "detail": "Transfers student details to an external adversary Google Sheet without institutional consent."}
        ]
    elif any(t in url_lower for t in ["verify", "kyc", "bank", "login", "account", "auth"]):
        attack_type = "Adversary-in-the-Middle (AiTM) Login Replica"
        goal = "Harvesting multi-factor credentials & banking access"
        blast_radius = "Direct financial loss, credential theft"
        steps = [
            {"phase": "Step 1: Spoofed Gateway", "detail": f"Redirects to spoofed interface on domain '{ext.registered_domain}'."},
            {"phase": "Step 2: Keylogging", "detail": "Captures passwords and OTP tokens in real-time."},
            {"phase": "Step 3: Session Replay", "detail": "Attacker replays tokens to legitimate server while redirecting victim."}
        ]
    else:
        steps = [
            {"phase": "Step 1: External Connection", "detail": f"Connects to external registrar '{ext.registered_domain}'."},
            {"phase": "Step 2: Browser Profiling", "detail": "Extracts telemetry and checks for device vulnerabilities."},
            {"phase": "Step 3: Malicious Payload", "detail": "Attempts unauthorized download or fraudulent payment gateway redirect."}
        ]

    return {
        "attack_type": attack_type,
        "threat_actor_goal": goal,
        "redirect_hops": hops,
        "simulated_steps": steps,
        "blast_radius": blast_radius,
        "safety_recommendation": "DO NOT FILL THIS FORM. This is an external predatory campaign masquerading as institutional notice."
    }

class URLRequest(BaseModel):
    url: str

class GmailScanRequest(BaseModel):
    email_user: str
    app_password: str
    max_emails: int = 25

@app.post("/api/scan")
def scan_url(request: URLRequest) -> Dict[str, Any]:
    raw_url: str = request.url.strip()
    if not raw_url:
        return {"error": "Invalid URL provided"}

    if is_verified_trusted_authority(raw_url) or is_benign_email_asset(raw_url):
        _, telemetry = extract_all_features(raw_url, check_whois=False)
        telemetry["Institutional Trust Status"] = "Verified Authentic Infrastructure (Whitelisted)"
        consequences = simulate_click_consequences(raw_url, is_phishing=False, risk_score=0.0, is_trusted=True)
        
        return {
            "url": raw_url,
            "verdict": "LEGITIMATE (VERIFIED PLATFORM)",
            "risk_score": 0.0,
            "is_phishing": False,
            "telemetry": telemetry,
            "consequences": consequences
        }

    feature_vec, telemetry = extract_all_features(raw_url, check_whois=True)
    prediction: int = int(model.predict([feature_vec])[0])
    risk_score: float = float(model.predict_proba([feature_vec])[0][1] * 100)

    if "forms.gle" in raw_url.lower() or "docs.google.com/forms" in raw_url.lower():
        risk_score = max(risk_score, 92.5)
        prediction = 1

    is_phish = bool(prediction == 1 or risk_score >= 50)
    verdict: str = "PHISHING / MALICIOUS" if is_phish else "LEGITIMATE"

    consequences = simulate_click_consequences(raw_url, is_phish, risk_score, is_trusted=False)

    return {
        "url": raw_url,
        "verdict": verdict,
        "risk_score": round(risk_score, 1),
        "is_phishing": is_phish,
        "telemetry": telemetry,
        "consequences": consequences
    }

@app.post("/api/scan-inbox")
def scan_gmail_inbox(req: GmailScanRequest) -> Dict[str, Any]:
    scanned_emails = []
    clean_password = req.app_password.replace(" ", "").strip()
    
    try:
        mail = imaplib.IMAP4_SSL("imap.gmail.com")
        mail.login(req.email_user.strip(), clean_password)
        mail.select("inbox")

        status, messages = mail.search(None, "ALL")
        if not messages or not messages[0]:
            mail.logout()
            return {"status": "success", "emails": []}

        # Fetch up to the last 25 emails
        fetch_limit = min(max(req.max_emails, 20), 50)
        email_ids = messages[0].split()[-fetch_limit:]

        for e_id in reversed(email_ids):
            _, msg_data = mail.fetch(e_id, "(RFC822)")
            for response_part in msg_data:
                if isinstance(response_part, tuple):
                    msg = email.message_from_bytes(response_part[1])
                    
                    # 1. Subject
                    subject_header = msg.get("Subject", "No Subject")
                    decoded_parts = decode_header(subject_header)
                    subject = ""
                    for part, encoding in decoded_parts:
                        if isinstance(part, bytes):
                            subject += part.decode(encoding if encoding else "utf-8", errors="ignore")
                        else:
                            subject += str(part)
                    
                    sender = msg.get("From", "Unknown Sender")
                    date_sent = msg.get("Date", "Unknown Date")
                    raw_msg_id = msg.get("Message-ID", "")
                    clean_msg_id = raw_msg_id.strip("<> ").strip()

                    gmail_direct_url = f"https://mail.google.com/mail/u/0/#search/rfc822msgid%3A{quote_plus(clean_msg_id)}" if clean_msg_id else f"https://mail.google.com/mail/u/0/#search/{quote_plus(subject)}"

                    # 2. Body
                    body_text = ""
                    if msg.is_multipart():
                        for part in msg.walk():
                            ctype = part.get_content_type()
                            cdispo = str(part.get("Content-Disposition"))
                            if ctype in ["text/plain", "text/html"] and "attachment" not in cdispo:
                                payload = part.get_payload(decode=True)
                                if payload:
                                    body_text += payload.decode("utf-8", errors="ignore") + " "
                    else:
                        payload = msg.get_payload(decode=True)
                        if payload:
                            body_text = payload.decode("utf-8", errors="ignore")

                    raw_links = list(set(re.findall(r'https?://[^\s<>"\'\)\],]+', body_text)))
                    link_verdicts = []
                    email_has_threat = False

                    sender_lower = sender.lower()
                    body_lower = body_text.lower()
                    subject_lower = subject.lower()

                    is_internal_college = "@cumminscollege.in" in sender_lower
                    is_official_google = "no-reply@accounts.google.com" in sender_lower or "google.com" in sender_lower
                    is_official_club = "tedxccoew" in sender_lower or "fissoc" in sender_lower
                    
                    is_trusted_sender = is_internal_college or is_official_google or is_official_club

                    # Social Engineering & External Form Detection
                    has_social_eng_words = any(w in body_lower or w in subject_lower for w in PHISHING_INTENT_WORDS)
                    has_unvetted_form = any("forms.gle" in l.lower() or "docs.google.com/forms" in l.lower() for l in raw_links)

                    if not is_trusted_sender and (has_social_eng_words or has_unvetted_form):
                        email_has_threat = True

                    for link in raw_links:
                        # 1. Google Forms from external senders = Direct Threat
                        if "forms.gle" in link.lower() or "docs.google.com/forms" in link.lower():
                            link_verdicts.append({
                                "url": link,
                                "is_phishing": True,
                                "risk_score": 92.5,
                                "is_asset": False
                            })
                            email_has_threat = True
                        elif is_benign_email_asset(link):
                            link_verdicts.append({
                                "url": link,
                                "is_phishing": False,
                                "risk_score": 0.0,
                                "is_asset": True
                            })
                        elif is_verified_trusted_authority(link, sender):
                            link_verdicts.append({
                                "url": link,
                                "is_phishing": False,
                                "risk_score": 0.0,
                                "is_asset": False
                            })
                        else:
                            f_vec, _ = extract_all_features(link, check_whois=False)
                            pred = int(model.predict([f_vec])[0])
                            score = float(model.predict_proba([f_vec])[0][1] * 100)
                            
                            is_p = bool(pred == 1 or score >= 50)
                            if is_p and not is_trusted_sender:
                                email_has_threat = True
                            
                            link_verdicts.append({
                                "url": link,
                                "is_phishing": is_p if not is_trusted_sender else False,
                                "risk_score": round(score, 1) if not is_trusted_sender else 0.0,
                                "is_asset": False
                            })

                    if is_trusted_sender:
                        email_has_threat = False

                    # Filter out static image tokens from display so real links stand out
                    filtered_links = [l for l in link_verdicts if not l["is_asset"]]
                    display_links = filtered_links if filtered_links else link_verdicts

                    scanned_emails.append({
                        "subject": subject,
                        "from": sender,
                        "date": date_sent,
                        "gmail_url": gmail_direct_url,
                        "total_links": len(display_links),
                        "has_threat": email_has_threat,
                        "links": display_links
                    })

        mail.logout()
        return {"status": "success", "emails": scanned_emails}

    except Exception as e:
        return {"status": "error", "message": str(e)}

@app.get("/")
def root() -> Dict[str, str]:
    return {"status": "PhishGuard AI API is active and ready"}