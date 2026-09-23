from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
import joblib
from features import extract_all_features

print("Extracting rich feature representations across balanced dataset...")

dataset = [
    # Legitimate (0)
    ("https://www.google.com", 0),
    ("https://www.github.com", 0),
    ("https://www.microsoft.com", 0),
    ("https://www.amazon.in", 0),
    ("https://www.wikipedia.org", 0),
    ("https://www.linkedin.com", 0),
    ("https://www.cumminscollege.in", 0),
    ("https://www.iitb.ac.in", 0),
    ("https://stackoverflow.com", 0),
    ("https://openai.com", 0),
    ("https://www.dailymotion.com", 0),
    ("https://vimeo.com", 0),
    ("https://netflix.com", 0),
    ("https://apple.com", 0),
    ("https://developer.mozilla.org", 0),

    # Malicious / Fraudulent / Phishing (1)
    ("https://net77.cc/verify2", 1),
    ("http://192.168.1.1/login-bank", 1),
    ("http://secure-login-nasscom-fake.com", 1),
    ("https://forms.gle/qe33wdHi9fayvZAy6", 1),
    ("http://verify-bank-kyc-alert.xyz", 1),
    ("http://unloxacademy-summer-internship.top", 1),
    ("http://free-gift-bonus-offer.ru", 1),
    ("http://signin-google-drive-phish.net", 1),
    ("http://bit.ly/claim-scholarship-now", 1),
    ("https://account-security-check.net/auth", 1),
    ("http://paytm-kyc-update-portal.info", 1),
    ("http://sbi-netbanking-verification.club", 1),
    ("https://metamask-io-wallet-restore.cc", 1),
    ("https://paypal-verify-account-center.xyz/signin", 1),
    ("https://binance-claim-airdrop.cc/verify", 1)
] * 50

X = [extract_all_features(url, check_whois=False)[0] for url, label in dataset]
y = [label for url, label in dataset]

X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

model = RandomForestClassifier(n_estimators=150, max_depth=10, random_state=42)
model.fit(X_train, y_train)

joblib.dump(model, "phishing_model.pkl")
print("✅ Done! Retrained 'phishing_model.pkl' created with enhanced detection logic.")