# PhishGuard 🛡️

PhishGuard is a Machine Learning-powered cybersecurity solution designed to detect and classify malicious/phishing URLs in real-time. The system extracts lexical, domain-based, and structural features from URLs to accurately identify potential security threats before users interact with them.

📌 Features
URL Feature Extraction: Analyzes incoming URLs across key security metrics (entropy, IP presence, HTTPS configuration, domain age/tokens).

ML Classification: Powered by a trained classification model (phishing_model.pkl) to predict risk scores and safety status.

REST API (api.py): Lightweight FastAPI endpoint serving prediction requests.

Interactive UI (app.py / index): Simple frontend interface for submitting URLs and viewing instant classification reports.

📁 Repository Structure
├── api.py               # REST API server for URL inference
├── app.py               # Main application entry point / web runner
├── features.py          # Feature extraction logic from raw URLs
├── index                # HTML UI template for interaction
├── phishing_model.pkl   # Pre-trained ML classification model
├── train_model.py       # Script to train and evaluate the model
└── README.md            # Project documentation
