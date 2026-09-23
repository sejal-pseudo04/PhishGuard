import streamlit as st
import pandas as pd
import joblib
import os
from features import extract_all_features
import json

# ==================== PAGE CONFIG ====================
st.set_page_config(
    page_title="PhishGuard AI",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ==================== LOAD MODEL ====================
@st.cache_resource
def load_model():
    """Load the trained model with error handling."""
    model_path = "phishing_model.pkl"
    
    if not os.path.exists(model_path):
        st.error(f"❌ Model not found! Run `python train_model.py` first to generate '{model_path}'")
        st.stop()
    
    try:
        model = joblib.load(model_path)
        return model
    except Exception as e:
        st.error(f"❌ Error loading model: {e}")
        st.stop()

# ==================== UTILITY FUNCTIONS ====================
def predict_phishing(url: str, model):
    """Predict if URL is phishing with error handling."""
    try:
        url = url.strip()
        
        if not url:
            return None, "Please enter a URL"
        
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        
        # Extract features
        features_dict = extract_all_features(url, check_whois=True)
        feature_vector = [
            features_dict['url_length'],
            features_dict['domain_length'],
            features_dict['subdomain_count'],
            features_dict['has_hyphen_domain'],
            features_dict['dot_count'],
            features_dict['is_https'],
            features_dict['is_http'],
            features_dict['has_ip'],
            features_dict['has_port'],
            features_dict['is_shortened'],
            features_dict['has_query'],
            features_dict['entropy'],
            features_dict['has_at_symbol'],
            features_dict['is_whitelisted'],
        ]
        
        # Get prediction
        prediction = model.predict([feature_vector])[0]
        risk_score = model.predict_proba([feature_vector])[0][1] * 100
        
        return (prediction, risk_score, features_dict), None
    
    except Exception as e:
        return None, f"Error analyzing URL: {str(e)}"

# ==================== UI LAYOUT ====================
st.title("🛡️ PhishGuard AI: Real-Time Phishing URL Detector")
st.caption("SPECTRA 2026 | Problem Statement 3: AI-Powered Malicious URL Classification System")

# Load model
model = load_model()

# ==================== MAIN INTERFACE ====================
col1, col2 = st.columns([3, 1])

with col1:
    url_input = st.text_input(
        "Enter Target URL to Scan:",
        placeholder="e.g., https://forms.gle/q3aHdi09fayv2AvG",
        help="Paste the full URL you want to check"
    )

with col2:
    scan_clicked = st.button("🔍 Scan URL", type="primary", use_container_width=True)

# ==================== SCANNING & RESULTS ====================
if scan_clicked:
    if not url_input:
        st.warning("⚠️ Please enter a URL")
    else:
        with st.spinner("Extracting multi-factor security telemetry & running ML inference..."):
            result, error = predict_phishing(url_input, model)
        
        if error:
            st.error(f"❌ {error}")
        else:
            prediction, risk_score, features = result
            
            # Display results in columns
            res_col1, res_col2 = st.columns([2, 1])
            
            with res_col1:
                if features['is_whitelisted']:
                    verdict = "✅ VERIFIED LEGITIMATE"
                    st.success(f"**Verdict:** {verdict}")
                    st.info("✓ This domain is on our verified authority whitelist")
                elif prediction == 1:
                    verdict = "🚨 PHISHING / MALICIOUS"
                    st.error(f"**Verdict:** {verdict}")
                else:
                    verdict = "✓ LEGITIMATE"
                    st.success(f"**Verdict:** {verdict}")
            
            with res_col2:
                st.metric(
                    "Risk Score",
                    f"{risk_score:.1f}%",
                    delta="High Risk" if risk_score >= 50 else "Safe"
                )
            
            # Security Telemetry
            st.divider()
            st.subheader("🔍 Extracted Security Telemetry")
            
            telem_col1, telem_col2 = st.columns(2)
            
            with telem_col1:
                st.metric("URL Length", f"{features['url_length']} chars")
                st.metric("Domain Length", f"{features['domain_length']} chars")
                st.metric("Subdomain Count", features['subdomain_count'])
                st.metric("Has Hyphen in Domain", "Yes" if features['has_hyphen_domain'] else "No")
                st.metric("Dot Count", features['dot_count'])
            
            with telem_col2:
                st.metric("Protocol", "HTTPS (Secure)" if features['is_https'] else ("HTTP (Insecure)" if features['is_http'] else "Unknown"))
                st.metric("Contains IP Address", "Yes ⚠️" if features['has_ip'] else "No")
                st.metric("Custom Port", "Yes ⚠️" if features['has_port'] else "No")
                st.metric("URL Shortener", "Yes ⚠️" if features['is_shortened'] else "No")
                st.metric("Query Parameters", "Yes" if features['has_query'] else "No")
            
            # Advanced telemetry
            with st.expander("📊 Advanced Telemetry"):
                st.metric("Shannon Entropy", f"{features['entropy']:.3f}")
                st.metric("@ Symbol Present", "Yes ⚠️" if features['has_at_symbol'] else "No")
                
                # Display raw features as JSON
                st.json({k: v for k, v in features.items()})

# ==================== SIDEBAR INFO ====================
with st.sidebar:
    st.header("ℹ️ About PhishGuard AI")
    
    st.markdown("""
    **PhishGuard AI** detects malicious URLs using:
    - 🔤 **Lexical Analysis**: URL structure & entropy
    - 🌐 **Network Signals**: IP detection, shortener URLs
    - 🤖 **ML Model**: RandomForest classifier
    - ✅ **Whitelist Check**: Verified authority domains
    
    ### How it works:
    1. URL is parsed into 14 structural features
    2. Features fed to trained RandomForest model
    3. Risk probability calculated (0-100%)
    4. Verdict returned with telemetry
    """)
    
    st.divider()
    
    st.subheader("🧪 Test Cases")
    if st.button("Test: Legitimate Google"):
        st.session_state.test_url = "https://www.google.com"
    
    if st.button("Test: Phishing BitLy"):
        st.session_state.test_url = "http://bit.ly/claim-scholarship-now"
    
    if st.button("Test: IP Login"):
        st.session_state.test_url = "http://192.168.1.1/login-bank"
    
    if 'test_url' in st.session_state:
        st.text_input("Quick Test:", value=st.session_state.test_url)

st.divider()
st.caption("🔐 PhishGuard AI v1.0 | Developed for SPECTRA 2026 Hackathon")