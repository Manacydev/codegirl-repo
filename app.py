from flask import Flask, render_template, request, jsonify
import joblib
import numpy as np
import pandas as pd
import re
import socket
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup
import requests
import whois
from datetime import datetime
import time
import urllib3
import os
import traceback
from multiprocessing import Process, Queue # For robust timeouts


app = Flask(__name__)

# --- Suppress InsecureRequestWarning ---
# This is often necessary as many sites, including some phishing sites,
# have improper SSL configurations.
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# ----------------------------------------------------------------------------
# | MODEL LOADING
# ----------------------------------------------------------------------------
try:
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))

    # Build correct paths for model files
    MODEL_PATH = os.path.join(BASE_DIR, "model", "Phishing_URL_detection.pkl")
    FEATURES_PATH = os.path.join(BASE_DIR, "model", "feature_names.pkl")

    # Load them safely
    model = joblib.load(MODEL_PATH)
    feature_names = joblib.load(FEATURES_PATH)
    print(f"Model loaded successfully from: {MODEL_PATH}")
    # This feature order is CRITICAL and must match the order used during training.
    feature_names_order = [
        'UsingIP', 'LongURL', 'ShortURL', 'Symbol@', 'Redirecting//',
        'PrefixSuffix-', 'SubDomains', 'HTTPS', 'DomainRegLen', 'Favicon',
        'NonStdPort', 'HTTPSDomainURL', 'RequestURL', 'AnchorURL',
        'LinksInScriptTags', 'ServerFormHandler', 'InfoEmail', 'AbnormalURL',
        'WebsiteForwarding', 'StatusBarCust', 'DisableRightClick',
        'UsingPopupWindow', 'IframeRedirection', 'AgeofDomain',
        'DNSRecording', 'WebsiteTraffic', 'PageRank', 'GoogleIndex',
        'LinksPointingToPage', 'StatsReport'
    ]
    print(f"Model loaded successfully from: {MODEL_PATH}")
except Exception as e:
    print(f"--- FATAL: An error occurred during model loading: {e} ---")
    traceback.print_exc()

# ----------------------------------------------------------------------------
# | FEATURE EXTRACTION & HELPERS (FULL IMPLEMENTATION)
# ----------------------------------------------------------------------------
def whois_worker(domain, queue):
    """Safely runs whois in a separate process."""
    try:
        w = whois.whois(domain)
        queue.put(w)
    except Exception:
        queue.put(None)

def get_whois_with_timeout(domain, timeout=10):
    """Gets whois data with a timeout to prevent hanging."""
    q = Queue()
    p = Process(target=whois_worker, args=(domain, q))
    p.start()
    p.join(timeout)
    if p.is_alive():
        p.terminate(); p.join()
        return None
    return q.get()

def extract_features(url: str):
    """
    Extracts all 30 features required by the model, including content-based features.
    """
    features = {name: 1 for name in feature_names_order}
    
    if not re.match(r"^(https?)://", url):
        url = "http://" + url
    parsed_url = urlparse(url)
    domain = parsed_url.netloc

    # --- URL-Based Features (No Content Fetch Needed) ---
    try:
        socket.inet_aton(domain)
        features['UsingIP'] = -1
    except (socket.error, ValueError): pass # It's not an IP
    if len(url) > 75: features['LongURL'] = -1
    elif 54 <= len(url) <= 75: features['LongURL'] = 0
    if re.search(r"bit\.ly|goo\.gl|t\.co", url): features['ShortURL'] = -1
    if '@' in url: features['Symbol@'] = -1
    if url.rfind('//') > 6: features['Redirecting//'] = -1
    if '-' in domain: features['PrefixSuffix-'] = -1
    if domain.count('.') > 3: features['SubDomains'] = -1
    elif domain.count('.') == 3: features['SubDomains'] = 0
    if not parsed_url.scheme == 'https': features['HTTPS'] = -1
    if parsed_url.port and parsed_url.port not in [80, 443]: features['NonStdPort'] = -1
    if 'https' in domain: features['HTTPSDomainURL'] = -1

    # --- WHOIS-Based Features ---
    w = get_whois_with_timeout(domain)
    if w and w.creation_date:
        creation_date = w.creation_date[0] if isinstance(w.creation_date, list) else w.creation_date
        expiration_date = w.expiration_date[0] if isinstance(w.expiration_date, list) else w.expiration_date
        if expiration_date:
            reg_len = (expiration_date - creation_date).days
            if reg_len <= 365: features['DomainRegLen'] = -1
        else: features['DomainRegLen'] = -1
        age = (datetime.now() - creation_date).days
        if age < 180: features['AgeofDomain'] = -1
        features['DNSRecording'] = 1
    else:
        features['DomainRegLen'] = -1; features['AgeofDomain'] = -1; features['DNSRecording'] = -1
    if w and w.domain_name:
         domain_match = False
         if isinstance(w.domain_name, list):
             for d in w.domain_name:
                 if domain.lower() in d.lower(): domain_match = True; break
         elif isinstance(w.domain_name, str):
             if domain.lower() in w.domain_name.lower(): domain_match = True
         if not domain_match: features['AbnormalURL'] = -1
    else: features['AbnormalURL'] = -1

    # --- Content-Based Features (Requires fetching HTML) ---
    try:
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'}
        response = requests.get(url, headers=headers, verify=False, timeout=10)
        soup = BeautifulSoup(response.text, 'html.parser')
        
        # 10. Favicon
        favicon = soup.find("link", rel=re.compile(r'icon', re.I))
        if favicon and urlparse(urljoin(url, favicon['href'])).netloc != domain: features['Favicon'] = -1
        
        # 13. RequestURL & 14. AnchorURL & 15. LinksInScriptTags
        req_urls, anchor_urls, script_urls = [], [], []
        for tag in soup.find_all(['img', 'video', 'audio', 'script'], src=True): req_urls.append(tag['src'])
        for tag in soup.find_all('a', href=True): anchor_urls.append(tag['href'])
        for tag in soup.find_all('script', src=True): script_urls.append(tag['src'])
        
        total_req, external_req = len(req_urls), 0
        for r_url in req_urls:
            if urlparse(urljoin(url, r_url)).netloc != domain: external_req += 1
        if total_req > 0 and (external_req / total_req) > 0.61: features['RequestURL'] = -1
        
        total_anchor, external_anchor = len(anchor_urls), 0
        for a_url in anchor_urls:
            if urlparse(urljoin(url, a_url)).netloc != domain: external_anchor += 1
        if total_anchor > 0 and (external_anchor / total_anchor) > 0.67: features['AnchorURL'] = -1
            
        # 16. ServerFormHandler (SFH)
        for form in soup.find_all('form', action=True):
            action = form['action']
            if not action or action.strip() in ["", "#", "javascript:void(0)"]: features['ServerFormHandler'] = -1; break
            if urlparse(urljoin(url, action)).netloc != domain: features['ServerFormHandler'] = 0; break
        
        # 17. InfoEmail
        if re.search(r"mailto:", response.text): features['InfoEmail'] = -1
        
        # 19. WebsiteForwarding
        if len(response.history) > 1: features['WebsiteForwarding'] = -1
            
        # 20. StatusBarCust
        if re.search(r"onmouseover\s*=\s*['\"]window\.status", response.text, re.I): features['StatusBarCust'] = -1
            
        # 21. DisableRightClick
        if re.search(r"event\.button\s*==\s*2", response.text): features['DisableRightClick'] = -1
            
        # 22. UsingPopupWindow
        if re.search(r"window\.open\(", response.text): features['UsingPopupWindow'] = -1
            
        # 23. IframeRedirection
        if soup.find_all('iframe'): features['IframeRedirection'] = -1

    except requests.exceptions.RequestException:
        # If content fetch fails, penalize all content-based features
        content_features = ['Favicon', 'RequestURL', 'AnchorURL', 'LinksInScriptTags', 'ServerFormHandler', 'InfoEmail', 'WebsiteForwarding', 'StatusBarCust', 'DisableRightClick', 'UsingPopupWindow', 'IframeRedirection']
        for f in content_features: features[f] = -1

    # --- External Service Features (Simulated) ---
    # These are hard to get for free. We simulate a plausible result.
    # A real system would use APIs like SimilarWeb.
    if features['AgeofDomain'] == -1: features['WebsiteTraffic'] = -1 # New domains have no traffic
    
    # 27. PageRank, 28. GoogleIndex, 29. LinksPointingToPage, 30. StatsReport
    # These are largely deprecated or require paid APIs. We default them.
    # A very new domain is unlikely to be indexed or have links.
    if features['AgeofDomain'] == -1:
        features['GoogleIndex'] = -1
        features['LinksPointingToPage'] = -1
    
    feature_array = [features.get(name, 1) for name in feature_names_order]
    return np.array(feature_array).reshape(1, -1), features

# ----------------------------------------------------------------------------
# | FLASK ROUTES
# ----------------------------------------------------------------------------
@app.route("/")
def index():
    return render_template("index.html")

@app.route("/predict", methods=["POST"])
def predict():
    if not model: return jsonify({"error": "Model not loaded properly."}), 500
    url = request.get_json().get("url", "")
    if not url: return jsonify({"error": "No URL provided."}), 400

    try:
        features_array, features_dict = extract_features(url)
        features_df = pd.DataFrame(features_array, columns=feature_names_order)
        
        prediction_val = model.predict(features_df)[0]
        probabilities = model.predict_proba(features_df)[0]
        
        is_safe = bool(prediction_val == 1)
        phishing_class_index = np.where(model.classes_ == -1)[0][0]
        phishing_prob = probabilities[phishing_class_index]

        response_data = {"is_safe": is_safe, "probability_unsafe": phishing_prob}
        if not is_safe:
            response_data["reasons"] = [k for k, v in features_dict.items() if v == -1]
        return jsonify(response_data)
    except Exception:
        traceback.print_exc()
        return jsonify({"error": "Could not process the URL."}), 500

@app.route('/report', methods=['POST'])
def report():
    url = request.get_json().get("url", "")
    if not url: return jsonify({"status": "error", "message": "No URL provided"}), 400
    print(f"--- [USER REPORT] URL reported as unsafe: {url} ---")
    return jsonify({"status": "success", "message": "URL reported successfully"})

if __name__ == "__main__":
    app.run(debug=True)

