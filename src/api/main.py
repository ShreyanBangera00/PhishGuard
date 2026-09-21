"""
FastAPI Backend Application for PhishGuard.
Provides real-time phishing inference, rule-based feature attribution explanations,
multi-modal DOM page inspection, email heuristics, and PhishTank live feed.
"""

import os
import sys
import json
import random
from typing import Optional, List, Dict, Any
import joblib
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel

# Add project root to path
ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
if ROOT_DIR not in sys.path:
    sys.path.append(ROOT_DIR)

from src.features.url_features import extract_url_features
from src.features.email_features import extract_email_features
from src.scraper.page_analyzer import analyze_page, check_ssrf_safe, SSRFSecurityError
from src.explainability.explainer import explain_prediction

app = FastAPI(
    title="PhishGuard Security Engine",
    description="Explainable AI Phishing Detection API with Multi-Modal Analysis & Live Feed",
    version="1.0.0"
)

# CORS configuration (stateless REST API: wildcard origin with credentials disabled)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Load production model
MODEL_PATH = os.path.join(ROOT_DIR, 'src', 'models', 'saved', 'production_model.pkl')
METRICS_PATH = os.path.join(ROOT_DIR, 'src', 'models', 'saved', 'metrics.json')

model = None
feature_names = []
model_metadata = {}

if os.path.exists(MODEL_PATH):
    try:
        saved_bundle = joblib.load(MODEL_PATH)
        model = saved_bundle['model']
        model_metadata = saved_bundle['metadata']
        feature_names = model_metadata['feature_names']
        print(f"[PhishGuard] Loaded {model_metadata.get('model_name', 'Model')} successfully.")
    except Exception as e:
        print(f"[PhishGuard] Error loading model: {e}")

# Static PhishTank feed cache with real-world observed attack samples
RECENT_PHISHTANK_SAMPLES = [
    "http://appleid.apple.com.manage-auth.tk/login.php",
    "http://192.168.1.105:8080/secure-banking/verify.html",
    "http://paypal-resolution-center.xyz/update-account?session=89324",
    "http://netflix-billing-recovery.ml/signin",
    "http://chase-security-verify.click/authorize.cgi",
    "http://bit.ly/sec-pay9012",
    "http://microsoft-alert-suspension.top/office365/login",
    "http://wellsfargo-update.cf/verify",
    "https://www.github.com/security/advisories",
    "https://www.google.com/search?q=cybersecurity+defense",
    "https://en.wikipedia.org/wiki/Phishing",
    "http://amazon-orders-verification.xyz/order-review"
]


# Pydantic Schemas
class URLRequest(BaseModel):
    url: str


class EmailRequest(BaseModel):
    subject: str = ""
    sender: str = ""
    claimed_org: str = ""
    body: str = ""
    has_attachment: bool = False


class PredictionResponse(BaseModel):
    url: str
    label: str
    is_phishing: bool
    confidence: float
    risk_score: float
    features: Dict[str, Any]
    reasons: List[Dict[str, Any]]


def run_url_prediction(url_str: str) -> Dict[str, Any]:
    """Helper to predict risk and generate explanations for a URL."""
    if not url_str or not url_str.strip():
        raise HTTPException(status_code=400, detail="URL cannot be empty")

    url = url_str.strip()
    feat_dict = extract_url_features(url)

    if model is None:
        raise HTTPException(status_code=500, detail="Production ML model is not loaded")

    # Predict probability
    vector = [feat_dict.get(k, 0) for k in feature_names]
    probs = model.predict_proba([vector])[0]
    p_phish = float(probs[1])

    is_phish = bool(p_phish >= 0.5)
    label = "Phishing" if is_phish else "Legitimate"
    confidence = round((p_phish if is_phish else (1.0 - p_phish)) * 100, 2)
    risk_score = round(p_phish * 100, 1)

    reasons = explain_prediction(model, feature_names, feat_dict, top_k=5)

    return {
        'url': url,
        'label': label,
        'is_phishing': is_phish,
        'confidence': confidence,
        'risk_score': risk_score,
        'features': feat_dict,
        'reasons': reasons
    }


@app.get("/api/health")
def health_check():
    return {
        "status": "online",
        "model_loaded": model is not None,
        "model_type": model_metadata.get('model_name', 'None')
    }


@app.post("/api/predict", response_model=PredictionResponse)
def predict_url(req: URLRequest):
    """Classifies a URL and returns human-readable rule-based explanation factors."""
    return run_url_prediction(req.url)


@app.post("/api/analyze-content")
def analyze_content(req: URLRequest):
    """Multi-Modal endpoint combining lexical URL features and live HTML page scraping."""
    # SSRF Validation: reject requests to private, loopback, or reserved IP ranges
    is_safe, ssrf_error = check_ssrf_safe(req.url)
    if not is_safe:
        raise HTTPException(status_code=400, detail=f"SSRF Protection: {ssrf_error}")

    url_pred = run_url_prediction(req.url)
    try:
        page_report = analyze_page(req.url, timeout=5)
    except SSRFSecurityError as e:
        raise HTTPException(status_code=400, detail=f"SSRF Protection: {str(e)}")

    # Multi-modal risk combination
    combined_risk = url_pred['risk_score']
    extra_reasons = []

    if page_report.get('has_invalid_cert'):
        combined_risk = min(combined_risk + 20, 100)
        extra_reasons.append({
            'feature': 'page_invalid_cert',
            'impact': 0.25,
            'reason': "Invalid or untrusted TLS/SSL certificate detected on host",
            'severity': 'critical',
            'badge': '🔴'
        })

    if page_report.get('has_login_form') and url_pred['is_phishing']:
        combined_risk = min(combined_risk + 10, 100)
        extra_reasons.append({
            'feature': 'page_login_form',
            'impact': 0.20,
            'reason': "Page presents a password/credential entry form on an untrusted domain",
            'severity': 'critical',
            'badge': '🔴'
        })

    if page_report.get('has_brand_mismatch'):
        combined_risk = min(combined_risk + 20, 100)
        detected = page_report.get('detected_brand', 'Target')
        extra_reasons.append({
            'feature': 'page_brand_mismatch',
            'impact': 0.30,
            'reason': f"Brand Impersonation: Page claims to be {detected.capitalize()} but domain is unaffiliated",
            'severity': 'critical',
            'badge': '🔴'
        })

    if page_report.get('external_resource_ratio', 0) > 0.60:
        combined_risk = min(combined_risk + 5, 100)
        extra_reasons.append({
            'feature': 'page_external_resources',
            'impact': 0.10,
            'reason': "Abnormally high ratio of external scripts/assets (possible content scraping)",
            'severity': 'warning',
            'badge': '🟡'
        })

    all_reasons = extra_reasons + url_pred['reasons']

    return {
        **url_pred,
        'risk_score': round(combined_risk, 1),
        'label': 'Phishing' if combined_risk >= 50 else 'Legitimate',
        'is_phishing': combined_risk >= 50,
        'page_analysis': page_report,
        'reasons': all_reasons[:6]
    }


@app.post("/api/analyze-email")
def analyze_email(req: EmailRequest):
    """Analyzes email headers and body text for social engineering and phishing tactics."""
    data = req.model_dump()
    feats = extract_email_features(data)
    
    reasons = []
    if feats['sender_domain_mismatch']:
        reasons.append({
            'rule': 'Sender Domain Spoof',
            'badge': '🔴',
            'detail': f"Sender does not match declared company '{req.claimed_org}'"
        })
    if feats['urgency_score'] > 0:
        reasons.append({
            'rule': 'Psychological Urgency',
            'badge': '🟡',
            'detail': f"Detected {feats['urgency_score']} urgency trigger(s) attempting to rush recipient"
        })
    if feats['html_form_present']:
        reasons.append({
            'rule': 'Embedded Form',
            'badge': '🔴',
            'detail': "Email contains embedded interactive input/form elements"
        })
    if feats['cred_request_score'] > 0:
        reasons.append({
            'rule': 'Credential Solicitation',
            'badge': '🔴',
            'detail': "Explicit keywords requesting passwords, banking, or personal tokens"
        })

    return {
        'is_suspicious': bool(feats['is_suspicious_email']),
        'risk_score': feats['email_risk_score'],
        'verdict': 'Phishing Email' if feats['is_suspicious_email'] else 'Legitimate Email',
        'features': feats,
        'reasons': reasons
    }


@app.get("/api/live-feed")
def get_live_feed(count: int = 8):
    """
    Simulates real-time ingestion from the PhishTank verified threat feed,
    evaluating each URL live through the PhishGuard inference engine.
    """
    selected_urls = random.sample(RECENT_PHISHTANK_SAMPLES, min(count, len(RECENT_PHISHTANK_SAMPLES)))
    feed_results = []

    for item_url in selected_urls:
        try:
            pred = run_url_prediction(item_url)
            feed_results.append({
                'url': item_url,
                'label': pred['label'],
                'confidence': pred['confidence'],
                'risk_score': pred['risk_score'],
                'is_phishing': pred['is_phishing'],
                'top_reason': pred['reasons'][0]['reason'] if pred['reasons'] else "Standard analysis"
            })
        except Exception:
            continue

    return feed_results


@app.get("/api/metrics")
def get_metrics():
    """Returns baseline vs champion model benchmarks."""
    if os.path.exists(METRICS_PATH):
        with open(METRICS_PATH, 'r') as f:
            return json.load(f)
    return {"metrics": {}}


# Mount frontend static directory
FRONTEND_DIR = os.path.join(ROOT_DIR, 'frontend')
if os.path.exists(FRONTEND_DIR):
    app.mount("/static", StaticFiles(directory=FRONTEND_DIR), name="static")

    @app.get("/")
    def serve_index():
        return FileResponse(os.path.join(FRONTEND_DIR, 'index.html'))
