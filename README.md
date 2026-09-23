# 🛡️ PhishGuard — Explainable AI Phishing Detection System

> **Course Project:** Software Engineering / Applied Machine Learning  
> **Architecture:** Multi-Modal Feature Extraction · Ensemble Modeling · Rule-Based Feature Attribution · FastAPI · Responsive Cyber-Defense UI  

[![Tests](https://img.shields.io/badge/pytest-passing-brightgreen.svg)](#8-testing--verification)
[![Python](https://img.shields.io/badge/python-3.11%20%7C%203.12%20%7C%203.14-blue.svg)](#2-quickstart)
[![Recall](https://img.shields.io/badge/Phishing%20Recall-100%25-success.svg)](#5-model-benchmarks)

---

## 📌 Project Overview
PhishGuard is an intelligent phishing detection and explainability platform. Rather than acting as an opaque "black-box" classifier, PhishGuard unpacks every prediction into **human-readable risk factors** powered by directional, rule-based feature attribution.

### Key Differentiators
1. **Explainability as a First-Class Feature**: Every flagged link provides plain-English reasons (e.g., *"🔴 URL uses raw IP address instead of domain name (+0.32)"*, *"🔴 Missing HTTPS encryption (+0.28)"*).
2. **Multi-Modal Threat Inspection**: Combines **17 lexical URL features**, live **DOM landing page scraping** (login password forms, brand-to-domain mismatches, external asset ratios, and TLS certificate validation), and **email social engineering heuristics**.
3. **Live Threat Feed Ingestion**: Ingests and classifies real-time URLs simulating live PhishTank telemetry with sub-second inference.

---

## 📁 Repository Structure
```
phishguard/
├── data/
│   ├── prepare_dataset.py       # 10k balanced dataset generator & preprocessor
│   └── processed/
│       ├── urls_cleaned.csv     # Cleaned, deduplicated labeled URLs
│       └── features.csv         # 17 extracted feature vectors (7,974 samples)
├── src/
│   ├── features/
│   │   ├── url_features.py      # 17 structural, lexical, and entropy features
│   │   └── email_features.py    # Sender mismatch, urgency score, credential keywords
│   ├── scraper/
│   │   └── page_analyzer.py     # Safe DOM scraper (forms, external ratio, cert validation, SSRF guard)
│   ├── models/
│   │   ├── ml_engine.py         # High-performance native ML engine (LR, RF, GBDT)
│   │   ├── train.py             # Stratified 80/20 train & benchmark pipeline
│   │   └── saved/
│   │       ├── production_model.pkl  # Champion model artifact
│   │       └── metrics.json          # Benchmark evaluation metrics
│   ├── explainability/
│   │   └── explainer.py         # Rule-based feature attribution & reason synthesizer
│   └── api/
│       └── main.py              # FastAPI microservice with /predict, /live-feed, /analyze-content
├── frontend/
│   ├── index.html               # Cyber-defense UI with gauges, factor breakdowns & ticker
│   ├── style.css                # Dark mode styling with animated risk meters
│   └── app.js                   # Interactive client controller & REST bindings
├── tests/
│   ├── test_url_features.py     # Unit tests for URL extractors & edge cases
│   ├── test_models.py           # Model inference and probability tests
│   └── test_api.py              # API endpoint integration tests
├── docs/
│   ├── report.md                # Comprehensive project report & academic paper
│   └── SYSTEM_EXPLAINER.md      # In-depth architectural & theoretical guide
├── requirements.txt
└── README.md
```

---

## 🚀 Quickstart

### 1. Setup Environment
```bash
# Clone the repository
git clone https://github.com/your-org/phishguard.git
cd phishguard

# Install dependencies
pip install -r requirements.txt
```

### 2. Prepare Data & Train Models
```bash
# Generate balanced 10k dataset and extract 17 features
python data/prepare_dataset.py

# Train baseline and champion models
python -m src.models.train
```

### 3. Run Automated Tests
```bash
python -m pytest tests/ -v
```

### 4. Launch the Web Dashboard
```bash
python -m uvicorn src.api.main:app --reload --port 8000
```
Open your browser and navigate to: **`http://localhost:8000`**

---

## 📊 Model Benchmarks

PhishGuard prioritizes **Recall** to minimize false negatives (catching malicious URLs before they compromise users):

| Model Architecture | Accuracy | Precision | Recall (Phishing) | F1-Score | ROC-AUC |
|-------------------|----------|-----------|-------------------|----------|---------|
| **Logistic Regression (Baseline)** | 99.94% | 99.88% | **100.00%** | 0.9994 | 1.0000 |
| **Random Forest (Champion)** | **100.00%** | **100.00%** | **100.00%** | **1.0000** | **1.0000** |
| **Gradient Boosted Trees (GBDT)** | 99.87% | 99.75% | **100.00%** | 0.9988 | 0.9996 |

> **⚠️ Dataset Limitations & Feature Leakage Caveat:**  
> The training and test datasets were generated synthetically using heuristic generators (`data/prepare_dataset.py`) based on explicit patterns (IP addresses, keywords, risky TLDs, hyphens) that directly align with the 17 extracted features. Consequently, the near-100% benchmark numbers reflect the strong separability of this synthetic generator rather than guaranteed real-world phishing detection capability against evasive zero-day threats. Evaluating against held-out, non-synthetic corpora (e.g., active PhishTank/OpenPhish feeds) is required for operational deployment.

---

## 🔬 Extracted URL Features

1. `url_length` — Total character length of URL
2. `hostname_length` — Length of authority/hostname
3. `num_dots` — Dot count across URL
4. `num_hyphens` — Hyphen count (brand typosquatting marker)
5. `num_at` — `@` symbol count (host masking technique)
6. `num_subdomains` — Depth of subdomain chaining
7. `has_ip` — Raw IPv4 address detection
8. `is_https` — Protocol security status
9. `has_shortener` — Known URL shorteners (`bit.ly`, `tinyurl.com`, etc.)
10. `path_length` — Character length of URL path
11. `num_query_params` — Query parameter count
12. `has_suspicious_words` — Presence of `login`, `verify`, `account`, `bank`, etc.
13. `special_char_ratio` — Special characters / total length
14. `digit_ratio` — Digits / total length
15. `has_redirect` — Double slash `//` in path
16. `tld_risk` — Known high-abuse TLDs (`.tk`, `.ml`, `.ga`, `.xyz`, etc.)
17. `entropy` — Shannon entropy (randomness and algorithmic generation marker)

---

## 📡 REST API Reference

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/predict` | Classifies URL, returns confidence % and top rule-based attribution factors |
| `POST` | `/api/analyze-content` | Multi-modal scan combining URL features + live DOM scraping (SSRF protected) |
| `POST` | `/api/analyze-email` | Evaluates email headers, sender spoofing, and urgency triggers |
| `GET`  | `/api/live-feed` | Simulates real-time threat ingestion from PhishTank feed |
| `GET`  | `/api/metrics` | Returns model benchmark evaluation report |
| `GET`  | `/api/health` | Health check endpoint confirming model status |

---

## 🛡️ License & Acknowledgements
Built for Software Engineering Capstone Course. Licensed under the MIT License.
