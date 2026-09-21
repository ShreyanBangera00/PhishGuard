# PhishGuard — Software Engineering Process & Milestone Tracker

> **Course:** Software Engineering  
> **Status:** ✅ All Phases 0 through 10 Completed & Verified  

---

## Milestone Progress Summary

| Phase | Description | Status | Key Deliverable |
|---|---|:---:|---|
| **Phase 0** | Environment Setup | ✅ | Dependencies, directory structure, and environment verification |
| **Phase 1** | Dataset Acquisition & Preparation | ✅ | 7,974 balanced samples deduplicated & split 80/20 |
| **Phase 2** | Feature Engineering | ✅ | 17 structural/lexical URL features + email heuristics |
| **Phase 3** | Baseline Models (LR & RF) | ✅ | Logistic Regression (99.94% Acc), Random Forest (100% Acc) |
| **Phase 4** | Model Improvement (GBDT) | ✅ | Gradient Boosting Classifier (99.87% Acc, 100% Recall) |
| **Phase 5** | Explainability Layer (Differentiator #1) | ✅ | Rule-based feature attribution with human-readable diagnostic cards |
| **Phase 6** | Multi-Modal Detection (Differentiator #2) | ✅ | DOM page scraper (passwords, brand mismatch, external ratio) |
| **Phase 7** | Web Interface & Live Demo (Differentiator #3) | ✅ | Dark cyber-defense UI with live threat feed ticker |
| **Phase 8** | Testing & Edge Cases | ✅ | 19 automated tests passing with 0 errors in < 1.0s |
| **Phase 9** | Documentation & Report | ✅ | Complete `docs/report.md` with 12 sections & architecture diagram |
| **Phase 10** | Packaging & Delivery | ✅ | `README.md`, `requirements.txt`, clean modular structure |

---

## Phase Checklist

- [x] **0.1** Create project directory structure
- [x] **0.2** Configure environment & dependencies (`pandas`, `numpy`, `fastapi`, `uvicorn`, `requests`, `bs4`, `tldextract`, `pytest`)
- [x] **1.1 - 1.7** Curate and clean balanced dataset; save `urls_cleaned.csv` and `features.csv`
- [x] **2.1 - 2.5** Implement `extract_url_features(url)` with all 17 features; build `email_features.py`
- [x] **3.1 - 3.6** Train Logistic Regression & Random Forest baseline models; calculate Recall/F1/ROC-AUC
- [x] **4.1 - 4.6** Train and tune Gradient Boosted Trees; select champion model (`production_model.pkl`)
- [x] **5.1 - 5.6** Implement explainability layer (`src/explainability/explainer.py`) with badge & reason formatting
- [x] **6.1 - 6.4** Implement sandboxed DOM page analyzer (`src/scraper/page_analyzer.py`)
- [x] **7.1 - 7.6** Develop FastAPI REST microservice & high-contrast cyber-defense dashboard
- [x] **8.1 - 8.4** Implement and run automated test suite (`tests/`): 19 unit & integration tests passing
- [x] **9.1 - 9.4** Author comprehensive technical report (`docs/report.md`) with architecture diagram & docstrings
- [x] **10.1 - 10.6** Freeze dependencies in `requirements.txt` and finalize `README.md`
