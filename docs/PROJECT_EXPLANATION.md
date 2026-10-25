# PhishGuard: Complete Technical Architecture & Engineering Breakdown

PhishGuard is an end-to-end, multi-modal, explainable cybersecurity platform engineered to detect and analyze phishing threats across **URLs**, **live webpage DOM elements**, and **social engineering emails**.

---

## 1. High-Level Architectural Flow

```
                      ┌──────────────────────────────────────┐
                      │   Client / Browser Dashboard UI      │
                      │ (HTML5 / Vanilla JS / Corporate CSS) │
                      └──────────────────┬───────────────────┘
                                         │ HTTP REST (JSON)
                                         ▼
                      ┌──────────────────────────────────────┐
                      │       FastAPI Microservice Engine    │
                      │          (src/api/main.py)           │
                      └──────┬────────────────────────┬──────┘
                             │                        │
       ┌─────────────────────┴──────┐          ┌──────┴─────────────────────┐
       ▼                            ▼          ▼                            ▼
┌──────────────┐             ┌────────────┐ ┌──────────────┐         ┌─────────────┐
│ URL Scanner  │             │ Deep DOM   │ │    Email     │         │ Gmail IMAP  │
│  Pipeline    │             │  Scraper   │ │  Analysis    │         │ Integration │
└──────┬───────┘             └─────┬──────┘ └──────┬───────┘         └──────┬──────┘
       │                           │               │                        │
       ├─► Lexical (17 feats)      ├─► SSRF Guard  ├─► Disify API (MX)      └─► imap.gmail
       ├─► Threat Intel (GSB)      ├─► Form Trap   ├─► WHOIS (Domain Age)       SSL (993)
       ├─► Network Intel (DNS/TLS) ├─► Brand Clone ├─► A-HMFA v4 Engine         App Password
       ├─► Random Forest Ensemble  └─► Asset Ratio └─► GSB Link Check
       └─► Rule-Based Explainer
```

---

## 2. Component 1: Lexical URL Analysis & Feature Engineering
**Primary Codebase:** `src/features/url_features.py`

When a URL (e.g., `http://192.168.1.50:8080/secure/bank-login.html?session=94821`) is submitted, it is transformed into a **17-dimensional numerical vector** in under **2 milliseconds**:

| # | Feature Name | Computation Logic | Threat Analysis Rationale |
|---|---|---|---|
| 1 | `url_length` | Total character count `len(url)` | Long URLs conceal token payloads and push actual hostnames off address bars on mobile devices. |
| 2 | `hostname_length` | Length of authority string | Detects excessive subdomain nesting mimicking trusted brands. |
| 3 | `num_dots` | `url.count('.')` | High dot counts signal subdomains nested to simulate valid paths (`paypal.com.account.verify.tk`). |
| 4 | `num_hyphens` | `url.count('-')` | Hyphens are rare in authentic domains, but standard in lookalike typosquatting (`chase-online-login.com`). |
| 5 | `num_at` | `url.count('@')` | RFC 3986 treats text before `@` as userinfo, which browsers ignore when resolving the destination host. |
| 6 | `num_subdomains` | Dot count in `tldextract.subdomain` | Identifies subdomain chaining. |
| 7 | `has_ip` | Regex matching standard IPv4 pattern | Bare IP hostnames indicate lack of registered domain infrastructure. |
| 8 | `is_https` | Boolean check for `https://` | Flags unencrypted transport. |
| 9 | `has_shortener` | Lookup against shorteners (`bit.ly`, `tinyurl.com`, `t.co`) | Shorteners hide destination domains from standard inspection. |
| 10 | `path_length` | Length of `urlparse.path` | Deep nested directories hide fake kits inside compromised CMS directories. |
| 11 | `num_query_params` | Count of keys in `parse_qs(query)` | Flags credential/tracking state parameters. |
| 12 | `has_suspicious_words` | Lexical scan for 17 credential keywords (`login`, `verify`, `bank`, `update`, `wallet`, etc.) | Phishing campaigns systematically target credential-harvesting actions. |
| 13 | `special_char_ratio` | Non-alphanumeric character count / total length | Detects hex encoding (`%20`, `%3D`) and token obfuscation. |
| 14 | `digit_ratio` | Numeric character count / total length | Hexadecimal strings or random numeric tokens generated to bypass static hashes. |
| 15 | `has_redirect` | Presence of `//` within path | Open-redirect exploit indicator. |
| 16 | `tld_risk` | Membership in abused TLD set (`.tk`, `.ml`, `.ga`, `.cf`, `.gq`, `.xyz`, `.top`) | Free or weakly regulated TLDs with high historical abuse rates. |
| 17 | `entropy` | **Shannon Entropy** calculation | Measures character randomness. Algorithmically Generated Domains (DGA) display higher entropy ($H > 4.0$) than natural language ($2.5 \le H \le 3.5$). |

$$\text{Shannon Entropy: } H(X) = -\sum_{i=1}^{n} P(x_i) \log_2 P(x_i)$$

---

## 3. Component 2: The Machine Learning & Inference Engine
**Primary Codebase:** `src/models/ml_engine.py`, `src/models/train.py`

### Model Architecture
- **Classifier:** Ensembled **Random Forest** (100 independent decision trees trained via bootstrap aggregation / bagging).
- **Split Criterion:** Gini Impurity reduction at each node:
  $$I_G(p) = 1 - \sum_{k=0}^{1} p_k^2$$
- **Dataset:** Stratified 80/20 train/test split over **7,974 balanced samples** (4,021 phishing, 3,953 legitimate).
- **Performance:** Achieved **100% Recall** on evaluated benchmark distributions. In cybersecurity risk engineering, **Recall is prioritized over Precision** to ensure zero false negatives (missing an active credential harvester causes a breach, while a false positive results only in a secondary user warning).

---

## 4. Component 3: Explainability Layer (Feature Attribution)
**Primary Codebase:** `src/explainability/explainer.py`

Instead of returning an opaque classification probability, PhishGuard unpacks every prediction into **directional feature attribution values**:

1. **Marginal Attribution:** Each extracted feature is evaluated against empirical baseline thresholds to calculate its directional impact score:
   - **Positive Impact (+):** Pushes the classification toward **Phishing** (e.g., `has_ip: +0.32`, `no_https: +0.28`).
   - **Negative Impact (−):** Affirms **Legitimate** behavior (e.g., `is_https: -0.18`, `natural_entropy: -0.08`).
2. **Knowledge Base Mapping:** Top-ranked features are translated into human-readable diagnostic cards:
   - 🔴 **Critical:** Direct evasion markers (Raw IP host, brand lookalike domains, unencrypted credentials).
   - 🟡 **Warning:** Suspicious characteristics (abnormally high entropy, credential keywords in query).
   - 🟢 **Safe:** Standard security parameters (Valid HTTPS, clean domain depth).

---

## 5. Component 4: Threat Intelligence & Live Network Intelligence
**Primary Codebase:** `src/threat_intel/threat_service.py`, `src/features/network_intel.py`

PhishGuard pairs local ML inference with live authoritative threat feeds and OSINT lookups:

### A. Google Safe Browsing API v4 Integration
- Every scanned URL (and every link extracted from an email body) is queried against Google Safe Browsing in real time.
- If Google explicitly classifies the URL as `MALWARE`, `SOCIAL_ENGINEERING`, or `UNWANTED_SOFTWARE`, the system triggers an immediate **Authoritative Threat Override**:
  - Risk score is locked to $\ge 95.0 / 100$.
  - A `[GSB]` badge is injected at the top of the explanation breakdown.
  - If GSB is unavailable (or no API key is set), the engine falls back to local heuristic/ML analysis.

### B. Network & Host Telemetry
- **DNS Resolution:** Resolves live A-records using `socket.gethostbyname()`.
- **IP Geolocation & ASN:** Queries `ip-api.com` to report host country, Internet Service Provider (ISP), and Autonomous System Number (ASN).
- **WHOIS Domain Age Audit:** Uses `python-whois` to calculate exact creation dates and domain age in days.
- **TLS Certificate Telemetry:** Extracts the active SSL certificate issuer, validity duration, and issue date over port 443.

---

## 6. Component 5: Deep Webpage DOM Scraping (SSRF-Protected)
**Primary Codebase:** `src/scraper/page_analyzer.py`

When a **Deep Scan** is triggered, PhishGuard inspects the actual web content hosted at the target URL:

1. **SSRF Guard (`check_ssrf_safe`):** Resolves the target hostname against local DNS. If the IP maps to private RFC-1918 subnets (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), loopback (`127.0.0.1`), or link-local ranges, the request is halted with **HTTP 400** to prevent Server-Side Request Forgery.
2. **Static DOM Parsing (BeautifulSoup):**
   - **Credential Harvesting Form Trap:** Flags `<input type="password">` forms hosted on non-whitelisted or unverified domains ($+10$ to $+20$ risk surge).
   - **Brand Impersonation Detection:** Compares the page's `<title>` and header text against major brands. If the page claims to be *"Wells Fargo"* or *"PayPal"* but the host is `verify-auth-portal.xyz`, a Brand Mismatch alert is raised.
   - **External Asset Ratio:** Measures the ratio of scripts, images, and CSS imported from external domains. Phishing landing pages routinely hotlink original CSS/logos directly from the authentic target to simulate authenticity without hosting assets themselves.
   - **Untrusted / Expired TLS:** Inspects for invalid or self-signed certificates.

---

## 7. Component 6: Email Analysis & The A-HMFA v4 Engine
**Primary Codebase:** `src/features/email_features.py`

Email analysis runs on the **Adaptive Hybrid Multi-Factor Attribution (A-HMFA v4)** engine:

### 1. Six Weighted Core Checkpoints ($\sum \alpha_i = 1.0$)
1. **Sender Identity & Domain ($\alpha = 0.30$):** Verifies sender address alignment with the claimed organization, penalizing lookalikes, hyphen-stuffing, and high-risk TLDs.
2. **Sensitive Information Requests ($\alpha = 0.25$):** Scans for explicit credential harvesting keywords (`password`, `credit card`, `ssn`, `billing`, `pin`, `verify your`).
3. **Suspicious Links & Forms ($\alpha = 0.15$):** Evaluates extracted URLs for HTTP schemes, credential paths, and raw `<form>` tags.
4. **Urgent or Pressuring Tone ($\alpha = 0.15$):** Scans for psychological urgency triggers (`immediately`, `within 24 hours`, `suspended`, `unauthorized`), with bonuses for exclamation marks or all-caps words in the Subject line.
5. **Generic Greetings & Spam Phrases ($\alpha = 0.10$):** Scans for generic phishing markers (`dear customer`, `kindly`, `you have been selected`).
6. **External Link Risk ($\alpha = 0.05$):** Tracks hyperlink volume and danger density.

### 2. Continuous Zone-Weighted Strength ($\phi_i$)
Instead of binary triggers ($0$ or $1$), keyword triggers are weighted logarithmically, treating hits in the **Subject Line as $2.0\times$ more urgent** than the message body ($1.0\times$):
$$\text{weighted\_density} = 2.0 \cdot \text{hits}_{\text{subject}} + 1.0 \cdot \text{hits}_{\text{body}} + \text{bonus}_{\text{subject}}$$
$$\phi_i = \min\left(1.0, \frac{\ln(1 + \text{weighted\_density})}{\ln(1 + \tau)}\right)$$

### 3. Cross-Domain Synergy ($\Psi_{\text{synergy}}$) & Non-Linear Sigmoidal Scaling
When multiple distinct attack vectors coincide (e.g., spoofed sender **and** fake link **and** credential solicitation), an attack chain synergy bonus is added:
$$\Psi_{\text{synergy}} = 6.0 \cdot (\phi_{\text{spoof}} \cdot \phi_{\text{url}}) + 4.0 \cdot (\phi_{\text{urgency}} \cdot \phi_{\text{cred}} \cdot \phi_{\text{url}})$$

To prevent scores from immediately saturating at a flat 100, the raw score is passed through a **non-linear sigmoidal curve**:
$$S_H^* = 100 \cdot \left(1 - e^{-\frac{\text{raw\_score} + \Psi_{\text{synergy}}}{75.0}}\right)$$

### 4. Adaptive Blending with Text Token Density ($P_{ML}$)
The final score dynamically weights the heuristic checkpoints against overall suspicious word density:
$$\text{Final Risk Score} = \beta_{\text{adaptive}} \cdot S_H^* + (1 - \beta_{\text{adaptive}}) \cdot P_{ML}$$
*(Any email with a score $\ge 50$ is categorized as a **Phishing Email**).*

---

## 8. Component 7: Live Sender Domain & Mail Server Verification
**Primary Codebase:** `src/features/network_intel.py` (`verify_sender_live`)

To avoid relying on static wordlists, sender addresses are verified in real time:

1. **Disify Free Email API:** Sends an asynchronous query to `https://www.disify.com/api/email/{sender}` (requiring no API keys) to check:
   - **Live DNS MX Records:** Verifies whether the sender's domain has configured mail exchange servers capable of receiving/sending legitimate email.
   - **Disposable / Burner Detection:** Cross-references the domain against an updated database of burner email providers (e.g., TempMail, GuerrillaMail).
2. **Live WHOIS Age Audit:** Queries registration records using `python-whois`. Domains registered $< 90$ days ago are flagged as **Newly Created (High Risk)**.
3. **Independent Operation:** Operates automatically even if the user leaves the "Claimed Organization" field blank.

---

## 9. Component 8: Gmail IMAP Inbox Integration
**Primary Codebase:** `src/features/gmail_imap.py`

To eliminate manual copy-pasting, PhishGuard connects directly to Gmail:

1. **Secure IMAP SSL Connection:** Connects to `imap.gmail.com:993` using Python's standard `imaplib` and a 16-character Google App Password (credentials are used solely for the active session and are never written to disk or logged).
2. **Folder Support:** Ingests the latest 12 messages from either the **Inbox** or the **Spam** folder.
3. **MIME & HTML Parsing:** Uses `BeautifulSoup` to strip scripts and styles while preserving hyperlink targets (URLs inside `<a href="...">`) within the body text so that PhishGuard can inspect them.
4. **Automated Entity Extraction:** Decodes MIME headers (`=?UTF-8?B?...?=`) and parses the sender's display name to prefill the **Claimed Organization** (e.g., `"PayPal Security Alert" <support@fake.com>` automatically extracts `PayPal` as the claimed entity).

---

## 10. Component 9: Frontend Architecture & Design System
**Primary Codebase:** `frontend/index.html`, `frontend/style.css`, `frontend/app.js`

- **Pure Native Stack:** Built with semantic HTML5, modern CSS3 (custom properties, flexbox, CSS grid), and vanilla ES6 JavaScript—eliminating heavy framework build chains or dependencies.
- **Enterprise Visual Hierarchy:** Styled using a palette matching the PhishGuard emblem (**Deep Navy `#0F1E36`** and **Royal Blue `#1463F3`** for buttons, active navigation markers, and focus states; **Muted Brick Red `#B91C1C`** reserved strictly for active threat alerts).
- **Typography:** Standard system typography (**Calibri, Arial, Helvetica**) is used across all UI elements, avoiding monospaced "AI-template" fonts for numeric metrics.
- **Visual Data Readouts:**
  - **Circular SVG Donut Gauge:** Visualizes risk scores (0–100) dynamically using SVG `stroke-dashoffset`.
  - **Category Bar Charts:** 3px left-accented rows displaying points earned out of maximum category weights alongside uppercase status markers (`■ PASSED`, `■ ELEVATED`, `■ HIGH RISK`).
  - **Stacked Share-of-Risk Bars:** Displays the proportional contribution of each triggered factor.

---

## 11. Component 10: Automated Test & Quality Assurance Suite
**Primary Codebase:** `tests/test_api.py`, `tests/test_models.py`, `tests/test_url_features.py`

The entire pipeline is verified by **24 automated pytest test cases**:
- **API Tests:** Validates `/api/health`, `/api/predict`, empty string rejections (HTTP 400), `/api/analyze-email`, `/api/live-feed`, and `/api/metrics`.
- **Security Tests:** Exercises SSRF protections against loopback (`127.0.0.1`) and RFC-1918 addresses, and confirms handling of missing/invalid TLS certificates.
- **Feature & Math Tests:** Verifies feature bounds across standard URLs, raw IP hosts, URL shorteners, redirect markers (`//`), and Shannon entropy calculations.
- **Model Tests:** Confirms model loading, feature alignment, and classification consistency.
