// PhishGuard Frontend Controller
document.addEventListener('DOMContentLoaded', () => {
  // Elements
  const tabs = document.querySelectorAll('.tab-btn');
  const tabContents = document.querySelectorAll('.tab-content');
  const urlInput = document.getElementById('url-input');
  const btnScan = document.getElementById('btn-scan');
  const btnDeepScan = document.getElementById('btn-deep-scan');
  const scanLoader = document.getElementById('scan-loader');
  const resultSection = document.getElementById('result-section');

  // Verdict Elements
  const verdictBanner = document.getElementById('verdict-banner');
  const verdictIcon = document.getElementById('verdict-icon');
  const verdictTag = document.getElementById('verdict-tag');
  const verdictTitle = document.getElementById('verdict-title');
  const targetUrlDisplay = document.getElementById('target-url-display');
  const confidenceValue = document.getElementById('confidence-value');
  const riskBarFill = document.getElementById('risk-bar-fill');
  const riskCaption = document.getElementById('risk-caption');
  const reasonsList = document.getElementById('reasons-list');
  const featureChips = document.getElementById('feature-chips');
  const pageScanDetails = document.getElementById('page-scan-details');
  const pageSignals = document.getElementById('page-signals');

  // Email Elements
  const emailSender = document.getElementById('email-sender');
  const emailClaimedOrg = document.getElementById('email-claimed-org');
  const emailSubject = document.getElementById('email-subject');
  const emailBody = document.getElementById('email-body');
  const btnScanEmail = document.getElementById('btn-scan-email');
  const btnTestPhishEmail = document.getElementById('btn-test-phish-email');
  const emailResult = document.getElementById('email-result');

  // ─── 1. Tab Switching ───
  tabs.forEach(btn => {
    btn.addEventListener('click', () => {
      tabs.forEach(t => t.classList.remove('active'));
      tabContents.forEach(c => c.classList.remove('active'));

      btn.classList.add('active');
      const targetTab = document.getElementById(btn.dataset.tab);
      if (targetTab) {
        targetTab.classList.add('active');
      }
    });
  });

  // ─── 2. Scan Triggers ───
  btnScan.addEventListener('click', () => triggerScan(false));
  btnDeepScan.addEventListener('click', () => triggerScan(true));

  urlInput.addEventListener('keypress', (e) => {
    if (e.key === 'Enter') triggerScan(false);
  });

  async function triggerScan(isDeep = false) {
    const url = urlInput.value.trim();
    if (!url) {
      alert('Please enter a URL to analyze.');
      return;
    }

    scanLoader.classList.remove('hidden');
    resultSection.classList.add('hidden');

    try {
      const endpoint = isDeep ? '/api/analyze-content' : '/api/predict';
      const response = await fetch(endpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url })
      });

      if (!response.ok) {
        const err = await response.json();
        throw new Error(err.detail || 'Analysis failed');
      }

      const data = await response.json();
      renderVerdict(data, isDeep);
    } catch (err) {
      alert('Error: ' + err.message);
    } finally {
      scanLoader.classList.add('hidden');
    }
  }

  // ─── 3. Render URL Verdict ───
  function renderVerdict(data, isDeep = false) {
    resultSection.classList.remove('hidden');

    const isPhish = data.is_phishing;
    targetUrlDisplay.textContent = data.url;
    confidenceValue.textContent = `${data.confidence}%`;
    riskCaption.textContent = `Risk Score: ${data.risk_score} / 100`;
    riskBarFill.style.width = `${Math.min(Math.max(data.risk_score, 3), 100)}%`;

    if (isPhish) {
      verdictBanner.className = 'verdict-banner danger';
      verdictIcon.innerHTML = '<svg viewBox="0 0 24 24"><path d="M18 6L6 18M6 6l12 12"/></svg>';
      verdictTag.textContent = 'THREAT DETECTED';
      verdictTitle.textContent = 'Phishing Attack Detected';
    } else {
      verdictBanner.className = 'verdict-banner safe';
      verdictIcon.innerHTML = '<svg viewBox="0 0 24 24"><path d="M20 6L9 17l-5-5"/></svg>';
      verdictTag.textContent = 'SAFE';
      verdictTitle.textContent = 'URL Appears Legitimate';
    }

    reasonsList.innerHTML = '';
    (data.reasons || []).forEach(r => {
      const item = document.createElement('div');
      item.className = `reason-item ${r.severity || 'neutral'}`;

      const sign = r.impact > 0 ? '+' : '';
      item.innerHTML = `
        <div class="reason-left">
          <span class="reason-dot"></span>
          <span>${r.reason}</span>
        </div>
        <span class="reason-impact">${sign}${r.impact.toFixed(3)}</span>
      `;
      reasonsList.appendChild(item);
    });

    featureChips.innerHTML = '';
    const feats = data.features || {};
    const displayKeys = [
      'url_length', 'hostname_length', 'num_dots', 'num_hyphens',
      'has_ip', 'is_https', 'has_shortener', 'num_subdomains',
      'has_suspicious_words', 'entropy', 'tld_risk', 'has_redirect'
    ];

    displayKeys.forEach(k => {
      if (feats[k] !== undefined) {
        const chip = document.createElement('div');
        chip.className = 'feat-chip';
        const label = k.replace(/_/g, ' ');
        const val = typeof feats[k] === 'number'
          ? (Number.isInteger(feats[k]) ? feats[k] : feats[k].toFixed(3))
          : feats[k];
        chip.innerHTML = `
          <span class="feat-label">${label}</span>
          <span class="feat-val">${val}</span>
        `;
        featureChips.appendChild(chip);
      }
    });

    if (data.threat_intel && data.threat_intel.google_safe_browsing) {
      const gsb = data.threat_intel.google_safe_browsing;
      const existingBadge = resultSection.querySelector('.threat-intel-badge');
      if (existingBadge) existingBadge.remove();

      const badge = document.createElement('div');
      if (!gsb.available) {
        badge.className = 'threat-intel-badge unavailable';
        badge.textContent = 'Google Safe Browsing: Not configured';
      } else if (gsb.is_threat) {
        badge.className = 'threat-intel-badge active';
        badge.textContent = `Google Safe Browsing: Flagged (${(gsb.threat_types || []).join(', ')})`;
      } else {
        badge.className = 'threat-intel-badge clear';
        badge.textContent = 'Google Safe Browsing: No threats found';
      }

      const verdictRight = document.querySelector('.verdict-right');
      if (verdictRight) verdictRight.appendChild(badge);
    }

    const networkIntelDetails = document.getElementById('network-intel-details');
    const networkSignals = document.getElementById('network-signals');
    if (data.network_intel && (data.network_intel.ip_address || data.network_intel.registrar)) {
      networkIntelDetails.classList.remove('hidden');
      const ni = data.network_intel;
      
      const ipText = ni.ip_address ? `${ni.ip_address} (${ni.country || 'Unknown'}, ${ni.asn_org || 'Unknown ISP'})` : 'Resolution failed';
      const ageText = ni.domain_age_days ? `${ni.domain_age_days} days old (Created: ${ni.creation_date})` : 'Unknown';
      const tlsText = ni.tls_issuer ? `Issued by ${ni.tls_issuer} (Valid for ${ni.tls_valid_days} days)` : 'No valid certificate';

      networkSignals.innerHTML = `
        <div class="page-signal-row"><span>Main Domain</span><strong>${ni.domain || 'N/A'}</strong></div>
        <div class="page-signal-row"><span>DNS A Record</span><strong>${ipText}</strong></div>
        <div class="page-signal-row"><span>Registrar</span><strong>${ni.registrar || 'Hidden / Unknown'}</strong></div>
        <div class="page-signal-row"><span>Domain Age</span><strong>${ageText}</strong></div>
        <div class="page-signal-row"><span>TLS Certificate</span><strong>${tlsText}</strong></div>
      `;
    } else {
      if (networkIntelDetails) networkIntelDetails.classList.add('hidden');
    }

    if (isDeep && data.page_analysis) {
      pageScanDetails.classList.remove('hidden');
      const pa = data.page_analysis;
      pageSignals.innerHTML = `
        <div class="page-signal-row"><span>Landing Page Status</span><strong>${pa.accessible ? 'Accessible (200 OK)' : (pa.error || 'Unreachable')}</strong></div>
        <div class="page-signal-row"><span>TLS / SSL Certificate</span><strong>${pa.has_invalid_cert ? 'Invalid / Untrusted' : 'Valid'}</strong></div>
        <div class="page-signal-row"><span>Page Title</span><strong>${pa.page_title || 'N/A'}</strong></div>
        <div class="page-signal-row"><span>Login Form Present</span><strong>${pa.has_login_form ? 'Yes — credential input detected' : 'No'}</strong></div>
        <div class="page-signal-row"><span>External Asset Ratio</span><strong>${(pa.external_resource_ratio * 100).toFixed(1)}%</strong></div>
        <div class="page-signal-row"><span>Brand Impersonation</span><strong>${pa.has_brand_mismatch ? `Detected (${pa.detected_brand})` : 'None detected'}</strong></div>
      `;
    } else {
      pageScanDetails.classList.add('hidden');
    }

    resultSection.scrollIntoView({ behavior: 'smooth', block: 'start' });
  }

  // ─── Attachment handling (manual upload + Gmail attachments) ───
  const attachInput = document.getElementById('email-attachments');
  const btnClearAttachments = document.getElementById('btn-clear-attachments');
  const attachmentStatus = document.getElementById('attachment-status');
  const MAX_ATTACH_BYTES = 10 * 1024 * 1024;
  const MAX_ATTACH_FILES = 5;
  let attachmentReports = [];

  function formatBytes(n) {
    if (n < 1024) return `${n} B`;
    if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
    return `${(n / (1024 * 1024)).toFixed(1)} MB`;
  }

  function setAttachmentStatus(msg, isError) {
    attachmentStatus.textContent = msg;
    attachmentStatus.className = 'attach-status' + (isError ? ' error' : '') + (msg ? '' : ' hidden');
  }

  function setAttachmentReports(reports) {
    attachmentReports = reports || [];
    if (attachmentReports.length) {
      const names = attachmentReports.map(r => r.filename).join(', ');
      setAttachmentStatus(`${attachmentReports.length} attachment(s) ready to scan: ${names}`, false);
      btnClearAttachments.classList.remove('hidden');
    } else {
      setAttachmentStatus('', false);
      btnClearAttachments.classList.add('hidden');
      attachInput.value = '';
    }
  }

  function fileToBase64(file) {
    return new Promise((resolve, reject) => {
      const reader = new FileReader();
      reader.onload = () => resolve(String(reader.result).split(',')[1] || '');
      reader.onerror = () => reject(new Error(`Could not read ${file.name}`));
      reader.readAsDataURL(file);
    });
  }

  attachInput.addEventListener('change', async () => {
    const files = Array.from(attachInput.files || []);
    if (!files.length) {
      setAttachmentReports([]);
      return;
    }
    if (files.length > MAX_ATTACH_FILES) {
      setAttachmentReports([]);
      setAttachmentStatus(`Please select at most ${MAX_ATTACH_FILES} files.`, true);
      return;
    }
    const tooBig = files.find(f => f.size > MAX_ATTACH_BYTES);
    if (tooBig) {
      setAttachmentReports([]);
      setAttachmentStatus(`${tooBig.name} is larger than ${MAX_ATTACH_BYTES / (1024 * 1024)} MB and cannot be scanned.`, true);
      return;
    }

    setAttachmentStatus('Scanning attachments...', false);
    try {
      const payloadFiles = [];
      for (const f of files) {
        payloadFiles.push({ filename: f.name, content_type: f.type || '', data_b64: await fileToBase64(f) });
      }
      const resp = await fetch('/api/scan-attachments', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ files: payloadFiles })
      });
      const data = await resp.json();
      if (!resp.ok) throw new Error(data.detail || 'Attachment scan failed');
      setAttachmentReports(data.reports || []);
    } catch (e) {
      setAttachmentReports([]);
      setAttachmentStatus(e.message, true);
    }
  });

  btnClearAttachments.addEventListener('click', () => setAttachmentReports([]));

  function attachmentLabel(m) {
    const reps = m.attachment_reports || [];
    if (!reps.length) return '';
    const risky = reps.some(r => r.confirmed_malicious || (r.risk || 0) >= 0.35);
    return `<span class="gmail-att${risky ? ' risky' : ''}">${reps.length} attachment${reps.length > 1 ? 's' : ''}${risky ? ' - flagged' : ''}</span>`;
  }

  function buildAttachmentCard(reports) {
    if (!reports || !reports.length) return '';
    const verdictClass = v => ({
      'Malicious': 'danger', 'High risk': 'danger', 'Suspicious': 'warning',
      'Low risk': 'warning', 'No issues found': 'safe', 'Not scanned': 'neutral'
    }[v] || 'neutral');

    const rows = reports.map(r => {
      const findings = (r.findings || []).filter(f => f.severity !== 'info');
      const vt = r.vt || {};
      let vtText = 'Lookup not configured';
      if (vt.status === 'found') vtText = `${vt.malicious} of ${vt.total} engines flag this file`;
      else if (vt.status === 'not found') vtText = 'Not seen before';
      else if (vt.status === 'rate limited') vtText = 'Lookup rate-limited';
      else if (vt.status && vt.status !== 'not configured') vtText = 'Lookup unavailable';

      let findingsHtml;
      if (r.skipped) {
        findingsHtml = `<span class="attach-meta">${escapeHtml(r.skipped)}</span>`;
      } else if (findings.length) {
        findingsHtml = `<ul class="attach-findings">${findings.map(f => `<li class="${escapeHtml(f.severity)}">${escapeHtml(f.text)}</li>`).join('')}</ul>`;
      } else {
        findingsHtml = '<span class="attach-meta">No suspicious traits found</span>';
      }

      return `
        <tr>
          <td>
            <div class="attach-file-name">${escapeHtml(r.filename)}</div>
            <div class="attach-meta">${formatBytes(r.size || 0)}${r.detected_type ? ' &middot; detected as ' + escapeHtml(r.detected_type) : ''}</div>
            <div class="attach-hash">SHA-256 ${escapeHtml(r.sha256 || '')}</div>
          </td>
          <td><span class="attach-verdict ${verdictClass(r.verdict)}">&#9632; ${escapeHtml(r.verdict || '')}</span></td>
          <td>${findingsHtml}</td>
          <td class="attach-meta">${escapeHtml(vtText)}</td>
        </tr>
      `;
    }).join('');

    return `
      <div class="card">
        <div class="card-header">
          <h3>Attachment Analysis</h3>
          <span class="chip-badge">${reports.length} File${reports.length > 1 ? 's' : ''}</span>
        </div>
        <p class="section-desc">Files are checked in memory using static analysis and a hash lookup. They are never opened or executed.</p>
        <div class="table-responsive">
          <table class="attach-table">
            <thead><tr><th>File</th><th>Verdict</th><th>Findings</th><th>VirusTotal</th></tr></thead>
            <tbody>${rows}</tbody>
          </table>
        </div>
        <p class="attach-note">"No issues found" means none of these checks triggered. It is not a guarantee that a file is safe, because new or heavily disguised malware can pass static checks.</p>
      </div>
    `;
  }

  // ─── 4. Email Inspector ───
  btnTestPhishEmail.addEventListener('click', () => {
    emailSender.value = 'security-update@paypal-auth-center.xyz';
    emailClaimedOrg.value = 'PayPal';
    emailSubject.value = 'URGENT: Suspicious activity detected on your PayPal account!';
    emailBody.value = `Dear Customer,

We detected unauthorized sign-in attempts to your account. Your access has been restricted immediately.
You must verify your billing credentials within 24 hours or your account will be permanently suspended.

Click here to verify now: http://paypal-resolution-center.xyz/update-account?session=89324

Please provide your login password and credit card details to confirm ownership.
Thank you,
PayPal Security Department`;
    setAttachmentReports([]);
  });

  btnScanEmail.addEventListener('click', async () => {
    const payload = {
      sender: emailSender.value.trim(),
      claimed_org: emailClaimedOrg.value.trim(),
      subject: emailSubject.value.trim(),
      body: emailBody.value.trim(),
      attachment_reports: attachmentReports
    };

    if (!payload.body && !payload.subject) {
      alert('Please enter an email subject or body.');
      return;
    }

    try {
      const resp = await fetch('/api/analyze-email', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });
      const data = await resp.json();
      renderEmailAnalysis(data);
    } catch (e) {
      alert('Error analyzing email: ' + e.message);
    }
  });

  // ─── 4b. Gmail Inbox Picker (IMAP + App Password) ───
  const gmailAddress = document.getElementById('gmail-address');
  const gmailPassword = document.getElementById('gmail-app-password');
  const gmailFolder = document.getElementById('gmail-folder');
  const btnGmailConnect = document.getElementById('btn-gmail-connect');
  const gmailStatus = document.getElementById('gmail-status');
  const gmailList = document.getElementById('gmail-list');

  function escapeHtml(s) {
    return String(s == null ? '' : s).replace(/[&<>"']/g, c => ({
      '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
    }[c]));
  }

  function setGmailStatus(msg, isError) {
    gmailStatus.textContent = msg;
    gmailStatus.className = 'gmail-status' + (isError ? ' error' : '');
  }

  btnGmailConnect.addEventListener('click', async () => {
    setGmailStatus('Connecting to Gmail...', false);
    gmailList.classList.add('hidden');
    btnGmailConnect.disabled = true;
    try {
      const resp = await fetch('/api/gmail/messages', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          gmail_address: gmailAddress.value.trim(),
          app_password: gmailPassword.value,
          folder: gmailFolder.value,
          limit: 12
        })
      });
      const data = await resp.json();
      if (!resp.ok) throw new Error(data.detail || 'Could not load emails');

      const msgs = data.messages || [];
      if (!msgs.length) {
        setGmailStatus('No emails found in this folder.', false);
        return;
      }
      setGmailStatus(`Loaded ${msgs.length} recent emails. Click "Scan" on one to analyze it.`, false);
      gmailList.innerHTML = msgs.map((m, i) => `
        <div class="gmail-item">
          <div class="gmail-item-main">
            <div class="gmail-item-top">
              <span class="gmail-item-sender">${escapeHtml(m.sender_name)} &lt;${escapeHtml(m.sender_email)}&gt;</span>
              <span>${escapeHtml(m.date)}</span>
            </div>
            <div class="gmail-item-subject">${escapeHtml(m.subject)}${attachmentLabel(m)}</div>
            <div class="gmail-item-snippet">${escapeHtml(m.snippet)}</div>
          </div>
          <button class="btn-primary gmail-scan-btn" data-idx="${i}">Scan</button>
        </div>
      `).join('');
      gmailList.classList.remove('hidden');

      gmailList.querySelectorAll('.gmail-scan-btn').forEach(btn => {
        btn.addEventListener('click', () => {
          const m = msgs[Number(btn.dataset.idx)];
          emailSender.value = m.sender_email;
          emailClaimedOrg.value = m.claimed_org || '';
          emailSubject.value = m.subject;
          emailBody.value = m.body;
          setAttachmentReports(m.attachment_reports || []);
          btnScanEmail.click();
        });
      });
    } catch (e) {
      setGmailStatus(e.message, true);
    } finally {
      btnGmailConnect.disabled = false;
    }
  });

  function renderEmailAnalysis(data) {
    emailResult.classList.remove('hidden');
    emailResult.className = 'email-analysis-dashboard';

    const isSusp = data.is_suspicious;
    const score = Number(data.risk_score || 0);
    const feats = data.features || {};
    const breakdown = data.breakdown || [];
    const mc = data.model_comparison || (feats && feats.model_comparison) || {};
    const pa = mc.proposed_ahmfa || {};

    const FRIENDLY_NAMES = {
      sender_domain_mismatch: 'Sender Identity & Domain',
      cred_request_score: 'Sensitive Info Requests',
      html_form_present: 'Suspicious Links & Forms',
      urgency_score: 'Urgent or Pressuring Tone',
      poor_grammar_score: 'Generic Greetings & Spam Phrases',
      num_links: 'External Link Risk',
      attachment_risk: 'Attachment Risk'
    };

    const SEGMENT_COLORS = {
      sender_domain_mismatch: '#B91C1C',
      cred_request_score: '#0F1E36',
      html_form_present: '#1463F3',
      urgency_score: '#D97706',
      poor_grammar_score: '#475569',
      num_links: '#0D9488',
      attachment_risk: '#7C2D12'
    };

    // 1. Circular SVG Donut Gauge calculation
    const radius = 38;
    const circumference = 2 * Math.PI * radius;
    const clampedScore = Math.min(Math.max(score, 0), 100);
    const dashOffset = circumference - (clampedScore / 100) * circumference;
    const gaugeColor = score >= 50 ? '#B91C1C' : (score >= 30 ? '#B45309' : '#15803D');

    const verdictIconSvg = isSusp
      ? '<svg viewBox="0 0 24 24"><path d="M18 6L6 18M6 6l12 12"/></svg>'
      : '<svg viewBox="0 0 24 24"><path d="M20 6L9 17l-5-5"/></svg>';

    const summaryText = isSusp
      ? 'This email shows clear warning signs of phishing (such as a mismatched sender address, pressure tactics, or requests for private information). Do not click any links or reply.'
      : 'This email passed our core security checks and does not show common phishing red flags.';

    // 2. Category Bar Chart HTML (Graph 1)
    const categoryBarsHtml = breakdown.map(b => {
      const maxPts = Math.round((b.weight || 0) * 100);
      const earnedPts = Number(b.contribution || 0);
      const pctOfCategory = Math.min(100, Math.round((b.strength || 0) * 100));

      let statusClass = 'safe';
      let statusLabel = 'PASSED';
      if (pctOfCategory >= 60) {
        statusClass = 'danger';
        statusLabel = 'HIGH RISK';
      } else if (pctOfCategory > 0) {
        statusClass = 'warning';
        statusLabel = 'ELEVATED';
      }

      const name = FRIENDLY_NAMES[b.feature] || b.label || b.feature;

      return `
        <div class="email-bar-item ${statusClass}">
          <div class="email-bar-header">
            <span class="email-bar-title">${name}</span>
            <div class="email-bar-meta">
              <span class="email-status-text ${statusClass}">&#9632; ${statusLabel}</span>
              <span class="email-bar-pts">+${earnedPts.toFixed(1)} <small>/ ${maxPts} pts</small></span>
            </div>
          </div>
          <div class="email-bar-track">
            <div class="email-bar-fill ${statusClass}" style="width: ${Math.max(pctOfCategory, pctOfCategory > 0 ? 5 : 0)}%;"></div>
          </div>
          <p class="email-bar-reason">${b.reason || ''}</p>
        </div>
      `;
    }).join('');

    // 2b. Live Sender Verification Readout (Disify MX/Disposable API + WHOIS)
    const si = feats.sender_intel || {};
    let senderIntelHtml = '';
    if (si && si.domain) {
      const mxStatus = si.has_mx_records === true
        ? '<strong style="color: var(--safe);">&#9632; Active Mail Server Verified (MX OK)</strong>'
        : '<strong style="color: var(--danger);">&#9632; No Mail Server Found (MX Failed)</strong>';
      const dispStatus = si.is_disposable
        ? '<strong style="color: var(--danger);">&#9632; Flagged as Disposable / Burner Email</strong>'
        : '<strong style="color: var(--safe);">&#9632; Standard Non-Disposable Domain</strong>';
      const domainStatusColor = (si.risk_severity || 0) >= 0.7 ? 'var(--danger)' : 'var(--text-primary)';

      senderIntelHtml = `
        <div class="page-scan-details" style="margin-top: 24px; padding-top: 20px; border-top: 1px solid var(--border);">
          <h4 style="font-size: 14px; font-weight: 600; margin-bottom: 12px; color: var(--text-primary);">Live Sender Domain &amp; Mail Server Verification</h4>
          <div class="page-signals">
            <div class="page-signal-row"><span>Sender Domain</span><strong>${si.domain}</strong></div>
            <div class="page-signal-row"><span>Mail Server (Disify MX)</span>${mxStatus}</div>
            <div class="page-signal-row"><span>Burner / Temp-Mail Check</span>${dispStatus}</div>
            <div class="page-signal-row"><span>WHOIS Domain Status</span><strong style="color: ${domainStatusColor};">${si.domain_status || 'Unknown'}</strong></div>
            <div class="page-signal-row"><span>Domain Registrar</span><strong>${si.registrar || 'Unregistered / Hidden'}</strong></div>
          </div>
        </div>
      `;
    }

    // 3. Stacked Score Distribution Bar & Simple Calculation Breakdown (Graph 2)
    const totalEarnedPts = breakdown.reduce((sum, b) => sum + (b.contribution || 0), 0);
    const synergyPts = Number(pa.synergy_bonus || 0);
    const ruleScore = Number(pa.S_H_star !== undefined ? pa.S_H_star : Math.min(100, totalEarnedPts));
    const wordDensityScore = Number(pa.P_ML !== undefined ? pa.P_ML : 28);
    const ruleWeightPct = Math.round((pa.beta_adaptive !== undefined ? pa.beta_adaptive : 0.6) * 100);
    const densityWeightPct = 100 - ruleWeightPct;

    const totalForStack = Math.max(totalEarnedPts + synergyPts, 1);
    const stackedSegmentsHtml = breakdown
      .filter(b => b.contribution > 0)
      .map(b => {
        const widthPct = Math.max(4, (b.contribution / totalForStack) * 100);
        const color = SEGMENT_COLORS[b.feature] || '#1463F3';
        const name = FRIENDLY_NAMES[b.feature] || b.label;
        return `<div class="stack-segment" style="width: ${widthPct}%; background: ${color};" title="${name}: +${b.contribution.toFixed(1)} pts"></div>`;
      }).join('');

    const legendHtml = breakdown
      .filter(b => b.contribution > 0)
      .map(b => {
        const color = SEGMENT_COLORS[b.feature] || '#1463F3';
        const name = FRIENDLY_NAMES[b.feature] || b.label;
        return `
          <span class="stack-legend-item">
            <span class="stack-dot" style="background: ${color};"></span>
            ${name} (<strong>+${b.contribution.toFixed(1)}</strong>)
          </span>
        `;
      }).join('');

    const totalFlaggedWords = (feats.urgency_score || 0) + (feats.cred_request_score || 0) + (feats.poor_grammar_score || 0);
    const totalWords = feats.word_count || 1;

    // 4. Key Takeaways / Red Flags for the User
    const reasons = data.reasons || [];
    const takeawaysHtml = reasons.length > 0
      ? reasons.map(r => {
          const isCrit = r.badge === '🔴';
          return `
            <div class="reason-item ${isCrit ? 'critical' : 'warning'}">
              <div class="reason-left">
                <span class="reason-dot"></span>
                <div>
                  <strong style="display: block; font-size: 13px; color: var(--text-primary);">${r.rule}</strong>
                  <span style="font-size: 12.5px; color: var(--text-secondary);">${r.detail}</span>
                </div>
              </div>
            </div>
          `;
        }).join('')
      : `
        <div class="reason-item safe">
          <div class="reason-left">
            <span class="reason-dot"></span>
            <span>No suspicious indicators were triggered in the sender address, subject, or message body.</span>
          </div>
        </div>
      `;

    emailResult.innerHTML = `
      <!-- Top Verdict Banner with SVG Gauge -->
      <div class="verdict-banner ${isSusp ? 'danger' : 'safe'}" style="margin-top: 24px;">
        <div class="verdict-left">
          <div class="verdict-indicator">${verdictIconSvg}</div>
          <div>
            <div class="verdict-tag">${isSusp ? 'PHISHING DETECTED' : 'SAFE EMAIL'}</div>
            <h2 class="verdict-title">${isSusp ? 'High-Risk Phishing Email' : 'Low Threat — Looks Safe'}</h2>
            <p class="email-verdict-summary">${summaryText}</p>
          </div>
        </div>
        <div class="email-gauge-box">
          <svg class="email-gauge-svg" width="96" height="96" viewBox="0 0 96 96">
            <circle cx="48" cy="48" r="${radius}" fill="none" stroke="rgba(0,0,0,0.08)" stroke-width="8" />
            <circle cx="48" cy="48" r="${radius}" fill="none" stroke="${gaugeColor}" stroke-width="8"
              stroke-linecap="round"
              stroke-dasharray="${circumference.toFixed(1)}"
              stroke-dashoffset="${dashOffset.toFixed(1)}"
              transform="rotate(-90 48 48)" />
          </svg>
          <div class="email-gauge-text">
            <span class="email-gauge-num" style="color: ${gaugeColor};">${Math.round(score)}</span>
            <span class="email-gauge-sub">/ 100</span>
          </div>
          <span class="email-gauge-caption">Risk Score</span>
        </div>
      </div>

      ${buildAttachmentCard(data.attachments)}
      <!-- Two-Column Visual Breakdown -->
      <div class="results-grid">
        <!-- Left Card: Visual Bar Graph of the 6 Checks -->
        <div class="card">
          <div class="card-header">
            <h3>Risk Breakdown by Category</h3>
            <span class="chip-badge">${breakdown.length} Security Checks</span>
          </div>
          <p class="section-desc">Each bar shows how many risk points were triggered in that category out of its maximum weight.</p>
          <div class="email-bars-container">
            ${categoryBarsHtml}
          </div>
          ${senderIntelHtml}
        </div>

        <!-- Right Card: How It Was Calculated + What You Should Know -->
        <div class="card">
          <div class="card-header">
            <h3>How the Score Was Calculated</h3>
            <span class="chip-badge">Plain-English Summary</span>
          </div>
          <p class="section-desc">Your final risk score combines our ${breakdown.length} security rule checks with an analysis of the email's language density.</p>

          ${totalEarnedPts > 0 ? `
            <div class="stack-chart-box">
              <div class="stack-chart-label">Share of Triggered Risk Points</div>
              <div class="stack-bar-track">${stackedSegmentsHtml}</div>
              <div class="stack-legend">${legendHtml}</div>
            </div>
          ` : ''}

          <!-- 3 Simple Calculation Steps Visual -->
          <div class="calc-steps-box">
            <div class="calc-step">
              <div class="calc-step-left">
                <span class="calc-step-num">1</span>
                <div>
                  <strong>${breakdown.length} Security Rule Checks</strong>
                  <p>Points from the ${breakdown.length} checks on the left (${totalEarnedPts.toFixed(1)} pts)${synergyPts > 0 ? ` + ${synergyPts.toFixed(1)} bonus pts because multiple red flags appeared together` : ''}, scaled smoothly to 100.</p>
                </div>
              </div>
              <span class="calc-step-val">${ruleScore.toFixed(1)} <small>/ 100</small></span>
            </div>

            <div class="calc-step">
              <div class="calc-step-left">
                <span class="calc-step-num">2</span>
                <div>
                  <strong>Suspicious Word Density</strong>
                  <p>Found <strong>${totalFlaggedWords}</strong> pressure/login phrase(s) across <strong>${totalWords}</strong> total words in the email.</p>
                </div>
              </div>
              <span class="calc-step-val">${wordDensityScore.toFixed(1)} <small>/ 100</small></span>
            </div>

            <div class="calc-step calc-step-final">
              <div class="calc-step-left">
                <span class="calc-step-num final">=</span>
                <div>
                  <strong>Final Combined Risk Score</strong>
                  <p>Blends <strong>${ruleWeightPct}%</strong> Rule Checks + <strong>${densityWeightPct}%</strong> Word Density. Scores <strong>50+</strong> are flagged as phishing.</p>
                </div>
              </div>
              <span class="calc-step-val" style="color: ${gaugeColor};">${score.toFixed(1)} <small>/ 100</small></span>
            </div>
          </div>

          <!-- Key Takeaways -->
          <div style="margin-top: 22px; padding-top: 18px; border-top: 1px solid var(--border);">
            <h4 style="font-size: 14px; font-weight: 600; margin-bottom: 12px; color: var(--text-primary);">What You Should Know</h4>
            <div class="reasons-list">
              ${takeawaysHtml}
            </div>
          </div>
        </div>
      </div>
    `;

    emailResult.scrollIntoView({ behavior: 'smooth', block: 'start' });
  }
});
