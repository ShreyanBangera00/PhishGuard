"""
Attachment Scanner for PhishGuard.

Static analysis only: files are held in memory, never executed and never written
to disk. Each attachment gets a risk value in [0, 1], a list of plain-English
findings, any URLs found inside it, and (optionally) a VirusTotal hash lookup.

Checks performed
  * Risky file types and disguised names (double extensions, RTL-override tricks)
  * Real file type from magic bytes vs. the claimed extension
  * ZIP contents (executables inside, password-protected, zip-bomb size guard)
  * Office macros / remote template injection (oletools if installed, else heuristics)
  * PDF active content (JavaScript, auto-run and launch actions, embedded files)
  * HTML/SVG attachments (password fields, form posts, obfuscated script)
  * SHA-256 reputation via VirusTotal (hash only; the file itself is never uploaded)
"""

import hashlib
import io
import logging
import os
import re
import zipfile

import requests

logger = logging.getLogger(__name__)

MAX_ATTACHMENT_BYTES = 10 * 1024 * 1024      # files above this are not scanned
MAX_ATTACHMENTS = 5                          # per email
MAX_ARCHIVE_ENTRIES = 200
MAX_ARCHIVE_DECLARED_BYTES = 200 * 1024 * 1024
MAX_SMALL_READ = 256 * 1024                  # cap when reading a member of an archive
MAX_URLS = 20
VT_MALICIOUS_THRESHOLD = 3                   # engines needed to call a file confirmed malicious

SEVERITY_POINTS = {'critical': 0.90, 'high': 0.60, 'medium': 0.35, 'low': 0.15, 'info': 0.0}

EXEC_EXT_CRITICAL = {
    '.exe', '.scr', '.com', '.pif', '.bat', '.cmd', '.msi', '.dll', '.hta', '.vbs',
    '.vbe', '.jse', '.wsf', '.wsh', '.ps1', '.cpl', '.reg', '.jar', '.apk',
}
EXEC_EXT_HIGH = {'.js', '.lnk', '.iso', '.img', '.vhd', '.chm', '.msc'}
DANGEROUS_EXT = EXEC_EXT_CRITICAL | EXEC_EXT_HIGH

ARCHIVE_EXT = {'.zip', '.rar', '.7z', '.gz', '.tar', '.cab'}
OOXML_EXT = {'.docx', '.xlsx', '.pptx', '.docm', '.xlsm', '.pptm', '.dotm', '.xlsb', '.xlam'}
OLE_EXT = {'.doc', '.xls', '.ppt', '.dot', '.xlt', '.pps'}
MACRO_EXT = {'.docm', '.xlsm', '.pptm', '.dotm', '.xlsb', '.xlam'}
HTML_EXT = {'.html', '.htm', '.shtml', '.xhtml', '.svg'}

MAGIC = [
    (b'MZ', 'exe'),
    (b'\x7fELF', 'elf'),
    (b'%PDF', 'pdf'),
    (b'PK\x03\x04', 'zip'),
    (b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1', 'ole'),
    (b'\x89PNG', 'png'),
    (b'\xff\xd8\xff', 'jpg'),
    (b'GIF8', 'gif'),
    (b'Rar!', 'rar'),
    (b'7z\xbc\xaf\x27\x1c', '7z'),
    (b'\x1f\x8b', 'gz'),
    (b'{\\rtf', 'rtf'),
]

# Which detected kinds are acceptable for a claimed extension.
EXPECTED_KINDS = {
    '.pdf': {'pdf'}, '.png': {'png'}, '.jpg': {'jpg'}, '.jpeg': {'jpg'}, '.gif': {'gif'},
    '.zip': {'zip'}, '.rar': {'rar'}, '.7z': {'7z'}, '.gz': {'gz'},
    '.docx': {'zip'}, '.xlsx': {'zip'}, '.pptx': {'zip'}, '.docm': {'zip'},
    '.xlsm': {'zip'}, '.pptm': {'zip'},
    '.doc': {'ole', 'rtf', 'zip'}, '.xls': {'ole', 'zip'}, '.ppt': {'ole', 'zip'},
    '.rtf': {'rtf'}, '.exe': {'exe'}, '.dll': {'exe'},
}
EXECUTABLE_KINDS = {'exe', 'elf'}

URL_RE = re.compile(r'https?://[^\s<>"\'\)\]\\]+', re.IGNORECASE)

_vt_cache: dict = {}


def _ext(name: str) -> str:
    return os.path.splitext(name.lower().strip())[1]


def detect_type(data: bytes):
    """Best-effort real file type from magic bytes. Returns None if unknown."""
    head = data[:16]
    for sig, kind in MAGIC:
        if head.startswith(sig):
            return kind
    snippet = data[:2048].lstrip().lower()
    if snippet.startswith((b'<!doctype html', b'<html', b'<head', b'<body', b'<form', b'<script', b'<svg')):
        return 'html'
    return None


def _extract_urls(text: str) -> list:
    seen = []
    for m in URL_RE.findall(text or ''):
        u = m.rstrip('.,;')
        if u not in seen:
            seen.append(u)
        if len(seen) >= MAX_URLS:
            break
    return seen


def _add(findings: list, severity: str, text: str):
    findings.append({'severity': severity, 'text': text})


def _check_filename(filename: str, findings: list):
    name = filename or ''
    lower = name.lower().strip()
    ext = _ext(lower)

    if '\u202e' in name:
        _add(findings, 'critical', 'File name contains a right-to-left override character, a trick that makes the real extension look different')

    parts = lower.split('.')
    if len(parts) >= 3 and ext in DANGEROUS_EXT:
        _add(findings, 'critical', f"Double extension disguises an executable ('{name}')")
    elif ext in EXEC_EXT_CRITICAL:
        _add(findings, 'critical', f"Executable or script file type ({ext})")
    elif ext in EXEC_EXT_HIGH:
        _add(findings, 'high', f"High-risk file type ({ext}) often used to deliver malware")
    elif ext in MACRO_EXT:
        _add(findings, 'medium', f"Macro-enabled Office file type ({ext})")

    if re.search(r'\s{3,}\.\w+$', name):
        _add(findings, 'medium', 'File name is padded with spaces before the extension to hide it')


def _check_magic(filename: str, kind, findings: list):
    ext = _ext(filename)
    if kind in EXECUTABLE_KINDS and ext not in EXEC_EXT_CRITICAL:
        _add(findings, 'critical', f"File is really a Windows/Linux executable but is named '{ext or 'no extension'}'")
        return
    expected = EXPECTED_KINDS.get(ext)
    if expected and kind and kind not in expected:
        _add(findings, 'medium', f"File content looks like '{kind}' but the extension says '{ext}'")


def _macro_scan(filename: str, data: bytes, findings: list):
    """Detect VBA macros. Uses oletools when installed, otherwise structural heuristics."""
    try:
        from oletools.olevba import VBA_Parser
        parser = VBA_Parser(filename or 'file', data=data)
        try:
            if not parser.detect_vba_macros():
                return
            autoexec, suspicious = [], []
            for kind, keyword, _desc in parser.analyze_macros():
                if kind == 'AutoExec':
                    autoexec.append(keyword)
                elif kind == 'Suspicious':
                    suspicious.append(keyword)
            if autoexec:
                _add(findings, 'high', f"Contains VBA macros that run automatically ({', '.join(sorted(set(autoexec))[:4])})")
            else:
                _add(findings, 'medium', 'Contains VBA macros')
            if suspicious:
                _add(findings, 'high', f"Macro code uses suspicious functions ({', '.join(sorted(set(suspicious))[:5])})")
        finally:
            parser.close()
        return
    except ImportError:
        pass
    except Exception as e:
        logger.warning(f"oletools failed on {filename}: {e}")

    # Heuristic fallback
    if b'_\x00V\x00B\x00A\x00_\x00P\x00R\x00O\x00J\x00E\x00C\x00T\x00' in data or b'vbaProject.bin' in data:
        _add(findings, 'medium', 'Contains VBA macros (install oletools for deeper macro analysis)')


def _inspect_zip(filename: str, data: bytes, findings: list, urls: list):
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile:
        _add(findings, 'medium', 'Archive is corrupt or not a valid ZIP file')
        return

    infos = zf.infolist()
    if len(infos) > MAX_ARCHIVE_ENTRIES:
        _add(findings, 'medium', f"Archive holds an unusually large number of files ({len(infos)})")
        infos = infos[:MAX_ARCHIVE_ENTRIES]

    declared = sum(i.file_size for i in infos)
    if declared > MAX_ARCHIVE_DECLARED_BYTES or (len(data) > 0 and declared / max(len(data), 1) > 1000):
        _add(findings, 'high', 'Archive expands to an extreme size, which can indicate a zip bomb')

    names = [i.filename for i in infos]
    ext = _ext(filename)
    is_office = '[Content_Types].xml' in names

    if any(i.flag_bits & 0x1 for i in infos):
        _add(findings, 'high', 'Archive is password-protected, so its contents cannot be inspected (a common way to slip malware past scanners)')

    if is_office:
        if any(n.lower().endswith('vbaproject.bin') for n in names):
            _macro_scan(filename, data, findings)
            if not any('macro' in f['text'].lower() for f in findings):
                _add(findings, 'medium', 'Contains VBA macros')
        if any('/embeddings/' in n.lower() for n in names):
            _add(findings, 'medium', 'Contains embedded objects')
        # Remote template injection
        for i in infos:
            if i.filename.lower().endswith('.rels') and i.file_size <= MAX_SMALL_READ:
                try:
                    rel = zf.read(i).decode('utf-8', errors='replace')
                except Exception:
                    continue
                for m in re.finditer(r'Target="(https?://[^"]+)"[^>]*TargetMode="External"', rel, re.IGNORECASE):
                    target = m.group(1)
                    if 'hyperlink' in rel[max(0, m.start() - 200):m.start()].lower():
                        continue
                    _add(findings, 'high', f"Document loads remote content from {target}")
                    if target not in urls:
                        urls.append(target)
        return

    # Generic archive
    for n in names:
        n_ext = _ext(n)
        if n_ext in EXEC_EXT_CRITICAL:
            _add(findings, 'critical', f"Archive contains an executable ('{n}')")
        elif n_ext in EXEC_EXT_HIGH:
            _add(findings, 'high', f"Archive contains a high-risk file ('{n}')")
        elif len(n.lower().split('.')) >= 3 and n_ext in DANGEROUS_EXT:
            _add(findings, 'critical', f"Archive contains a file with a disguised double extension ('{n}')")
        elif n_ext in ARCHIVE_EXT:
            _add(findings, 'low', f"Archive contains another archive ('{n}')")


def _inspect_pdf(data: bytes, findings: list, urls: list):
    low = data.lower()
    if b'/launch' in low:
        _add(findings, 'critical', 'PDF can launch external programs (/Launch action)')
    if b'/javascript' in low or re.search(rb'/js\b', low):
        _add(findings, 'high', 'PDF contains embedded JavaScript')
    if b'/openaction' in low or re.search(rb'/aa\b', low):
        _add(findings, 'medium', 'PDF runs an action automatically when opened')
    if b'/embeddedfile' in low:
        _add(findings, 'medium', 'PDF contains an embedded file')
    if b'/submitform' in low:
        _add(findings, 'medium', 'PDF contains a form that submits data to a server')

    try:
        import pypdf
        reader = pypdf.PdfReader(io.BytesIO(data))
        if reader.is_encrypted:
            _add(findings, 'medium', 'PDF is encrypted, so its contents cannot be fully inspected')
            return
        for page in reader.pages[:10]:
            for annot in (page.get('/Annots') or []):
                try:
                    action = annot.get_object().get('/A')
                    uri = action.get_object().get('/URI') if action else None
                except Exception:
                    uri = None
                if uri and str(uri) not in urls and len(urls) < MAX_URLS:
                    urls.append(str(uri))
    except Exception:
        pass


def _inspect_html(filename: str, data: bytes, findings: list, urls: list):
    text = data[:MAX_SMALL_READ * 4].decode('utf-8', errors='replace')
    low = text.lower()
    ext = _ext(filename)

    if ext in {'.html', '.htm', '.shtml', '.xhtml'}:
        _add(findings, 'low', 'HTML attachment (often used to host a fake login page outside any website)')
    if re.search(r'type\s*=\s*["\']?password', low):
        _add(findings, 'high', 'Contains a password entry field, typical of a fake login page')
    if re.search(r'<form[^>]+action\s*=\s*["\']?https?://', low):
        _add(findings, 'medium', 'Form posts the entered data to an external website')
    if any(tok in low for tok in ('eval(', 'atob(', 'unescape(', 'fromcharcode', 'document.write(')):
        _add(findings, 'medium', 'Uses obfuscated or dynamically generated script')
    if ext == '.svg' and '<script' in low:
        _add(findings, 'high', 'SVG image contains a script')
    for u in _extract_urls(text):
        if u not in urls and len(urls) < MAX_URLS:
            urls.append(u)


def vt_lookup(sha256: str, api_key: str) -> dict:
    """Hash-only VirusTotal v3 lookup. Never uploads the file."""
    if not api_key:
        return {'checked': False, 'status': 'not configured'}
    if sha256 in _vt_cache:
        return _vt_cache[sha256]
    result = {'checked': True, 'status': 'error', 'malicious': 0, 'suspicious': 0, 'total': 0}
    try:
        resp = requests.get(
            f'https://www.virustotal.com/api/v3/files/{sha256}',
            headers={'x-apikey': api_key},
            timeout=6,
        )
        if resp.status_code == 200:
            stats = resp.json()['data']['attributes']['last_analysis_stats']
            result.update(
                status='found',
                malicious=int(stats.get('malicious', 0)),
                suspicious=int(stats.get('suspicious', 0)),
                total=int(sum(stats.values())),
            )
        elif resp.status_code == 404:
            result['status'] = 'not found'
        elif resp.status_code == 429:
            result['status'] = 'rate limited'
        else:
            result['status'] = f'error {resp.status_code}'
    except Exception as e:
        logger.warning(f'VirusTotal lookup failed: {e}')
        result['status'] = 'unavailable'
    if result['status'] in ('found', 'not found'):
        _vt_cache[sha256] = result
    return result


def _combine(findings: list) -> float:
    """Noisy-OR so several moderate findings add up but never exceed 1.0."""
    keep = 1.0
    for f in findings:
        keep *= 1.0 - SEVERITY_POINTS.get(f['severity'], 0.0)
    return round(1.0 - keep, 3)


def _verdict(report: dict) -> str:
    if report.get('skipped'):
        return 'Not scanned'
    if report.get('confirmed_malicious'):
        return 'Malicious'
    risk = report['risk']
    if risk >= 0.7:
        return 'High risk'
    if risk >= 0.35:
        return 'Suspicious'
    if risk > 0:
        return 'Low risk'
    return 'No issues found'


def scan_attachment(filename: str, data: bytes, content_type: str = '', vt_api_key: str = None) -> dict:
    """Scan one attachment held in memory and return a JSON-serialisable report."""
    filename = filename or 'unnamed'
    findings: list = []
    urls: list = []
    report = {
        'filename': filename,
        'size': len(data),
        'content_type': content_type,
        'detected_type': None,
        'sha256': hashlib.sha256(data).hexdigest(),
        'risk': 0.0,
        'verdict': '',
        'findings': findings,
        'urls': urls,
        'vt': {'checked': False, 'status': 'not configured'},
        'confirmed_malicious': False,
        'skipped': None,
    }

    if len(data) == 0:
        report['skipped'] = 'File is empty'
        report['verdict'] = _verdict(report)
        return report
    if len(data) > MAX_ATTACHMENT_BYTES:
        report['skipped'] = f'File is larger than {MAX_ATTACHMENT_BYTES // (1024 * 1024)} MB and was not scanned'
        report['verdict'] = _verdict(report)
        return report

    kind = detect_type(data)
    report['detected_type'] = kind
    ext = _ext(filename)

    _check_filename(filename, findings)
    _check_magic(filename, kind, findings)

    try:
        if kind == 'zip':
            _inspect_zip(filename, data, findings, urls)
        elif kind == 'ole' or ext in OLE_EXT:
            _macro_scan(filename, data, findings)
        if kind == 'pdf' or ext == '.pdf':
            _inspect_pdf(data, findings, urls)
        if kind == 'html' or ext in HTML_EXT:
            _inspect_html(filename, data, findings, urls)
        if kind is None and ext in {'.txt', '.csv', '.eml', '.url'}:
            for u in _extract_urls(data[:MAX_SMALL_READ].decode('utf-8', errors='replace')):
                if u not in urls and len(urls) < MAX_URLS:
                    urls.append(u)
    except Exception as e:
        logger.warning(f'Static analysis error on {filename}: {e}')
        _add(findings, 'info', 'Some checks could not be completed for this file')

    # Hash reputation
    api_key = vt_api_key if vt_api_key is not None else os.environ.get('VIRUSTOTAL_API_KEY', '')
    vt = vt_lookup(report['sha256'], api_key)
    report['vt'] = vt
    if vt.get('status') == 'found':
        if vt['malicious'] >= VT_MALICIOUS_THRESHOLD:
            report['confirmed_malicious'] = True
            _add(findings, 'critical', f"VirusTotal: {vt['malicious']} of {vt['total']} antivirus engines flag this file as malicious")
        elif vt['malicious'] > 0 or vt['suspicious'] > 0:
            _add(findings, 'medium', f"VirusTotal: {vt['malicious']} malicious and {vt['suspicious']} suspicious detections out of {vt['total']} engines")
    elif vt.get('status') == 'not found':
        _add(findings, 'info', 'VirusTotal has not seen this exact file before')

    report['risk'] = 1.0 if report['confirmed_malicious'] else _combine(findings)
    report['verdict'] = _verdict(report)
    return report


def summarize_reports(reports: list) -> dict:
    """Aggregate numbers used by the email scorer."""
    reports = [r for r in (reports or []) if isinstance(r, dict)]
    scanned = [r for r in reports if not r.get('skipped')]
    max_risk = max((float(r.get('risk', 0.0)) for r in scanned), default=0.0)
    return {
        'count': len(reports),
        'scanned': len(scanned),
        'max_risk': max(0.0, min(1.0, max_risk)),
        'confirmed_malicious': any(r.get('confirmed_malicious') for r in reports),
    }
