#!/usr/bin/env python3
"""
PySentinel Report Generator
Reads structured scan JSON outputs → produces a self-contained HTML report.

Usage (called by pysentinel.sh):
    python3 generate_report.py \
        --meta        /tmp/scan/meta.json      \
        --bandit      /tmp/scan/bandit.json    \
        --semgrep     /tmp/scan/semgrep.json   \
        --gitleaks    /tmp/scan/gitleaks.json  \
        --secrets     /tmp/scan/secrets.json   \
        --pip-audit   /tmp/scan/pip_audit.json \
        --output      /reports/report.html
"""

import argparse
import html as html_lib
import json
import os
import sys
from datetime import datetime
from pathlib import Path


# ── Helpers ────────────────────────────────────────────────────────────────────

def read_json(path, default):
    """Safely read a JSON file; return default on any error."""
    try:
        p = Path(path)
        if not p.exists() or p.stat().st_size == 0:
            return default
        text = p.read_text(encoding='utf-8').strip()
        if not text or text == 'null':
            return default
        return json.loads(text)
    except Exception:
        return default


def esc(s):
    """HTML-escape a string."""
    return html_lib.escape(str(s or ''), quote=True)


def sev_class(s):
    """Normalise severity string to CSS class."""
    s = str(s).upper().strip()
    if s in ('CRITICAL',):        return 'CRITICAL'
    if s in ('HIGH', 'ERROR'):    return 'HIGH'
    if s in ('MEDIUM', 'WARNING','WARN'): return 'MEDIUM'
    if s in ('LOW', 'INFO'):      return 'LOW'
    return 'LOW'


def sev_badge(s):
    cls = sev_class(s)
    label = cls.capitalize()
    return f'<span class="sev {cls}">{label}</span>'


def status_dot(s):
    """Return a coloured status dot span."""
    c = {'pass': 'pass', 'warn': 'warn', 'fail': 'fail', 'skip': 'skip'}.get(s, 'skip')
    return f'<span class="status-dot {c}"></span>'


def count_badge(n, label=None):
    cls = 'has-issues' if n > 0 else 'no-issues'
    txt = f'{n} issue{"s" if n != 1 else ""}' if label is None else label
    return f'<span class="count-badge {cls}">{txt}</span>'


def gh_link(target, filepath, line=None):
    """Build GitHub file link if target is a GitHub URL."""
    if not target or 'github.com' not in str(target):
        return None
    base = target.rstrip('/').rstrip('.git')
    url  = f"{base}/blob/HEAD/{filepath}"
    if line:
        url += f"#L{line}"
    return url


def file_cell(target, filepath, line=None):
    """Render a file:line table cell, linked to GitHub if possible."""
    display = f"{filepath}:{line}" if line else filepath
    link    = gh_link(target, filepath, line)
    if link:
        return f'<td class="file-cell"><a href="{esc(link)}" target="_blank">{esc(display)}</a></td>'
    return f'<td class="file-cell">{esc(display)}</td>'


def empty_state(msg="No findings"):
    return f'''<tr class="no-results-row">
      <td colspan="99">
        <div class="empty-state"><span class="icon">✓</span>{esc(msg)}</div>
      </td></tr>'''


def verdict_css_class(v):
    v = str(v).upper()
    if 'AVOID' in v or 'CRITICAL' in v: return 'avoid'
    if 'CAUTION' in v:                  return 'caution'
    return 'safe'


# ── Section builders ──────────────────────────────────────────────────────────

def section_html(step_num, step_id, title, status, count_label, body_html,
                 has_findings=False, skip_msg=None):
    """Wrap content in a collapsible section card."""
    dot   = status_dot(status)
    badge = count_badge(0, count_label) if not has_findings \
            else f'<span class="count-badge has-issues">{count_label}</span>'

    if skip_msg:
        body = f'<div class="skip-notice">⏭ {esc(skip_msg)}</div>'
    else:
        body = body_html

    return f'''
<div class="section" id="section-{step_id}" data-has-findings="{'true' if has_findings else 'false'}">
  <div class="section-header">
    <div class="section-header-left">
      {dot}
      <span class="section-step">Step {step_num}</span>
      <span class="section-title">{esc(title)}</span>
    </div>
    <div class="section-right">
      {badge}
      <span class="chevron">▾</span>
    </div>
  </div>
  <div class="section-body">{body}</div>
</div>'''


# ── Bandit ────────────────────────────────────────────────────────────────────

def build_bandit(data, target):
    results  = data.get('results', [])
    metrics  = data.get('metrics', {}).get('_totals', {})
    h = int(metrics.get('SEVERITY.HIGH',   0))
    m = int(metrics.get('SEVERITY.MEDIUM', 0))
    l = int(metrics.get('SEVERITY.LOW',    0))
    total = len(results)

    rows = ''
    for r in sorted(results, key=lambda x: x.get('issue_severity',''), reverse=True):
        sev   = sev_badge(r.get('issue_severity', 'LOW'))
        conf  = esc(r.get('issue_confidence', '?'))
        tid   = esc(r.get('test_id', ''))
        msg   = esc(r.get('issue_text', '')[:140])
        fname = r.get('filename', '').replace(os.environ.get('SOURCE_DIR', ''), '').lstrip('/')
        line  = r.get('line_number')
        sev_c = sev_class(r.get('issue_severity', 'LOW'))
        rows += f'''<tr data-severity="{sev_c}">
          <td>{sev}</td>
          <td><code>{tid}</code></td>
          <td class="msg-cell">{msg}</td>
          {file_cell(target, fname, line)}
          <td><span class="sev INFO">{conf}</span></td>
        </tr>'''

    if not rows:
        rows = empty_state('Bandit: no issues found')

    label = f'{total} issue{"s" if total!=1 else ""}' if total else '✓ clean'
    status = 'warn' if total > 0 else 'pass'

    body = f'''
    <div class="info-grid" style="margin-bottom:1px;">
      <div class="info-cell"><div class="info-cell-label">Files scanned</div>
        <div class="info-cell-value">{int(metrics.get("loc",0))}</div></div>
      <div class="info-cell"><div class="info-cell-label">HIGH</div>
        <div class="info-cell-value" style="color:var(--sev-high)">{h}</div></div>
      <div class="info-cell"><div class="info-cell-label">MEDIUM</div>
        <div class="info-cell-value" style="color:var(--sev-medium)">{m}</div></div>
      <div class="info-cell"><div class="info-cell-label">LOW</div>
        <div class="info-cell-value" style="color:var(--sev-low)">{l}</div></div>
    </div>
    <div class="table-wrap"><table>
      <thead><tr><th>Severity</th><th>Test ID</th><th>Message</th><th>File : Line</th><th>Confidence</th></tr></thead>
      <tbody>{rows}</tbody>
    </table></div>'''

    return section_html(9, 'bandit', 'SAST — Bandit', status, label, body, has_findings=total>0)


# ── Semgrep ───────────────────────────────────────────────────────────────────

def build_semgrep(data, target):
    results = data.get('results', [])
    total   = len(results)

    rows = ''
    for r in results:
        extra = r.get('extra', {})
        sev   = sev_badge(extra.get('severity', 'INFO'))
        sev_c = sev_class(extra.get('severity', 'INFO'))
        rule  = esc(r.get('check_id','?').split('.')[-1][:40])
        msg   = esc(extra.get('message','')[:140])
        fname = r.get('path','').replace(os.environ.get('SOURCE_DIR',''),'').lstrip('/')
        line  = r.get('start',{}).get('line')
        rows += f'''<tr data-severity="{sev_c}">
          <td>{sev}</td>
          <td><code>{rule}</code></td>
          <td class="msg-cell">{msg}</td>
          {file_cell(target, fname, line)}
        </tr>'''

    if not rows:
        rows = empty_state('Semgrep: no findings')

    label  = f'{total} finding{"s" if total!=1 else ""}' if total else '✓ clean'
    status = 'warn' if total > 0 else 'pass'

    body = f'''<div class="table-wrap"><table>
      <thead><tr><th>Severity</th><th>Rule</th><th>Message</th><th>File : Line</th></tr></thead>
      <tbody>{rows}</tbody>
    </table></div>'''

    return section_html(10, 'semgrep', 'SAST — Semgrep', status, label, body, has_findings=total>0)


# ── Gitleaks ──────────────────────────────────────────────────────────────────

def build_gitleaks(data, target, available):
    if not available:
        return section_html(8, 'gitleaks', 'Git History — gitleaks', 'skip',
                            'skipped', '', skip_msg='gitleaks not installed. Install it and re-run for full git-history secret scanning.')

    leaks = data if isinstance(data, list) else []
    total = len(leaks)

    rows = ''
    for leak in leaks:
        rule   = esc(leak.get('RuleID','?'))
        desc   = esc(leak.get('Description','?')[:80])
        fname  = esc(leak.get('File','?'))
        commit = esc(str(leak.get('Commit','?'))[:8])
        author = esc(leak.get('Author','?'))
        date_  = esc(str(leak.get('Date','?'))[:10])
        line   = leak.get('StartLine')
        link   = gh_link(target, leak.get('File',''), line)
        file_display = f"{leak.get('File','')}:{line}" if line else leak.get('File','?')
        file_td = f'<td class="file-cell"><a href="{esc(link)}" target="_blank">{esc(file_display)}</a></td>' \
                  if link else f'<td class="file-cell">{esc(file_display)}</td>'
        rows += f'''<tr data-severity="CRITICAL">
          <td><span class="sev CRITICAL">Secret</span></td>
          <td><code>{rule}</code></td>
          <td class="msg-cell">{desc}</td>
          {file_td}
          <td><code>{commit}</code></td>
          <td>{author}</td>
          <td>{date_}</td>
        </tr>'''

    if not rows:
        rows = empty_state('gitleaks: no secrets found in git history ✓')

    label  = f'{total} leak{"s" if total!=1 else ""}' if total else '✓ clean history'
    status = 'fail' if total > 0 else 'pass'

    body = f'''<div class="table-wrap"><table>
      <thead><tr><th>Type</th><th>Rule</th><th>Description</th><th>File : Line</th><th>Commit</th><th>Author</th><th>Date</th></tr></thead>
      <tbody>{rows}</tbody>
    </table></div>'''

    return section_html(8, 'gitleaks', 'Git History Secrets — gitleaks', status, label, body, has_findings=total>0)


# ── detect-secrets ────────────────────────────────────────────────────────────

def build_secrets(data, target):
    results = data.get('results', {})
    items   = [(f, s) for f, slist in results.items() for s in slist]
    total   = len(items)

    rows = ''
    for fname, s in items:
        typ  = esc(s.get('type','?'))
        line = s.get('line_number')
        rows += f'''<tr data-severity="HIGH">
          <td><span class="sev HIGH">Secret</span></td>
          <td>{typ}</td>
          {file_cell(target, fname, line)}
        </tr>'''

    if not rows:
        rows = empty_state('detect-secrets: no hardcoded secrets found ✓')

    label  = f'{total} secret{"s" if total!=1 else ""}' if total else '✓ clean'
    status = 'fail' if total > 0 else 'pass'

    body = f'''<div class="table-wrap"><table>
      <thead><tr><th>Severity</th><th>Secret Type</th><th>File : Line</th></tr></thead>
      <tbody>{rows}</tbody>
    </table></div>'''

    return section_html(7, 'secrets', 'Hardcoded Secrets — detect-secrets', status, label, body, has_findings=total>0)


# ── pip-audit CVEs ────────────────────────────────────────────────────────────

def build_pip_audit(data):
    deps  = data.get('dependencies', [])
    vuln_deps = [d for d in deps if d.get('vulns')]
    total = sum(len(d['vulns']) for d in vuln_deps)

    rows = ''
    for d in vuln_deps:
        for v in d['vulns']:
            vid   = v.get('id','?')
            link  = f"https://osv.dev/vulnerability/{vid}" if vid.startswith('PYSEC') \
                    else f"https://nvd.nist.gov/vuln/detail/{vid}" if vid.startswith('CVE') \
                    else None
            vid_td = f'<a href="{esc(link)}" target="_blank"><code>{esc(vid)}</code></a>' if link \
                     else f'<code>{esc(vid)}</code>'
            desc   = esc(v.get('description','?')[:140])
            fixes  = ', '.join(v.get('fix_versions', [])) or 'No fix available'
            rows += f'''<tr data-severity="HIGH">
              <td><span class="sev HIGH">CVE</span></td>
              <td><code>{esc(d["name"])}</code></td>
              <td><code>{esc(d["version"])}</code></td>
              <td>{vid_td}</td>
              <td class="msg-cell">{desc}</td>
              <td><code>{esc(fixes)}</code></td>
            </tr>'''

    if not rows:
        rows = empty_state(f'pip-audit: no CVEs found across {len(deps)} dependencies ✓')

    label  = f'{total} CVE{"s" if total!=1 else ""}' if total else '✓ no CVEs'
    status = 'fail' if total > 0 else 'pass'

    body = f'''<div class="info-grid" style="margin-bottom:1px;">
      <div class="info-cell"><div class="info-cell-label">Dependencies scanned</div>
        <div class="info-cell-value">{len(deps)}</div></div>
      <div class="info-cell"><div class="info-cell-label">Vulnerable packages</div>
        <div class="info-cell-value" style="color:var(--sev-critical)">{len(vuln_deps)}</div></div>
      <div class="info-cell"><div class="info-cell-label">Total CVEs</div>
        <div class="info-cell-value" style="color:var(--sev-critical)">{total}</div></div>
    </div>
    <div class="table-wrap"><table>
      <thead><tr><th>Type</th><th>Package</th><th>Version</th><th>CVE / ID</th><th>Description</th><th>Fixed in</th></tr></thead>
      <tbody>{rows}</tbody>
    </table></div>'''

    return section_html(11, 'pip-audit', 'CVE Scan — pip-audit', status, label, body, has_findings=total>0)


# ── Custom findings (network / FS / obfuscation) ──────────────────────────────

def build_custom(findings, target):
    total = len(findings)

    # Group by category
    categories = {}
    for f in findings:
        cat = f.get('category', 'other')
        categories.setdefault(cat, []).append(f)

    CAT_LABELS = {
        'obfuscation': '🔒 Obfuscation & Code Execution',
        'network':     '🌐 Network & Exfiltration',
        'filesystem':  '📁 Filesystem & Credential Access',
        'other':       '⚠️ Other Patterns',
    }

    body = ''
    for cat, items in categories.items():
        label = CAT_LABELS.get(cat, cat)
        rows  = ''
        for item in items:
            sev_c  = sev_class(item.get('severity','MEDIUM'))
            rows += f'''<tr data-severity="{sev_c}">
              <td>{sev_badge(item.get("severity","MEDIUM"))}</td>
              <td><code>{esc(item.get("pattern","?"))}</code></td>
              <td class="msg-cell">{esc(item.get("description","")[:120])}</td>
              {file_cell(target, item.get("file","?"), item.get("line_number"))}
              <td class="mono" style="font-size:0.75rem;max-width:300px;color:var(--text-secondary)">
                {esc(str(item.get("line_content",""))[:100])}
              </td>
            </tr>'''
        body += f'''<div style="padding:10px 14px 4px;font-size:0.78rem;
                      font-weight:700;color:var(--text-muted);letter-spacing:0.06em">
                    {esc(label)}</div>
                  <div class="table-wrap"><table>
                    <thead><tr><th>Severity</th><th>Pattern</th><th>Description</th>
                      <th>File : Line</th><th>Code</th></tr></thead>
                    <tbody>{rows}</tbody>
                  </table></div>'''

    if not body:
        body = f'<div class="empty-state"><span class="icon">✓</span>No suspicious patterns detected</div>'

    label  = f'{total} pattern{"s" if total!=1 else ""}' if total else '✓ clean'
    status = 'warn' if total > 0 else 'pass'

    return section_html(5, 'custom', 'Pattern Analysis (Obfuscation / Network / Filesystem)',
                        status, label, body, has_findings=total>0)


# ── PyPI metadata ─────────────────────────────────────────────────────────────

def build_metadata(meta):
    info = meta.get('pypi_info', {})
    if not info:
        return section_html(3, 'metadata', 'Package Metadata', 'skip', 'n/a', '',
                            skip_msg='Metadata unavailable (GitHub source or offline scan).')

    flags = meta.get('metadata_flags', [])
    warnings_html = ''
    if flags:
        items = ''.join(f'<li>{esc(f)}</li>' for f in flags)
        warnings_html = f'<ul style="padding:1rem 1.4rem;color:var(--sev-medium);font-size:0.83rem">{items}</ul>'

    deps = info.get('requires_dist') or []
    dep_rows = ''.join(f'<tr data-severity="LOW"><td><code>{esc(d)}</code></td></tr>' for d in deps) \
               or empty_state('No dependencies declared')

    body = f'''
    <div class="info-grid">
      <div class="info-cell"><div class="info-cell-label">Package</div>
        <div class="info-cell-value">{esc(info.get("name","?"))}</div></div>
      <div class="info-cell"><div class="info-cell-label">Version</div>
        <div class="info-cell-value">{esc(info.get("version","?"))}</div></div>
      <div class="info-cell"><div class="info-cell-label">Author</div>
        <div class="info-cell-value">{esc(info.get("author","?"))}</div></div>
      <div class="info-cell"><div class="info-cell-label">License</div>
        <div class="info-cell-value">{esc(info.get("license","?"))}</div></div>
      <div class="info-cell"><div class="info-cell-label">Total releases</div>
        <div class="info-cell-value">{esc(info.get("total_releases","?"))}</div></div>
      <div class="info-cell"><div class="info-cell-label">Home page</div>
        <div class="info-cell-value">
          <a href="{esc(info.get('home_page','#'))}" target="_blank">
            {esc(info.get("home_page","?")[:60])}
          </a>
        </div>
      </div>
    </div>
    {warnings_html}
    <div style="padding:10px 14px 4px;font-size:0.78rem;font-weight:700;
                color:var(--text-muted);letter-spacing:0.06em">
      Dependencies ({len(deps)})
    </div>
    <div class="table-wrap"><table>
      <thead><tr><th>Declared dependency</th></tr></thead>
      <tbody>{dep_rows}</tbody>
    </table></div>'''

    status = 'warn' if flags else 'pass'
    label  = f'{len(flags)} flag{"s" if len(flags)!=1 else ""}' if flags else '✓ looks healthy'
    return section_html(3, 'metadata', 'Package Metadata & Typosquatting', status, label, body,
                        has_findings=bool(flags))


# ── Step summary table ────────────────────────────────────────────────────────

def build_summary_table(sections_status):
    rows = ''
    icons = {'pass': '✓', 'warn': '⚠', 'fail': '✗', 'skip': '⏭'}
    colors = {'pass': 'var(--sev-low)', 'warn': 'var(--sev-medium)',
              'fail': 'var(--sev-critical)', 'skip': 'var(--text-muted)'}

    for step_num, step_id, title, status, count in sections_status:
        icon  = icons.get(status, '?')
        color = colors.get(status, 'inherit')
        anchor = f'#section-{step_id}'
        rows += f'''<tr>
          <td style="color:var(--text-muted);width:60px">Step {step_num}</td>
          <td><a href="{anchor}" onclick="document.getElementById('section-{step_id}').classList.add('open')">{esc(title)}</a></td>
          <td style="color:{color};font-weight:700;text-align:center">{icon}</td>
          <td>{esc(count)}</td>
        </tr>'''

    body = f'''<div class="table-wrap"><table class="step-summary-table">
      <thead><tr><th>Step</th><th>Check</th><th style="text-align:center">Result</th><th>Detail</th></tr></thead>
      <tbody>{rows}</tbody>
    </table></div>'''

    return f'''
<div class="section open" id="section-summary">
  <div class="section-header">
    <div class="section-header-left">
      <span class="section-title">📋 Scan Summary</span>
    </div>
    <div class="section-right"><span class="chevron">▾</span></div>
  </div>
  <div class="section-body">{body}</div>
</div>'''


# ── Full HTML assembly ────────────────────────────────────────────────────────

def generate_html(meta, bandit, semgrep, gitleaks_data, secrets,
                  pip_audit, css, js):

    run_id       = meta.get('run_id', 'unknown')
    target       = meta.get('target', '?')
    package      = meta.get('package_name', target)
    started      = meta.get('started_at', '?')
    finished     = meta.get('finished_at', '?')
    duration     = meta.get('duration_seconds', 0)
    version      = meta.get('scanner_version', '2.1')
    verdict      = meta.get('verdict', 'UNKNOWN')
    verdict_emoji= meta.get('verdict_emoji', '🔍')
    verdict_sub  = meta.get('verdict_sub', '')
    score        = meta.get('score', {})
    critical_n   = score.get('critical', 0)
    high_n       = score.get('high', 0)
    medium_n     = score.get('medium', 0)
    low_n        = score.get('low', 0)
    is_github    = meta.get('is_github', False)
    gl_avail     = meta.get('tools', {}).get('gitleaks_available', False)

    custom_findings = meta.get('custom_findings', [])
    dur_str = f"{duration//60}m {duration%60}s" if duration else '—'
    source_label = 'GitHub' if is_github else 'PyPI'
    v_class = verdict_css_class(verdict)

    # Build section blocks
    s_metadata  = build_metadata(meta)
    s_custom    = build_custom(custom_findings, target if is_github else None)
    s_secrets   = build_secrets(secrets, target if is_github else None)
    s_gitleaks  = build_gitleaks(gitleaks_data, target, gl_avail)
    s_bandit    = build_bandit(bandit, target if is_github else None)
    s_semgrep   = build_semgrep(semgrep, target if is_github else None)
    s_pipadit   = build_pip_audit(pip_audit)

    # Summary table data
    bandit_total  = len(bandit.get('results', []))
    semgrep_total = len(semgrep.get('results', []))
    secrets_total = sum(len(v) for v in secrets.get('results',{}).values())
    gl_leaks = len(gitleaks_data) if isinstance(gitleaks_data, list) else 0
    pip_total = sum(len(d.get('vulns',[])) for d in pip_audit.get('dependencies',[]) if d.get('vulns'))
    custom_total = len(custom_findings)

    def ssum(n):
        return f'{n} issue{"s" if n!=1 else ""}' if n else '✓ clean'
    def sstatus(n):
        return 'warn' if n > 0 else 'pass'

    meta_flags = len(meta.get('metadata_flags', []))
    summary_rows = [
        (3,  'metadata',  'Package Metadata & Typosquatting',        'warn' if meta_flags else 'pass', ssum(meta_flags)),
        (5,  'custom',    'Pattern Analysis (Obfuscation/Network/FS)',sstatus(custom_total),            ssum(custom_total)),
        (7,  'secrets',   'Hardcoded Secrets — detect-secrets',       sstatus(secrets_total),          ssum(secrets_total)),
        (8,  'gitleaks',  'Git History Secrets — gitleaks',           sstatus(gl_leaks) if gl_avail else 'skip', ssum(gl_leaks) if gl_avail else 'not installed'),
        (9,  'bandit',    'SAST — Bandit',                            sstatus(bandit_total),           ssum(bandit_total)),
        (10, 'semgrep',   'SAST — Semgrep',                          sstatus(semgrep_total),          ssum(semgrep_total)),
        (11, 'pip-audit', 'CVE Scan — pip-audit',                    sstatus(pip_total),              ssum(pip_total)),
    ]
    s_summary = build_summary_table(summary_rows)

    return f'''<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>PySentinel Report — {esc(package)} — {esc(run_id)}</title>
  <style>{css}</style>
</head>
<body>

<!-- ── Navbar ──────────────────────────────────────────────── -->
<nav class="navbar">
  <div class="navbar-brand">
    <span class="shield">🛡</span>
    PySentinel <span style="color:var(--text-muted);font-weight:400;font-size:0.8rem">v{esc(version)}</span>
  </div>
  <div class="navbar-right">
    <span class="run-id-badge" data-tip="Scan Run ID">RUN&nbsp;{esc(run_id)}</span>
    <button id="expand-all" style="background:transparent;border:1px solid var(--border);
      color:var(--text-secondary);border-radius:var(--radius-sm);padding:4px 12px;
      font-size:0.78rem;cursor:pointer">Expand all</button>
  </div>
</nav>

<!-- ── Page ────────────────────────────────────────────────── -->
<div class="page">

  <!-- Verdict banner -->
  <div class="verdict-banner {v_class}">
    <div>
      <div class="verdict-label">{esc(verdict)}</div>
      <div class="verdict-sub">{esc(verdict_sub)}</div>
    </div>
    <div class="verdict-emoji">{verdict_emoji}</div>
  </div>

  <!-- Target info strip -->
  <div class="target-strip">
    <div class="target-cell">
      <div class="target-cell-label">Target</div>
      <div class="target-cell-value">
        <a href="{esc(target) if 'http' in target else '#'}" target="_blank">{esc(package)}</a>
      </div>
    </div>
    <div class="target-cell">
      <div class="target-cell-label">Source</div>
      <div class="target-cell-value">{esc(source_label)}</div>
    </div>
    <div class="target-cell">
      <div class="target-cell-label">Scan started</div>
      <div class="target-cell-value">{esc(started)}</div>
    </div>
    <div class="target-cell">
      <div class="target-cell-label">Duration</div>
      <div class="target-cell-value">{esc(dur_str)}</div>
    </div>
    <div class="target-cell">
      <div class="target-cell-label">Run ID</div>
      <div class="target-cell-value" style="font-family:var(--font-mono);font-size:0.82rem">{esc(run_id)}</div>
    </div>
  </div>

  <!-- Score cards -->
  <div class="score-grid">
    <div class="score-card critical">
      <div class="score-num">{critical_n}</div>
      <div class="score-label">Critical</div>
    </div>
    <div class="score-card high">
      <div class="score-num">{high_n}</div>
      <div class="score-label">High</div>
    </div>
    <div class="score-card medium">
      <div class="score-num">{medium_n}</div>
      <div class="score-label">Medium</div>
    </div>
    <div class="score-card low">
      <div class="score-num">{low_n}</div>
      <div class="score-label">Low</div>
    </div>
  </div>

  <!-- Toolbar -->
  <div class="toolbar">
    <button class="filter-btn" data-sev="CRITICAL">● Critical</button>
    <button class="filter-btn" data-sev="HIGH">● High</button>
    <button class="filter-btn" data-sev="MEDIUM">● Medium</button>
    <button class="filter-btn" data-sev="LOW">● Low</button>
    <div class="search-wrap">
      <span class="search-icon">🔍</span>
      <input class="search-input" id="search-input" type="text" placeholder="Search findings…">
    </div>
  </div>

  <!-- Sections -->
  {s_summary}
  {s_metadata}
  {s_custom}
  {s_secrets}
  {s_gitleaks}
  {s_bandit}
  {s_semgrep}
  {s_pipadit}

</div><!-- /page -->

<footer>
  Generated by <strong>PySentinel v{esc(version)}</strong> &nbsp;·&nbsp;
  Run ID: <code>{esc(run_id)}</code> &nbsp;·&nbsp;
  {esc(finished)}
</footer>

<script>{js}</script>
</body>
</html>'''


# ── CLI entry point ───────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description='PySentinel HTML Report Generator')
    parser.add_argument('--meta',      required=True,  help='meta.json written by pysentinel.sh')
    parser.add_argument('--bandit',    required=True,  help='bandit.json')
    parser.add_argument('--semgrep',   required=True,  help='semgrep.json')
    parser.add_argument('--gitleaks',  required=True,  help='gitleaks.json')
    parser.add_argument('--secrets',   required=True,  help='secrets.json (detect-secrets)')
    parser.add_argument('--pip-audit', required=True,  dest='pip_audit', help='pip_audit.json')
    parser.add_argument('--output',    required=True,  help='Output HTML file path')
    args = parser.parse_args()

    assets = Path(__file__).parent / 'assets'
    css    = (assets / 'report.css').read_text(encoding='utf-8')
    js     = (assets / 'report.js').read_text(encoding='utf-8')

    meta       = read_json(args.meta,       {})
    bandit     = read_json(args.bandit,     {'results': [], 'metrics': {}})
    semgrep    = read_json(args.semgrep,    {'results': []})
    gitleaks   = read_json(args.gitleaks,   [])
    secrets    = read_json(args.secrets,    {'results': {}})
    pip_audit  = read_json(args.pip_audit,  {'dependencies': []})

    html_out = generate_html(meta, bandit, semgrep, gitleaks, secrets, pip_audit, css, js)

    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(html_out, encoding='utf-8')
    print(f"[reporter] HTML report → {out}")


if __name__ == '__main__':
    main()
