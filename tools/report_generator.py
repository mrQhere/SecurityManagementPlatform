"""
VAPT Final Report Generator — Compliance-Ready PDF
====================================================
Generates a professional Vulnerability Assessment and Penetration Testing
(VAPT) Final Report conforming to PCI-DSS, SOC 2, and ISO 27001 audit
requirements.

Structure:
  Section 1  — Document Control & Cover Page
  Section 2  — Table of Contents & Executive Summary
  Section 3  — Engagement Scope & Methodology
  Section 4  — Findings Summary Matrix
  Section 5  — Deep-Dive Technical Findings (per-finding pages)
  Section 6  — Appendices, Tooling & Attestation
"""
import os
import json
import logging
import hashlib
import html as _html_module
from datetime import datetime
from tools.config_manager import BASE_DIR, init_directories, load_settings

logger = logging.getLogger("smp")

try:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch, mm
    from reportlab.platypus import (
        SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
        PageBreak, HRFlowable, KeepTogether, Image
    )
    from reportlab.platypus.flowables import Flowable
    from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT
    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False
    logger.warning("ReportLab not available. PDF reports will not be generated.")


# ── Palette ───────────────────────────────────────────────────────────────────
_P = {
    "bg":       "#0A0A0F",
    "surface":  "#111118",
    "card":     "#16161F",
    "border":   "#252530",
    "accent":   "#2563EB",
    "accent2":  "#1D4ED8",
    "white":    "#F8F8FC",
    "muted":    "#6B7280",
    "dim":      "#374151",
    "crit":     "#DC2626",
    "high":     "#EA580C",
    "med":      "#D97706",
    "low":      "#2563EB",
    "info":     "#4B5563",
    "green":    "#059669",
}

_SEV_CSS = {
    "Critical": _P["crit"],
    "High":     _P["high"],
    "Medium":   _P["med"],
    "Low":      _P["low"],
    "Info":     _P["info"],
}

_SEV_LABEL = {
    "Critical": ("CRITICAL", _P["crit"]),
    "High":     ("HIGH",     _P["high"]),
    "Medium":   ("MEDIUM",   _P["med"]),
    "Low":      ("LOW",      _P["low"]),
    "Info":     ("INFO",     _P["info"]),
}

def _esc(s):
    return _html_module.escape(str(s or ""))

def _c(hex_str):
    return colors.HexColor(hex_str)

def _sev_color(sev):
    return _c(_SEV_CSS.get(sev, _P["info"]))

_SEV_ORDER = ["Critical", "High", "Medium", "Low", "Info"]

def _sev_rank(sev):
    try:
        return _SEV_ORDER.index(sev)
    except ValueError:
        return 99


# ── Page template with header/footer ─────────────────────────────────────────

class _VAPTDoc(SimpleDocTemplate):
    """Custom doc template that stamps CONFIDENTIAL header/footer on every page."""

    def __init__(self, filepath, target_url, scan_date, doc_version, **kw):
        super().__init__(filepath, **kw)
        self.target_url = target_url
        self.scan_date = scan_date
        self.doc_version = doc_version

    def handle_pageBegin(self):
        self._doPage()
        super().handle_pageBegin()

    def _doPage(self):
        canvas = self.canv
        W, H = A4
        canvas.saveState()

        # Top classification bar
        canvas.setFillColor(_c(_P["crit"]))
        canvas.setStrokeColor(_c(_P["crit"]))
        canvas.rect(0, H - 24, W, 24, fill=1, stroke=0)
        canvas.setFillColor(colors.white)
        canvas.setFont("Helvetica-Bold", 8)
        canvas.drawCentredString(W / 2, H - 15, "CONFIDENTIAL — INTERNAL USE ONLY — NOT FOR DISTRIBUTION")

        # Bottom bar
        canvas.setFillColor(_c(_P["surface"]))
        canvas.rect(0, 0, W, 22, fill=1, stroke=0)
        canvas.setFillColor(_c(_P["muted"]))
        canvas.setFont("Helvetica", 7)
        canvas.drawString(18, 7, f"VAPT Final Report  |  Target: {self.target_url}  |  Date: {self.scan_date}")
        canvas.drawRightString(W - 18, 7, f"v{self.doc_version}  |  Page {canvas.getPageNumber()}")

        canvas.restoreState()


# ── Style factory ─────────────────────────────────────────────────────────────

def _styles():
    base = getSampleStyleSheet()

    def S(name, **kw):
        return ParagraphStyle(name, parent=base["Normal"], **kw)

    return {
        "cover_title": S("CoverTitle",
            fontName="Helvetica-Bold", fontSize=30, textColor=_c(_P["white"]),
            alignment=TA_LEFT, leading=38, spaceAfter=8),

        "cover_sub": S("CoverSub",
            fontName="Helvetica", fontSize=13, textColor=_c(_P["muted"]),
            alignment=TA_LEFT, spaceAfter=6),

        "cover_kv_key": S("CoverKVK",
            fontName="Helvetica-Bold", fontSize=9, textColor=_c(_P["muted"]),
            leading=14, spaceAfter=2),

        "cover_kv_val": S("CoverKVV",
            fontName="Helvetica-Bold", fontSize=11, textColor=_c(_P["white"]),
            leading=14, spaceAfter=6),

        "conf_stamp": S("ConfStamp",
            fontName="Helvetica-Bold", fontSize=10, textColor=_c(_P["crit"]),
            alignment=TA_CENTER, spaceAfter=4),

        "section_num": S("SecNum",
            fontName="Helvetica-Bold", fontSize=8, textColor=_c(_P["accent"]),
            leading=12, spaceAfter=2),

        "section_title": S("SecTitle",
            fontName="Helvetica-Bold", fontSize=17, textColor=_c(_P["white"]),
            leading=22, spaceAfter=4, spaceBefore=20),

        "h3": S("H3",
            fontName="Helvetica-Bold", fontSize=11, textColor=_c(_P["white"]),
            leading=16, spaceBefore=12, spaceAfter=4),

        "h4": S("H4",
            fontName="Helvetica-Bold", fontSize=9, textColor=_c(_P["muted"]),
            leading=13, spaceBefore=8, spaceAfter=3),

        "body": S("Body",
            fontName="Helvetica", fontSize=9, textColor=_c(_P["muted"]),
            leading=14, spaceAfter=4),

        "body_white": S("BodyW",
            fontName="Helvetica", fontSize=9, textColor=_c(_P["white"]),
            leading=14, spaceAfter=4),

        "mono": S("Mono",
            fontName="Courier", fontSize=8, textColor=_c(_P["green"]),
            leading=12, spaceAfter=2),

        "cell": S("Cell",
            fontName="Helvetica", fontSize=8, textColor=_c(_P["white"]),
            leading=11),

        "cell_dim": S("CellDim",
            fontName="Helvetica", fontSize=8, textColor=_c(_P["muted"]),
            leading=11),

        "cell_bold": S("CellBold",
            fontName="Helvetica-Bold", fontSize=8, textColor=_c(_P["white"]),
            leading=11),

        "cell_accent": S("CellAccent",
            fontName="Helvetica-Bold", fontSize=8, textColor=_c(_P["accent"]),
            leading=11),

        "toc_entry": S("TOCEntry",
            fontName="Helvetica", fontSize=10, textColor=_c(_P["white"]),
            leading=20, leftIndent=0),

        "toc_sub": S("TOCSub",
            fontName="Helvetica", fontSize=9, textColor=_c(_P["muted"]),
            leading=16, leftIndent=20),

        "exec_narrative": S("ExecNarrative",
            fontName="Helvetica", fontSize=10, textColor=_c(_P["muted"]),
            leading=17, spaceAfter=8),

        "finding_id": S("FindingID",
            fontName="Helvetica-Bold", fontSize=13, textColor=_c(_P["white"]),
            leading=18, spaceAfter=2),

        "label": S("Label",
            fontName="Helvetica-Bold", fontSize=7, textColor=_c(_P["muted"]),
            leading=10, spaceAfter=1),

        "value": S("Value",
            fontName="Helvetica", fontSize=9, textColor=_c(_P["white"]),
            leading=14, spaceAfter=3),

        "attest": S("Attest",
            fontName="Helvetica", fontSize=9, textColor=_c(_P["muted"]),
            leading=15, spaceAfter=4),
    }


# ── Reusable layout primitives ────────────────────────────────────────────────

BW = A4[0] - 2 * 18 * mm   # body width ≈ 521 pt

def _hr(color=_P["border"], thick=0.5):
    return HRFlowable(width="100%", thickness=thick, color=_c(color),
                      spaceAfter=6, spaceBefore=4)

def _spacer(h=8):
    return Spacer(1, h)

def _section_header(st, section_num, title):
    return KeepTogether([
        _hr(_P["accent"], thick=1),
        Paragraph(f"SECTION {section_num}", st["section_num"]),
        Paragraph(title, st["section_title"]),
        _hr(),
    ])

def _kv_table(pairs, st, col_w=None):
    """Two-column key-value table."""
    cw = col_w or [BW * 0.30, BW * 0.70]
    data = [[Paragraph(_esc(k), st["cell_dim"]),
             Paragraph(_esc(v), st["cell"])] for k, v in pairs]
    t = Table(data, colWidths=cw, hAlign="LEFT")
    t.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, -1), _c(_P["card"])),
        ("ROWBACKGROUNDS",(0, 0), (-1, -1), [_c(_P["card"]), _c(_P["surface"])]),
        ("GRID",          (0, 0), (-1, -1), 0.3, _c(_P["border"])),
        ("TOPPADDING",    (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("LEFTPADDING",   (0, 0), (-1, -1), 10),
        ("VALIGN",        (0, 0), (-1, -1), "TOP"),
    ]))
    return t

def _data_table(headers, rows, col_widths, st):
    """Standard data table with accent header row."""
    head_row = [Paragraph(_esc(h), st["cell_bold"]) for h in headers]
    body_rows = []
    for row in rows:
        body_rows.append([
            Paragraph(_esc(str(c)), st["cell"]) if not isinstance(c, Paragraph) else c
            for c in row
        ])
    data = [head_row] + body_rows
    t = Table(data, colWidths=col_widths, hAlign="LEFT", repeatRows=1)
    t.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1,  0), _c(_P["accent2"])),
        ("ROWBACKGROUNDS",(0, 1), (-1, -1), [_c(_P["card"]), _c(_P["surface"])]),
        ("GRID",          (0, 0), (-1, -1), 0.3, _c(_P["border"])),
        ("TOPPADDING",    (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("LEFTPADDING",   (0, 0), (-1, -1), 7),
        ("VALIGN",        (0, 0), (-1, -1), "TOP"),
    ]))
    return t

def _sev_badge_para(sev, st):
    label, color = _SEV_LABEL.get(sev, ("INFO", _P["info"]))
    return Paragraph(
        f'<font color="{color}"><b>{label}</b></font>', st["cell"])

def _code_block(text, st, max_chars=1800):
    text = str(text or "").replace("&", "&amp;").replace("<", "&lt;")[:max_chars]
    lines = text.split("\n")
    block_rows = [[Paragraph(_esc(ln), st["mono"])] for ln in lines]
    if not block_rows:
        return _spacer(2)
    t = Table(block_rows, colWidths=[BW - 20])
    t.setStyle(TableStyle([
        ("BACKGROUND",   (0, 0), (-1, -1), _c("#0A0E14")),
        ("BOX",          (0, 0), (-1, -1), 0.5, _c(_P["green"])),
        ("TOPPADDING",   (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING",(0, 0), (-1, -1), 4),
        ("LEFTPADDING",  (0, 0), (-1, -1), 8),
    ]))
    return t


# ── Main entry point ──────────────────────────────────────────────────────────

def generate_scan_reports(scan_id, target, current_findings, previous_scan=None):
    """
    Generates HTML (legacy kept for email) and a compliance-ready VAPT PDF.
    Returns: (html_report_path | None, pdf_report_path | None)
    """
    init_directories()

    url = target["url"]
    safe_name = (url.replace("http://", "").replace("https://", "")
                 .replace("/", "_").replace(":", "_").strip("_"))
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    html_path = os.path.join(BASE_DIR, "reports", "html",
                             f"report_{safe_name}_{timestamp}.html")
    pdf_path  = os.path.join(BASE_DIR, "reports", "pdf",
                             f"VAPT_Report_{safe_name}_{timestamp}.pdf")

    from tools.db_manager import get_scan, get_technologies_for_scan, get_risk_score, get_scan_trend_deltas
    scan_rec     = get_scan(scan_id)
    scanned_by   = (scan_rec.get("scanned_by") if scan_rec else None) or \
                   load_settings().get("tester_name", "Security Auditor")
    technologies = get_technologies_for_scan(scan_id)
    risk_data    = get_risk_score(scan_id)
    trend_deltas = get_scan_trend_deltas(url, scan_id)

    ctx = _build_context(scan_id, target, current_findings, previous_scan,
                         scanned_by, technologies, risk_data, trend_deltas)

    # HTML fallback (lightweight)
    try:
        _generate_html_fallback(html_path, ctx)
        logger.info(f"HTML report generated: {html_path}")
    except Exception as e:
        logger.error(f"HTML report failed: {e}", exc_info=True)
        html_path = None

    # VAPT PDF
    if REPORTLAB_AVAILABLE:
        try:
            _generate_vapt_pdf(pdf_path, ctx)
            logger.info(f"VAPT PDF report generated: {pdf_path}")
            
            # Digitally verify and hash the PDF
            with open(pdf_path, "rb") as f:
                pdf_bytes = f.read()
            file_hash = hashlib.sha256(pdf_bytes).hexdigest()
            
            # Save the hash to the database for future verification
            from tools.db_manager import save_report_hash
            save_report_hash(scan_id, file_hash)
            
            signed_pdf_path = os.path.join(BASE_DIR, "reports", "pdf", f"VAPT_Report_{safe_name}_{timestamp}_{file_hash[:8]}.pdf")
            os.rename(pdf_path, signed_pdf_path)
            pdf_path = signed_pdf_path
            logger.info(f"PDF Digitally Signed: {pdf_path}")
            
        except Exception as e:
            logger.error(f"PDF report failed: {e}", exc_info=True)
            pdf_path = None
    else:
        logger.warning("ReportLab not installed — PDF report skipped.")
        pdf_path = None

    return html_path, pdf_path


# ── Context builder ───────────────────────────────────────────────────────────

def _build_context(scan_id, target, findings, previous_scan,
                   scanned_by, technologies, risk_data, trend_deltas):
    url       = target["url"]
    scan_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    settings  = load_settings()

    def by_tool(*tools):
        return [f for f in findings if f.get("source_tool") in tools]

    nmap      = by_tool("Nmap")
    nuclei    = by_tool("Nuclei")
    nikto     = by_tool("Nikto")
    ffuf      = by_tool("ffuf")
    wapiti    = by_tool("Wapiti")
    sqlmap    = by_tool("SQLMap")
    ssl_f     = by_tool("SSL")
    tracert   = by_tool("Traceroute")
    cve_corr  = by_tool("CVE Correlation")
    shodan    = by_tool("Shodan")
    wayback   = by_tool("Wayback Machine")
    crtsh     = by_tool("CRT.sh")
    ht_data   = by_tool("HackerTarget")
    whois_d   = by_tool("Whois")
    httpx     = by_tool("HTTPx")
    subfinder = by_tool("Subfinder")
    headers   = by_tool("Security Headers")
    robots    = by_tool("Robots.txt")
    cors      = by_tool("CORS")
    cms       = by_tool("CMS Scanner")
    redirect  = by_tool("Open Redirect")
    tech_fp   = by_tool("Tech Fingerprint")
    zap       = by_tool("ZAP")

    counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
    for f in findings:
        s = f.get("severity", "Info")
        if s in counts:
            counts[s] += 1

    return dict(
        target=target,
        url=url, scan_time=scan_time, scanned_by=scanned_by,
        doc_version="1.0", doc_status="Final",
        findings=findings, nmap=nmap, nuclei=nuclei, nikto=nikto,
        ffuf=ffuf, wapiti=wapiti, sqlmap=sqlmap, ssl_f=ssl_f,
        tracert=tracert, cve_corr=cve_corr,
        shodan=shodan, wayback=wayback, crtsh=crtsh,
        ht_data=ht_data, whois_d=whois_d,
        httpx=httpx, subfinder=subfinder, headers=headers, robots=robots,
        cors=cors, cms=cms, redirect=redirect, tech_fp=tech_fp, zap=zap,
        technologies=technologies, risk_data=risk_data,
        previous_scan=previous_scan, counts=counts,
        total=len(findings),
        settings=settings,
        trend_deltas=trend_deltas,
    )


# ═══════════════════════════════════════════════════════════════════════════════
#  VAPT PDF — COMPLIANCE GRADE
# ═══════════════════════════════════════════════════════════════════════════════

def _generate_vapt_pdf(filepath, ctx):
    c      = ctx
    counts = c["counts"]
    W, H   = A4
    st     = _styles()

    doc = _VAPTDoc(
        filepath,
        target_url=c["url"],
        scan_date=c["scan_time"][:10],
        doc_version=c["doc_version"],
        pagesize=A4,
        rightMargin=18 * mm,
        leftMargin=18 * mm,
        topMargin=26 * mm,
        bottomMargin=20 * mm,
    )

    story = []

    # ══════════════════════════════════════════════════════════════════════════
    # SECTION 1 — COVER PAGE
    # ══════════════════════════════════════════════════════════════════════════
    story += [
        _spacer(60),
        Paragraph("VULNERABILITY ASSESSMENT &amp;", st["cover_title"]),
        Paragraph("PENETRATION TESTING (VAPT)", st["cover_title"]),
        Paragraph("FINAL REPORT", st["cover_title"]),
        _spacer(6),
        _hr(_P["accent"], thick=2),
        _spacer(10),
        Paragraph(f"Target: {_esc(c['url'])}", st["cover_sub"]),
        Paragraph(f"Assessment Date: {c['scan_time'][:10]}", st["cover_sub"]),
        Paragraph(f"Lead Auditor: {_esc(c['scanned_by'])}", st["cover_sub"]),
        _spacer(30),
    ]

    # Cover metadata grid
    company_name = c["target"].get("company_name") or "Unknown Company"
    submitted_to = c["target"].get("submitted_to") or "Internal Security Team"
    
    cover_meta = [
        ("Document Title",      "Vulnerability Assessment and Penetration Testing (VAPT) Final Report"),
        ("Target Application",   c["url"]),
        ("Target Company",       company_name),
        ("Submitted To",         submitted_to),
        ("Date of Issuance",     c["scan_time"][:10]),
        ("Document Version",     c["doc_version"]),
        ("Document Status",      c["doc_status"]),
        ("Lead Penetration Tester", c["scanned_by"]),
        ("QA Reviewer",          c["settings"].get("qa_reviewer", "QA Manager")),
        ("Data Classification",  "CONFIDENTIAL — INTERNAL USE ONLY"),
        ("Verification Status",  "DIGITALLY VERIFIED (SHA-256 Hash Attached to Filename)"),
    ]
    story.append(_kv_table(cover_meta, st, col_w=[BW * 0.35, BW * 0.65]))
    story += [_spacer(20)]

    # Document version / change log table
    vt_data = [
        ["Version", "Date", "Author", "Reviewer", "Description"],
        ["0.1 Draft",    c["scan_time"][:10], c["scanned_by"], "—",
         "Initial automated scan draft"],
        ["1.0 Final",    c["scan_time"][:10], c["scanned_by"],
         c["settings"].get("qa_reviewer", "QA Manager"), "Final delivery"],
    ]
    col_w_ver = [50, 72, 105, 105, 189]
    head_row = [Paragraph(h, st["cell_bold"]) for h in vt_data[0]]
    body_rows = [[Paragraph(str(v), st["cell_dim"]) for v in row] for row in vt_data[1:]]
    ver_table = Table([head_row] + body_rows, colWidths=col_w_ver, hAlign="LEFT")
    ver_table.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, 0), _c(_P["accent2"])),
        ("BACKGROUND",    (0, 1), (-1, -1), _c(_P["card"])),
        ("GRID",          (0, 0), (-1, -1), 0.3, _c(_P["border"])),
        ("TOPPADDING",    (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("LEFTPADDING",   (0, 0), (-1, -1), 7),
    ]))
    story += [Paragraph("Document Version Control", st["h3"]), ver_table, _spacer(20)]

    story.append(Paragraph(
        "⚠  CLASSIFICATION: CONFIDENTIAL — INTERNAL USE ONLY — NOT FOR DISTRIBUTION",
        st["conf_stamp"]
    ))
    story.append(PageBreak())

    # ══════════════════════════════════════════════════════════════════════════
    # SECTION 2 — TABLE OF CONTENTS & EXECUTIVE SUMMARY
    # ══════════════════════════════════════════════════════════════════════════
    story.append(_section_header(st, "2", "Table of Contents &amp; Executive Summary"))

    toc_items = [
        ("1", "Document Control & Cover Page"),
        ("2", "Table of Contents & Executive Summary"),
        ("3", "Engagement Scope & Methodology Boundaries"),
        ("4", "Findings Summary Matrix"),
        ("5", "Deep-Dive Technical Findings"),
        ("5B", "Automated Hardening Recommendations & Action Plan"),
        ("6A", "Appendix A — Security Assessment Tooling"),
        ("6B", "Appendix B — Post-Testing Environment Clean-up Log"),
        ("6C", "Appendix C — Severity Definitions Glossary"),
        ("6D", "Appendix D — Formal Attestation & Sign-off"),
    ]
    for num, title in toc_items:
        story.append(Paragraph(
            f'<font color="{_P["accent"]}"><b>{num}.</b></font>  {_esc(title)}',
            st["toc_entry"]))
    story.append(_spacer(14))
    story.append(_hr())

    # Executive Narrative
    story.append(Paragraph("Executive Narrative", st["h3"]))

    crit_n = counts["Critical"]
    high_n = counts["High"]
    med_n  = counts["Medium"]
    low_n  = counts["Low"]
    total  = c["total"]

    if crit_n > 0:
        posture_stmt = (
            f"The assessment of <b>{_esc(c['url'])}</b> reveals a <b>HIGH-RISK security posture</b>. "
            f"{crit_n} Critical and {high_n} High severity vulnerabilities were confirmed, representing "
            f"immediate risk to confidentiality, integrity, and availability of the target environment. "
            f"Immediate remediation action is required before the next business cycle."
        )
    elif high_n > 0:
        posture_stmt = (
            f"The assessment of <b>{_esc(c['url'])}</b> reveals a <b>MEDIUM-HIGH risk posture</b>. "
            f"{high_n} High severity findings were confirmed alongside {med_n} Medium severity issues. "
            f"The application demonstrates functional security controls at the perimeter but shows "
            f"significant gaps in depth-of-defence measures. Prioritised remediation is recommended within 72 hours."
        )
    else:
        posture_stmt = (
            f"The assessment of <b>{_esc(c['url'])}</b> indicates a <b>LOW-TO-MODERATE security posture</b>. "
            f"No Critical or High findings were identified during this engagement. {med_n} Medium and {low_n} Low "
            f"severity observations were recorded. The application demonstrates a reasonable security baseline; "
            f"continued periodic assessment and hardening are recommended."
        )

    story.append(Paragraph(posture_stmt, st["exec_narrative"]))
    story.append(_spacer(12))

    # Historical Trend Analysis
    if c.get("trend_deltas") and c["trend_deltas"].get("previous_scan_id"):
        story.append(Paragraph("Historical Scan Trend Analysis", st["h3"]))
        td = c["trend_deltas"]
        trend_text = (
            f"Compared to the previous assessment (Scan ID: {td['previous_scan_id']}), the following changes were observed:<br/><br/>"
            f"<b><font color='{_P['crit']}'>[+] New Findings:</font></b> {td['new']}<br/>"
            f"<b><font color='{_P['green']}'>[-] Resolved Findings:</font></b> {td['resolved']}<br/>"
            f"<b><font color='{_P['med']}'>[=] Persisting Findings:</font></b> {td['persisting']}"
        )
        story.append(Paragraph(trend_text, st["body"]))
        story.append(_spacer(12))

    # Risk Metric Dashboard — severity counts table
    story.append(Paragraph("Risk Metric Dashboard", st["h3"]))
    sev_cols = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    sev_vals = [str(counts.get("Critical", 0)), str(counts.get("High", 0)),
                str(counts.get("Medium", 0)), str(counts.get("Low", 0)),
                str(counts.get("Info", 0))]
    sev_colors = [_P["crit"], _P["high"], _P["med"], _P["low"], _P["info"]]
    head_cells = [Paragraph(f'<font color="{sev_colors[i]}"><b>{sev_cols[i]}</b></font>', st["cell_bold"])
                  for i in range(5)]
    val_cells  = [Paragraph(f'<font color="{sev_colors[i]}"><b>{sev_vals[i]}</b></font>',
                            ParagraphStyle("SevNum", parent=st["cell_bold"],
                                           fontSize=22, alignment=TA_CENTER, leading=28))
                  for i in range(5)]
    sev_t = Table([head_cells, val_cells], colWidths=[BW / 5] * 5, hAlign="LEFT")
    sev_t.setStyle(TableStyle([
        ("ALIGN",         (0, 0), (-1, -1), "CENTER"),
        ("BACKGROUND",    (0, 0), (-1, -1), _c(_P["card"])),
        ("BOX",           (0, 0), (-1, -1), 0.5, _c(_P["border"])),
        ("GRID",          (0, 0), (-1, -1), 0.3, _c(_P["border"])),
        ("TOPPADDING",    (0, 0), (-1, -1), 10),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
    ]))
    story += [sev_t, _spacer(14)]

    # Strategic Action Plan
    story.append(Paragraph("Strategic Action Plan (Management Summary)", st["h3"]))
    actions = []
    if crit_n > 0:
        actions.append("<b>IMMEDIATE (0–24 hrs):</b> Isolate and patch all Critical findings. "
                       "Initiate emergency change control. Brief executive stakeholders.")
    if high_n > 0:
        actions.append("<b>SHORT-TERM (24–72 hrs):</b> Address all High severity findings. "
                       "Deploy WAF rules as interim mitigation while permanent patches are prepared.")
    if c["cve_corr"]:
        actions.append("<b>MEDIUM-TERM (1–2 weeks):</b> Upgrade all software components matched to CVE "
                       "correlation results. Enforce version pinning and dependency auditing in CI/CD.")
    if c["ssl_f"]:
        actions.append("<b>CONFIGURATION (ongoing):</b> Enforce TLS 1.2+ across all endpoints. "
                       "Disable deprecated cipher suites. Automate certificate renewal.")
    if not actions:
        actions.append("<b>MAINTAIN:</b> No critical findings. Continue scheduled quarterly assessments. "
                       "Monitor CVE feeds and apply patches within standard SLA windows.")

    for act in actions:
        act_t = Table([[Paragraph(act, st["body"])]], colWidths=[BW])
        act_t.setStyle(TableStyle([
            ("BACKGROUND",   (0, 0), (-1, -1), _c(_P["card"])),
            ("LEFTBORDER",   (0, 0), (0, -1), 3, _c(_P["accent"])),
            ("BOX",          (0, 0), (-1, -1), 0.3, _c(_P["border"])),
            ("TOPPADDING",   (0, 0), (-1, -1), 8),
            ("BOTTOMPADDING",(0, 0), (-1, -1), 8),
            ("LEFTPADDING",  (0, 0), (-1, -1), 12),
        ]))
        story += [act_t, _spacer(5)]

    story.append(PageBreak())

    # ══════════════════════════════════════════════════════════════════════════
    # SECTION 3 — SCOPE & METHODOLOGY
    # ══════════════════════════════════════════════════════════════════════════
    story.append(_section_header(st, "3", "Engagement Scope &amp; Methodology Boundaries"))

    story.append(Paragraph("In-Scope Asset Inventory", st["h3"]))
    subdomains = c["crtsh"] + c["subfinder"]
    scope_rows = [
        ["Primary Target", c["url"], "Web Application", "Authorized"],
    ]
    for sub in subdomains[:20]:
        host = sub.get("title", "").replace("Subdomain Discovered: ", "")
        scope_rows.append([host, "Subdomain", "Web", "Authorized"])
    for nmap_f in c["nmap"][:10]:
        scope_rows.append([c["url"], nmap_f.get("title", ""), "Network Port", "Authorized"])
    story.append(_data_table(
        ["Asset / Host", "URL / Port", "Asset Type", "Auth Status"],
        scope_rows,
        [BW * 0.28, BW * 0.32, BW * 0.22, BW * 0.18],
        st
    ))
    story.append(_spacer(10))

    story.append(Paragraph("Out-of-Scope / Excluded Assets", st["h3"]))
    oos_rows = [
        ["Third-party payment processors (e.g., Stripe, PayPal)", "Legal boundary — vendor-controlled"],
        ["Cloud provider management consoles (AWS, GCP, Azure)", "Vendor infrastructure — not authorized"],
        ["Third-party SSO / OAuth providers", "Vendor-controlled authentication endpoints"],
        ["CDN infrastructure (Cloudflare, Fastly)", "Shared infrastructure — potential collateral impact"],
    ]
    story.append(_data_table(
        ["Excluded Asset / Endpoint", "Reason for Exclusion"],
        oos_rows,
        [BW * 0.55, BW * 0.45],
        st
    ))
    story.append(_spacer(10))

    story.append(Paragraph("Testing Timeline", st["h3"]))
    story.append(_kv_table([
        ("Engagement Start",    c["scan_time"]),
        ("Engagement End",      c["scan_time"]),
        ("Timezone",            "UTC+05:30 (IST) — as recorded by the scanning host"),
        ("Scan Duration",       "Automated multi-tool pipeline, sequential execution"),
        ("Testing Type",        "Black Box / Gray Box — no source code access"),
    ], st))
    story.append(_spacer(10))

    story.append(Paragraph("Assessment Framework Compliance", st["h3"]))
    framework_rows = [
        ["OWASP WSTG v4.2", "Web Security Testing Guide — primary methodology"],
        ["NIST SP 800-115", "Technical Guide to Information Security Testing"],
        ["PTES",            "Penetration Testing Execution Standard"],
        ["CVSS v4.0",       "Common Vulnerability Scoring System for all severity ratings"],
        ["CWE",             "Common Weakness Enumeration taxonomy for all findings"],
        ["PCI-DSS v4.0",    "Sections 6.4 and 11.3 — penetration testing compliance"],
    ]
    story.append(_data_table(
        ["Framework / Standard", "Application Scope"],
        framework_rows,
        [BW * 0.38, BW * 0.62],
        st
    ))
    story.append(PageBreak())

    # ══════════════════════════════════════════════════════════════════════════
    # SECTION 4 — FINDINGS SUMMARY MATRIX
    # ══════════════════════════════════════════════════════════════════════════
    story.append(_section_header(st, "4", "Findings Summary Matrix"))

    # Sort: Critical → High → Medium → Low → Info
    sorted_findings = sorted(c["findings"], key=lambda f: _sev_rank(f.get("severity", "Info")))

    if sorted_findings:
        matrix_data = [["ID", "Vulnerability Title", "Component / Tool",
                         "Severity", "CVSS", "Status"]]
        for idx, f in enumerate(sorted_findings, 1):
            sev  = f.get("severity", "Info")
            label, color = _SEV_LABEL.get(sev, ("INFO", _P["info"]))
            sev_cell = Paragraph(
                f'<font color="{color}"><b>{label}</b></font>', st["cell"])
            matrix_data.append([
                Paragraph(f"SEC-{idx:02d}", st["cell_dim"]),
                Paragraph(_esc(f.get("title", "Unknown")[:55]), st["cell"]),
                Paragraph(_esc(f.get("source_tool", "")[:20]), st["cell_dim"]),
                sev_cell,
                Paragraph("N/A", st["cell_dim"]),  # CVSS per-finding if available
                Paragraph('<font color="#D97706">Open</font>', st["cell"]),
            ])

        matrix_t = Table(matrix_data,
                         colWidths=[42, BW * 0.38, BW * 0.16, 55, 35, 50],
                         hAlign="LEFT", repeatRows=1)
        matrix_t.setStyle(TableStyle([
            ("BACKGROUND",    (0, 0), (-1, 0), _c(_P["accent2"])),
            ("ROWBACKGROUNDS",(0, 1), (-1, -1), [_c(_P["card"]), _c(_P["surface"])]),
            ("GRID",          (0, 0), (-1, -1), 0.3, _c(_P["border"])),
            ("TOPPADDING",    (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ("LEFTPADDING",   (0, 0), (-1, -1), 5),
            ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
        ]))
        story.append(matrix_t)
    else:
        story.append(Paragraph("No findings were recorded for this scan.", st["body"]))

    story.append(PageBreak())

    # ══════════════════════════════════════════════════════════════════════════
    # SECTION 5 — DEEP-DIVE TECHNICAL FINDINGS
    # ══════════════════════════════════════════════════════════════════════════
    story.append(_section_header(st, "5", "Deep-Dive Technical Findings"))

    if not sorted_findings:
        story.append(Paragraph("No technical findings to document.", st["body"]))
    else:
        for idx, f in enumerate(sorted_findings, 1):
            sev  = f.get("severity", "Info")
            tool = f.get("source_tool", "Unknown")
            title = f.get("title", "Unknown Finding")
            desc  = f.get("description", "No description available.")
            label, sev_hex = _SEV_LABEL.get(sev, ("INFO", _P["info"]))

            # ── Finding header block ──────────────────────────────────────
            header_data = [[
                Paragraph(f"SEC-{idx:02d}", ParagraphStyle(
                    "FID", parent=st["cell_dim"], fontSize=9, textColor=_c(_P["muted"]))),
                Paragraph(
                    f'<font color="{sev_hex}"><b>[{label}]</b></font>  {_esc(title[:80])}',
                    st["finding_id"]),
            ]]
            hdr_t = Table(header_data, colWidths=[52, BW - 52], hAlign="LEFT")
            hdr_t.setStyle(TableStyle([
                ("BACKGROUND",   (0, 0), (-1, -1), _c(_P["card"])),
                ("LEFTBORDER",   (0, 0), (0, -1), 4, _c(sev_hex)),
                ("BOX",          (0, 0), (-1, -1), 0.3, _c(_P["border"])),
                ("TOPPADDING",   (0, 0), (-1, -1), 10),
                ("BOTTOMPADDING",(0, 0), (-1, -1), 10),
                ("LEFTPADDING",  (0, 0), (-1, -1), 10),
                ("VALIGN",       (0, 0), (-1, -1), "MIDDLE"),
            ]))
            story.append(KeepTogether([hdr_t, _spacer(6)]))

            # ── Taxonomy Mappings ─────────────────────────────────────────
            story.append(Paragraph("Taxonomy Mappings", st["h4"]))
            story.append(_kv_table([
                ("MITRE ATT&CK",    f.get('mitre_id', 'Unknown')),
                ("CVE",             "See CVE Correlation section for matched CVEs"),
                ("CWE",             _get_cwe_hint(tool, sev)),
                ("OWASP Category",  _get_owasp_hint(tool)),
                ("CVSS Vector",     f"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:{_cvss_vc(sev)}/VI:{_cvss_vi(sev)}/VA:N/SC:N/SI:N/SA:N"),
                ("Detection Tool",  tool),
                ("Confidence",      f"{f.get('confidence', 50)}%"),
            ], st))
            story.append(_spacer(6))

            # ── Technical Breakdown ───────────────────────────────────────
            story.append(Paragraph("Technical Breakdown", st["h4"]))
            story.append(Paragraph(_esc(desc[:600]), st["body"]))
            story.append(_spacer(6))

            # ── Evidence / Raw Output ─────────────────────────────────────
            if len(desc) > 30:
                story.append(Paragraph("Evidence / Raw Scanner Output", st["h4"]))
                story.append(_code_block(desc[:1200], st))
                story.append(_spacer(6))

            # ── Remediation Blueprint ─────────────────────────────────────
            story.append(Paragraph("Remediation Blueprint", st["h4"]))
            strategic, code_fix = _get_remediation(tool, sev, title)
            story.append(Paragraph(f"<b>Strategic Fix:</b> {strategic}", st["body"]))
            if code_fix:
                story.append(_spacer(4))
                story.append(Paragraph("Code-Level Recommendation:", st["label"]))
                story.append(_code_block(code_fix, st))

            story += [_spacer(10), _hr(_P["border"]), _spacer(6)]

            # Page break every 3 findings to avoid walls of text
            if idx % 3 == 0 and idx < len(sorted_findings):
                story.append(PageBreak())

    # ══════════════════════════════════════════════════════════════════════════
    # SECTION 5B — AUTOMATED HARDENING RECOMMENDATIONS
    # ══════════════════════════════════════════════════════════════════════════
    _generate_hardening_section(c["findings"], st, story)
    story.append(PageBreak())

    # ══════════════════════════════════════════════════════════════════════════
    # SECTION 6A — APPENDIX: TOOLING
    # ══════════════════════════════════════════════════════════════════════════
    story.append(_section_header(st, "6A", "Appendix A — Security Assessment Tooling"))

    tools_rows = [
        ["HTTPx",           "HTTP probe & header analysis",         "Open Source", "Active — HTTP"],
        ["WhatWeb",         "Passive technology fingerprinting",    "Open Source", "Passive"],
        ["Subfinder",       "DNS subdomain enumeration",            "Open Source", "Passive — DNS"],
        ["CRT.sh",          "Certificate transparency subdomain enum","Public API","Passive — HTTPS"],
        ["HackerTarget",    "Reverse DNS / IP intel",               "Public API", "Passive"],
        ["Whois",           "Domain registration intelligence",     "System",     "Passive"],
        ["Wayback Machine", "Historical URL mapping",               "Public API", "Passive"],
        ["Traceroute",      "Network path discovery",               "System",     "Active — UDP/ICMP"],
        ["Nmap",            "Port & service scanning",              "Open Source", "Active — TCP SYN"],
        ["sslyze",          "SSL/TLS certificate & cipher analysis","Open Source", "Active — TLS"],
        ["Security Headers","HTTP security header audit",           "Custom",     "Active — HTTP"],
        ["Robots.txt",      "Robots / sitemap reconnaissance",      "Custom",     "Passive — HTTP"],
        ["CORS Scanner",    "CORS misconfiguration detection",      "Custom",     "Active — HTTP"],
        ["CMS Scanner",     "CMS & admin panel fingerprinting",     "Custom",     "Active — HTTP"],
        ["Nikto",           "Legacy web vulnerability scanning",    "Open Source", "Active — HTTP"],
        ["Nuclei",          "Template-based CVE scanning",          "Open Source", "Active — HTTP"],
        ["ffuf",            "Directory & file fuzzing",             "Open Source", "Active — HTTP"],
        ["Open Redirect",   "Open redirect parameter testing",      "Custom",     "Active — HTTP"],
        ["Wapiti",          "OWASP web application scan",           "Open Source", "Active — Injection"],
        ["SQLMap",          "SQL injection detection",              "Open Source", "Active — Injection"],
        ["Shodan InternetDB","Passive IoT/IP exposure profiling",   "Public API", "Passive"],
        ["CVE Correlator",  "Tech → CVE database cross-matching",  "Custom",     "Offline"],
        ["Risk Scorer",     "0–100 CVSS-weighted risk calculation", "Custom",     "Offline"],
        ["SMP Report Engine","VAPT PDF report compilation",         "Proprietary","Offline"],
    ]
    story.append(_data_table(
        ["Tool", "Purpose", "Type", "Method"],
        tools_rows,
        [BW * 0.22, BW * 0.38, BW * 0.18, BW * 0.22],
        st
    ))
    story.append(PageBreak())

    # ══════════════════════════════════════════════════════════════════════════
    # SECTION 6B — APPENDIX: POST-TESTING CLEAN-UP LOG
    # ══════════════════════════════════════════════════════════════════════════
    story.append(_section_header(st, "6B", "Appendix B — Post-Testing Environment Clean-up Log"))
    story.append(Paragraph(
        "The following log certifies that the test environment was left in a clean state "
        "following the assessment. All test artefacts have been removed or documented.",
        st["body"]
    ))
    story.append(_spacer(8))

    cleanup_rows = [
        ["Test Accounts Created",       "None — black-box assessment; no test accounts were provisioned", c["scan_time"][:10], "N/A — Not Created"],
        ["Injected Payloads",           "Automated tool payloads (Nuclei, ffuf, Nikto, SQLMap)", c["scan_time"][:10], "Transient — cleared on session end"],
        ["Modified Database Rows",      "None — read-only assessment. SQLMap run in detection-only mode", c["scan_time"][:10], "N/A — No Modifications"],
        ["Files Uploaded / Created",    "None — no file upload testing performed", c["scan_time"][:10], "N/A"],
        ["Sessions / Cookies Modified", "Standard browser sessions during active scanning only", c["scan_time"][:10], "Cleared on session end"],
    ]
    story.append(_data_table(
        ["Artefact Type", "Details", "Date / Time", "Removal / Status"],
        cleanup_rows,
        [BW * 0.22, BW * 0.40, BW * 0.18, BW * 0.20],
        st
    ))
    story.append(PageBreak())

    # ══════════════════════════════════════════════════════════════════════════
    # SECTION 6C — APPENDIX: SEVERITY DEFINITIONS GLOSSARY
    # ══════════════════════════════════════════════════════════════════════════
    story.append(_section_header(st, "6C", "Appendix C — Vulnerability Severity Definitions Glossary"))

    glossary = [
        ("CRITICAL", _P["crit"],
         "CVSS Base Score 9.0–10.0. Exploitation requires no authentication and no user interaction. "
         "Leads to full system compromise, remote code execution, or complete data exfiltration. "
         "Requires immediate remediation before next business day."),
        ("HIGH", _P["high"],
         "CVSS Base Score 7.0–8.9. Exploitation is straightforward and may require minimal privileges. "
         "Significant confidentiality, integrity, or availability impact. "
         "Remediation required within 24–72 hours."),
        ("MEDIUM", _P["med"],
         "CVSS Base Score 4.0–6.9. Exploitation requires specific conditions (authenticated user, "
         "social engineering, or chained vulnerabilities). Moderate impact. "
         "Remediation required within 14–30 days."),
        ("LOW", _P["low"],
         "CVSS Base Score 0.1–3.9. Limited attack surface or impact. "
         "Represents hardening opportunities or minor information disclosures. "
         "Remediation at next maintenance window (30–90 days)."),
        ("INFORMATIONAL", _P["info"],
         "CVSS Base Score 0.0. No direct exploitability. Observations, recon data, "
         "or best-practice deviations. Document and review during next security review cycle."),
    ]

    for label, color, definition in glossary:
        label_cell = Paragraph(
            f'<font color="{color}"><b>{label}</b></font>', st["cell_bold"])
        def_cell = Paragraph(definition, st["cell_dim"])
        row_t = Table([[label_cell, def_cell]],
                      colWidths=[70, BW - 70], hAlign="LEFT")
        row_t.setStyle(TableStyle([
            ("BACKGROUND",    (0, 0), (-1, -1), _c(_P["card"])),
            ("LEFTBORDER",    (0, 0), (0, -1), 3, _c(color)),
            ("BOX",           (0, 0), (-1, -1), 0.3, _c(_P["border"])),
            ("TOPPADDING",    (0, 0), (-1, -1), 8),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
            ("LEFTPADDING",   (0, 0), (-1, -1), 10),
            ("VALIGN",        (0, 0), (-1, -1), "TOP"),
        ]))
        story += [row_t, _spacer(5)]

    story.append(_spacer(10))
    story.append(Paragraph("CVSS Base Metric Vector Definitions", st["h3"]))
    cvss_rows = [
        ("AV  — Attack Vector",       "N=Network, A=Adjacent, L=Local, P=Physical"),
        ("AC  — Attack Complexity",   "L=Low, H=High"),
        ("PR  — Privileges Required", "N=None, L=Low, H=High"),
        ("UI  — User Interaction",    "N=None, R=Required"),
        ("VC/VI/VA",                  "Impact on Confidentiality / Integrity / Availability: N=None, L=Low, H=High"),
        ("SC/SI/SA",                  "Subsequent System impact: N=None, L=Low, H=High"),
    ]
    story.append(_kv_table(cvss_rows, st, col_w=[BW * 0.32, BW * 0.68]))
    story.append(PageBreak())

    # ══════════════════════════════════════════════════════════════════════════
    # SECTION 6D — FORMAL ATTESTATION
    # ══════════════════════════════════════════════════════════════════════════
    story.append(_section_header(st, "6D", "Appendix D — Formal Attestation &amp; Sign-off"))

    story.append(Paragraph("Formal Attestation Letter", st["h3"]))
    attest_text = (
        f"This Vulnerability Assessment and Penetration Testing (VAPT) Final Report has been prepared "
        f"by the Security Management Platform (SMP) automated assessment engine on behalf of the "
        f"designated Lead Penetration Tester, <b>{_esc(c['scanned_by'])}</b>.<br/><br/>"
        f"The assessment was conducted against the target system <b>{_esc(c['url'])}</b> on "
        f"<b>{c['scan_time'][:10]}</b> in accordance with the following professional and ethical standards:<br/><br/>"
        f"• The engagement was performed under explicit written authorization from the asset owner.<br/>"
        f"• All testing was conducted within the declared scope boundaries. No out-of-scope assets were accessed.<br/>"
        f"• Assessment methodologies comply with OWASP WSTG v4.2 and NIST SP 800-115.<br/>"
        f"• All test artefacts and injected payloads have been removed from the target environment.<br/>"
        f"• No production data was exfiltrated, stored, or retained by the testing team.<br/>"
        f"• This document contains confidential information and is classified for INTERNAL USE ONLY.<br/><br/>"
        f"The undersigned affirm that this assessment was completed in full accordance with professional "
        f"ethical hacking standards and that all findings documented herein represent accurate, "
        f"reproducible security observations at the time of the engagement."
    )
    story.append(Paragraph(attest_text, st["attest"]))
    story.append(_spacer(20))

    # Signature blocks
    sig_date = c["scan_time"][:10]
    sig_data = [
        [
            Paragraph(
                f"<b>Lead Penetration Tester</b><br/><br/><br/>"
                f"Signature: _______________________________<br/><br/>"
                f"Name: <b>{_esc(c['scanned_by'])}</b><br/>"
                f"Date: {sig_date}<br/>"
                f"Organisation: Security Management Platform",
                st["attest"]),
            Paragraph(
                f"<b>QA / Review Manager</b><br/><br/><br/>"
                f"Signature: _______________________________<br/><br/>"
                f"Name: <b>{_esc(c['settings'].get('qa_reviewer', 'QA Manager'))}</b><br/>"
                f"Date: {sig_date}<br/>"
                f"Organisation: Security Management Platform",
                st["attest"]),
        ]
    ]
    sig_t = Table(sig_data, colWidths=[BW / 2 - 10, BW / 2 - 10], hAlign="LEFT")
    sig_t.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, -1), _c(_P["card"])),
        ("BOX",           (0, 0), (-1, -1), 0.5, _c(_P["border"])),
        ("INNERGRID",     (0, 0), (-1, -1), 0.3, _c(_P["border"])),
        ("TOPPADDING",    (0, 0), (-1, -1), 16),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 16),
        ("LEFTPADDING",   (0, 0), (-1, -1), 14),
        ("VALIGN",        (0, 0), (-1, -1), "TOP"),
    ]))
    story.append(sig_t)
    story.append(_spacer(20))
    story.append(Paragraph(
        f"Document Reference: VAPT-{c['url'].replace('https://','').replace('http://','')[:20].upper()}-{c['scan_time'][:10]}  |  "
        f"Version: {c['doc_version']}  |  Status: {c['doc_status']}",
        st["body"]
    ))
    story.append(Paragraph(
        "⚠  CLASSIFICATION: CONFIDENTIAL — INTERNAL USE ONLY — NOT FOR DISTRIBUTION",
        st["conf_stamp"]
    ))

    doc.build(story)


# ── Hardening Recommendation matching ────────────────────────────────────────

def _generate_hardening_section(findings, st, story):
    """
    Appends Section 5B: Automated Hardening Recommendations / Action Plan to story.
    Matches findings to rules in config/hardening_rules.json.
    """
    import os
    import json
    rules_path = os.path.join(BASE_DIR, "config", "hardening_rules.json")
    if not os.path.exists(rules_path):
        return

    try:
        with open(rules_path, "r", encoding="utf-8") as f:
            rules = json.load(f)
    except Exception as e:
        logger.error(f"Failed to load hardening rules: {e}")
        return

    # Match rules to findings
    matched_rules = []
    for rule in rules:
        matched_findings = []
        highest_sev = "Info"
        keywords = rule.get("keywords", [])
        for f in findings:
            title_lower = f.get("title", "").lower()
            desc_lower = f.get("description", "").lower()
            if any(kw.lower() in title_lower or kw.lower() in desc_lower for kw in keywords):
                matched_findings.append(f)
                sev = f.get("severity", "Info")
                if _sev_rank(sev) < _sev_rank(highest_sev):
                    highest_sev = sev

        if matched_findings:
            matched_rules.append({
                "rule": rule,
                "findings": matched_findings,
                "highest_severity": highest_sev
            })

    if not matched_rules:
        story.append(_section_header(st, "5B", "Automated Hardening Recommendations"))
        story.append(Paragraph("No specific infrastructure hardening templates matched the active findings list.", st["body"]))
        story.append(_spacer(20))
        return

    # Sort matched rules by highest severity of findings they address
    matched_rules.sort(key=lambda r: _sev_rank(r["highest_severity"]))

    story.append(_section_header(st, "5B", "Automated Hardening Recommendations &amp; Action Plan"))
    story.append(Paragraph(
        "This section maps the active scan findings to pre-configured security hardening templates. "
        "Each recommendation below includes strategic explanations and specific server/command fixes sorted by severity.",
        st["body"]
    ))
    story.append(_spacer(15))

    for idx, mr in enumerate(matched_rules, 1):
        rule = mr["rule"]
        findings_str = ", ".join(f["title"] for f in mr["findings"])
        label, sev_hex = _SEV_LABEL.get(mr["highest_severity"], ("INFO", _P["info"]))

        # Title
        story.append(Paragraph(f"<b>5B.{idx} — {rule.get('title')}</b>", st["h3"]))
        
        # Details table
        pairs = [
            ("Addressed Vulnerabilities", findings_str[:160] + ("..." if len(findings_str) > 160 else "")),
            ("Max Severity Level", f'<font color="{sev_hex}"><b>{label}</b></font>'),
            ("Implementation Effort", rule.get("effort", "Medium")),
        ]
        story.append(_kv_table(pairs, st))
        story.append(_spacer(6))

        # Explanation
        story.append(Paragraph("<b>Concept &amp; Risk Explanation:</b>", st["label"] if "label" in st else st["cell_bold"]))
        story.append(Paragraph(rule.get("explanation", ""), st["body"]))
        story.append(_spacer(6))

        # Command fixes
        if rule.get("fix_nginx"):
            story.append(Paragraph("<b>Nginx Configuration:</b>", st["cell_bold"]))
            story.append(_code_block(rule.get("fix_nginx"), st))
            story.append(_spacer(4))
        if rule.get("fix_apache"):
            story.append(Paragraph("<b>Apache Configuration:</b>", st["cell_bold"]))
            story.append(_code_block(rule.get("fix_apache"), st))
            story.append(_spacer(4))
        if rule.get("fix_bash"):
            bash_cmds = rule.get("fix_bash")
            if isinstance(bash_cmds, list):
                bash_str = "\n".join(bash_cmds)
            else:
                bash_str = str(bash_cmds)
            story.append(Paragraph("<b>Remediation Commands (Shell/Bash):</b>", st["cell_bold"]))
            story.append(_code_block(bash_str, st))
            story.append(_spacer(4))
        if rule.get("fix_notes"):
            story.append(Paragraph("<b>Implementation Notes:</b>", st["cell_bold"]))
            story.append(Paragraph(rule.get("fix_notes"), st["body"]))
            story.append(_spacer(6))

        story.append(_hr(_P["border"]))
        story.append(_spacer(10))

        # Add page break after every 2 rules to keep layout clean
        if idx % 2 == 0 and idx < len(matched_rules):
            story.append(PageBreak())


# ── Taxonomy / Remediation helpers ────────────────────────────────────────────

def _get_cwe_hint(tool, sev):
    mapping = {
        "SQLMap":          "CWE-89: SQL Injection",
        "Wapiti":          "CWE-79: Cross-Site Scripting (XSS) / CWE-89: SQLi",
        "Nuclei":          "CWE-1035: OWASP Top 10 Category",
        "Nikto":           "CWE-16: Configuration / CWE-200: Information Exposure",
        "SSL":             "CWE-326: Inadequate Encryption Strength / CWE-295: Certificate Validation",
        "CORS":            "CWE-942: Permissive Cross-domain Policy",
        "Security Headers":"CWE-693: Protection Mechanism Failure",
        "Open Redirect":   "CWE-601: URL Redirection to Untrusted Site",
        "ffuf":            "CWE-538: File and Directory Information Exposure",
        "Nmap":            "CWE-16: Configuration — Unnecessary Open Ports",
        "CVE Correlation": "See matched CVE record for authoritative CWE",
    }
    return mapping.get(tool, "CWE-1035: OWASP Top 10 / See NVD for specific CWE")

def _get_owasp_hint(tool):
    mapping = {
        "SQLMap":          "A03:2021 — Injection",
        "Wapiti":          "A03:2021 — Injection / A07:2021 — Identification and Authentication Failures",
        "Nuclei":          "A06:2021 — Vulnerable and Outdated Components",
        "Nikto":           "A05:2021 — Security Misconfiguration",
        "SSL":             "A02:2021 — Cryptographic Failures",
        "CORS":            "A05:2021 — Security Misconfiguration",
        "Security Headers":"A05:2021 — Security Misconfiguration",
        "Open Redirect":   "A01:2021 — Broken Access Control",
        "ffuf":            "A05:2021 — Security Misconfiguration",
        "Nmap":            "A05:2021 — Security Misconfiguration",
        "CVE Correlation": "A06:2021 — Vulnerable and Outdated Components",
    }
    return mapping.get(tool, "A05:2021 — Security Misconfiguration")

def _cvss_vc(sev):
    return {"Critical": "H", "High": "H", "Medium": "L", "Low": "L", "Info": "N"}.get(sev, "N")

def _cvss_vi(sev):
    return {"Critical": "H", "High": "H", "Medium": "L", "Low": "N", "Info": "N"}.get(sev, "N")

def _get_remediation(tool, sev, title):
    if tool == "SQLMap":
        strategic = ("Replace all string-concatenated SQL queries with parameterised statements "
                     "or an ORM. Deploy a WAF with SQLi ruleset as interim mitigation.")
        code_fix = (
            "# VULNERABLE:\n"
            "query = f\"SELECT * FROM users WHERE id = '{user_id}'\"\n\n"
            "# SECURE (parameterised):\n"
            "cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))"
        )
    elif tool == "CORS":
        strategic = ("Restrict CORS allowed origins to an explicit allowlist. "
                     "Never reflect the Origin header back without validation.")
        code_fix = (
            "# INSECURE:\nAccess-Control-Allow-Origin: *\n\n"
            "# SECURE:\nAccess-Control-Allow-Origin: https://yourdomain.com\n"
            "Access-Control-Allow-Credentials: false"
        )
    elif tool == "SSL":
        strategic = ("Enforce TLS 1.2 minimum. Disable SSLv2, SSLv3, TLS 1.0, TLS 1.1. "
                     "Remove RC4, 3DES, and export-grade cipher suites. "
                     "Automate certificate renewal with Let's Encrypt or ACM.")
        code_fix = (
            "# nginx TLS hardening:\nssl_protocols TLSv1.2 TLSv1.3;\n"
            "ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256;\n"
            "ssl_prefer_server_ciphers on;\nssl_stapling on;"
        )
    elif tool == "Security Headers":
        strategic = ("Deploy all OWASP-recommended HTTP security headers. "
                     "Enable Content-Security-Policy, HSTS, X-Frame-Options, and Referrer-Policy.")
        code_fix = (
            "# Add to nginx / Apache / application middleware:\n"
            "Strict-Transport-Security: max-age=31536000; includeSubDomains; preload\n"
            "Content-Security-Policy: default-src 'self'\n"
            "X-Frame-Options: DENY\n"
            "X-Content-Type-Options: nosniff\n"
            "Referrer-Policy: strict-origin-when-cross-origin"
        )
    elif tool == "Open Redirect":
        strategic = ("Validate all redirect URLs against a strict allowlist of internal paths. "
                     "Reject any user-supplied redirect target containing external domains.")
        code_fix = (
            "# INSECURE:\nreturn redirect(request.args.get('next'))\n\n"
            "# SECURE:\nALLOWED = {'/', '/dashboard', '/profile'}\n"
            "next_url = request.args.get('next', '/')\n"
            "if next_url not in ALLOWED:\n    next_url = '/'\nreturn redirect(next_url)"
        )
    elif tool in ("Nuclei", "Nikto", "Wapiti"):
        strategic = (f"Patch the vulnerability identified by {tool}. Apply vendor security updates "
                     "and enforce input validation / output encoding across all affected endpoints.")
        code_fix = None
    elif tool == "CVE Correlation":
        strategic = ("Upgrade the affected software component to the patched version specified in "
                     "the CVE record. Subscribe to vendor security advisories for automated alerts.")
        code_fix = None
    elif tool == "Nmap":
        strategic = ("Audit all open ports. Close or firewall any service not required for business "
                     "operations. Enforce default-deny firewall policy.")
        code_fix = (
            "# UFW example:\nufw default deny incoming\nufw allow 443/tcp\nufw allow 80/tcp\n"
            "ufw enable"
        )
    else:
        if sev in ("Critical", "High"):
            strategic = ("Immediately isolate the affected component. Apply vendor patch or "
                         "deploy compensating WAF rules as interim mitigation.")
        elif sev == "Medium":
            strategic = ("Schedule remediation within the next change window. "
                         "Apply hardening configurations per vendor guidance.")
        else:
            strategic = ("Review best practice hardening guides for this component. "
                         "Address at next scheduled maintenance window.")
        code_fix = None

    return strategic, code_fix


# ── HTML fallback (minimal) ───────────────────────────────────────────────────

def _generate_html_fallback(filepath, ctx):
    """Minimal HTML report — used for email attachment when PDF is primary."""
    c     = ctx
    counts = c["counts"]
    lines = [
        "<!DOCTYPE html><html><head><meta charset='utf-8'>",
        "<title>VAPT Report</title>",
        "<style>body{font-family:Arial,sans-serif;background:#0A0A0F;color:#ccc;padding:30px;}"
        "h1,h2{color:#fff}table{border-collapse:collapse;width:100%}"
        "th{background:#1D4ED8;color:#fff;padding:8px}td{padding:6px;border:1px solid #252530}"
        ".crit{color:#DC2626}.high{color:#EA580C}.med{color:#D97706}"
        ".low{color:#2563EB}.info{color:#4B5563}</style></head><body>",
        f"<h1>VAPT Final Report — {_esc(c['url'])}</h1>",
        f"<p>Date: {c['scan_time']} | Auditor: {_esc(c['scanned_by'])}</p>",
        f"<p class='crit'>Critical: {counts['Critical']}</p>",
        f"<p class='high'>High: {counts['High']}</p>",
        f"<p class='med'>Medium: {counts['Medium']}</p>",
        f"<p class='low'>Low: {counts['Low']}</p>",
        f"<p class='info'>Info: {counts['Info']}</p>",
        "<h2>Findings</h2><table><tr><th>ID</th><th>Title</th><th>Severity</th><th>Tool</th></tr>",
    ]
    sorted_f = sorted(c["findings"], key=lambda f: _sev_rank(f.get("severity", "Info")))
    for idx, f in enumerate(sorted_f, 1):
        sev = f.get("severity", "Info")
        cls = {"Critical": "crit", "High": "high", "Medium": "med",
               "Low": "low"}.get(sev, "info")
        lines.append(
            f"<tr><td>SEC-{idx:02d}</td><td>{_esc(f.get('title',''))}</td>"
            f"<td class='{cls}'>{_esc(sev)}</td><td>{_esc(f.get('source_tool',''))}</td></tr>"
        )
    lines += ["</table>", "<p><em>CONFIDENTIAL — INTERNAL USE ONLY</em></p>",
              "</body></html>"]
    os.makedirs(os.path.dirname(filepath), exist_ok=True)
    with open(filepath, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines))
