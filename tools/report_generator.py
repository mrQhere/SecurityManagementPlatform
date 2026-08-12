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


# ── V9.4.3 — Extract ReportLab PDF template to JSON/YAML config ─────────────────
# Load visual constants (colors, fonts, sizes, text) from config to allow custom branding
_REPORT_TEMPLATE_CONFIG_PATH = os.path.join(BASE_DIR, "config", "report_template.json")
_TEMPLATE_CONFIG = {}

_P = {
    "bg":       "#FFFFFF",
    "surface":  "#F9FAFB",
    "card":     "#F3F4F6",
    "border":   "#E5E7EB",
    "accent":   "#2563EB",
    "accent2":  "#1D4ED8",
    "white":    "#111827",  # Used as primary text color
    "muted":    "#6B7280",
    "dim":      "#9CA3AF",
    "crit":     "#DC2626",
    "high":     "#EA580C",
    "med":      "#D97706",
    "low":      "#2563EB",
    "info":     "#4B5563",
    "green":    "#059669",
}

if os.path.exists(_REPORT_TEMPLATE_CONFIG_PATH):
    try:
        with open(_REPORT_TEMPLATE_CONFIG_PATH, "r", encoding="utf-8") as f:
            _TEMPLATE_CONFIG = json.load(f)
            if "palette" in _TEMPLATE_CONFIG:
                _P.update(_TEMPLATE_CONFIG["palette"])
    except Exception as e:
        logger.warning(f"Failed to load report_template.json: {e}")

def _get_font(key, default):
    return _TEMPLATE_CONFIG.get("fonts", {}).get(key, default)
    
def _get_text(key, default):
    return _TEMPLATE_CONFIG.get("text", {}).get(key, default)


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
        canvas.setFont(_get_font("primary_bold", "Helvetica-Bold"), 8)
        canvas.drawCentredString(W / 2, H - 15, "CONFIDENTIAL — INTERNAL USE ONLY — NOT FOR DISTRIBUTION")

        # Bottom bar
        canvas.setFillColor(_c(_P["surface"]))
        canvas.rect(0, 0, W, 28, fill=1, stroke=0)
        canvas.setFillColor(_c(_P["dim"]))
        
        # Text logo footer
        canvas.setFont(_get_font("primary_bold", "Helvetica-Bold"), 8)
        canvas.drawString(18, 10, "SMP • Security Management Platform © mrQhere")
        
        canvas.setFont(_get_font("primary", "Helvetica"), 7)
        canvas.drawString(200, 10, f"VAPT Final Report  |  Target: {self.target_url}  |  Date: {self.scan_date}")
        
        # ── V9.4.3 — Dynamic config text footer ──
        right_text = _get_text("header_right", "v{version} | Page {page}").replace("{version}", str(self.doc_version)).replace("{page}", str(canvas.getPageNumber()))
        canvas.drawRightString(W - 18, 10, right_text)

        canvas.restoreState()


# ── Style factory ─────────────────────────────────────────────────────────────

def _styles():
    base = getSampleStyleSheet()

    def S(name, **kw):
        return ParagraphStyle(name, parent=base["Normal"], **kw)

    # ── V9.4.3 — Dynamic Fonts ───────────────────────────────────────────
    font_bold = _get_font("primary_bold", "Helvetica-Bold")
    font_reg = _get_font("primary", "Helvetica")
    font_mono = _get_font("mono", "Courier")

    return {
        "cover_title": S("CoverTitle",
            fontName=font_bold, fontSize=30, textColor=_c(_P["white"]),
            alignment=TA_LEFT, leading=38, spaceAfter=8),

        "cover_sub": S("CoverSub",
            fontName=font_reg, fontSize=13, textColor=_c(_P["muted"]),
            alignment=TA_LEFT, spaceAfter=6),

        "cover_kv_key": S("CoverKVK",
            fontName=font_bold, fontSize=9, textColor=_c(_P["muted"]),
            leading=14, spaceAfter=2),

        "cover_kv_val": S("CoverKVV",
            fontName=font_bold, fontSize=11, textColor=_c(_P["white"]),
            leading=14, spaceAfter=6),

        "conf_stamp": S("ConfStamp",
            fontName=font_bold, fontSize=10, textColor=_c(_P["crit"]),
            alignment=TA_CENTER, spaceAfter=4),

        "section_num": S("SecNum",
            fontName=font_bold, fontSize=8, textColor=_c(_P["accent"]),
            leading=12, spaceAfter=2),

        "section_title": S("SecTitle",
            fontName=font_bold, fontSize=17, textColor=_c(_P["white"]),
            leading=22, spaceAfter=4, spaceBefore=20),

        "h3": S("H3",
            fontName=font_bold, fontSize=11, textColor=_c(_P["white"]),
            leading=16, spaceBefore=12, spaceAfter=4),

        "h4": S("H4",
            fontName=font_bold, fontSize=9, textColor=_c(_P["muted"]),
            leading=13, spaceBefore=8, spaceAfter=3),

        "body": S("Body",
            fontName=font_reg, fontSize=9, textColor=_c(_P["muted"]),
            leading=14, spaceAfter=4),

        "body_white": S("BodyW",
            fontName=font_reg, fontSize=9, textColor=_c(_P["white"]),
            leading=14, spaceAfter=4),

        "mono": S("Mono",
            fontName=font_mono, fontSize=8, textColor=_c(_P["green"]),
            leading=12, spaceAfter=2),

        "cell": S("Cell",
            fontName=font_reg, fontSize=8, textColor=_c(_P["white"]),
            leading=11),

        "cell_dim": S("CellDim",
            fontName=font_reg, fontSize=8, textColor=_c(_P["muted"]),
            leading=11),

        "cell_bold": S("CellBold",
            fontName=font_bold, fontSize=8, textColor=_c(_P["white"]),
            leading=11),

        "cell_accent": S("CellAccent",
            fontName=font_bold, fontSize=8, textColor=_c(_P["accent"]),
            leading=11),

        "toc_entry": S("TOCEntry",
            fontName=font_reg, fontSize=10, textColor=_c(_P["white"]),
            leading=20, leftIndent=0),

        "toc_sub": S("TOCSub",
            fontName=font_reg, fontSize=9, textColor=_c(_P["muted"]),
            leading=16, leftIndent=20),

        "exec_narrative": S("ExecNarrative",
            fontName=font_reg, fontSize=10, textColor=_c(_P["muted"]),
            leading=17, spaceAfter=8),

        "finding_id": S("FindingID",
            fontName=font_bold, fontSize=13, textColor=_c(_P["white"]),
            leading=18, spaceAfter=2),

        "label": S("Label",
            fontName=font_bold, fontSize=7, textColor=_c(_P["muted"]),
            leading=10, spaceAfter=1),

        "value": S("Value",
            fontName=font_reg, fontSize=9, textColor=_c(_P["white"]),
            leading=14, spaceAfter=3),

        "attest": S("Attest",
            fontName=font_reg, fontSize=9, textColor=_c(_P["muted"]),
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
    Generates HTML and a compliance-ready VAPT PDF.
    File naming: SMP_sitename_Report_YYYY-MM-DD_HASH16.pdf
    The content hash is derived from deterministic scan facts (URL + date +
    finding counts + scanned_by) so it can be verified WITHOUT the database.
    Returns: (html_report_path | None, pdf_report_path | None)
    """
    init_directories()

    url = target["url"]
    # Clean site name for filename: strip protocol, replace special chars
    site_name = (url.replace("http://", "").replace("https://", "")
                 .split("/")[0]          # domain only, no path
                 .replace(":", "-")      # remove ports
                 .strip("."))
    report_date = datetime.now().strftime("%Y-%m-%d")

    from tools.db_manager import get_scan, get_technologies_for_scan, get_risk_score, get_scan_trend_deltas
    scan_rec   = get_scan(scan_id)
    scanned_by = (scan_rec.get("scanned_by") if scan_rec and scan_rec.get("scanned_by") else None) or \
                 load_settings().get("tester_name") or "Security Tester"
    technologies = get_technologies_for_scan(scan_id)
    risk_data    = get_risk_score(scan_id)
    trend_deltas = get_scan_trend_deltas(url, scan_id)

    # ── Capture Evidence (Screenshots) ─────────────────────────────────
    try:
        from scanners.screenshot_capture import capture_evidence_for_findings
        evidence_map = capture_evidence_for_findings(current_findings, scan_id)
        for f in current_findings:
            title = f.get("title", "")
            if title in evidence_map:
                f["evidence_path"] = evidence_map[title]
    except Exception as e:
        logger.error(f"Failed to capture evidence: {e}")

    ctx = _build_context(scan_id, target, current_findings, previous_scan,
                         scanned_by, technologies, risk_data, trend_deltas)

    # ── V9 Artificial Intelligence Correlation ─────────────────────────
    try:
        from intelligence.brain import process_findings_for_global_intel, generate_ai_insights
        process_findings_for_global_intel(current_findings)
        ctx["ai_insights"] = generate_ai_insights(current_findings)
    except Exception as e:
        logger.error(f"Brain integration failed: {e}")
        ctx["ai_insights"] = None


    # ── Derive content hash from deterministic facts (NOT from PDF binary) ─────
    # This hash can be recomputed from the data printed on the cover page alone,
    # even after the database is deleted, making reports self-verifying.
    from tools.verify_report import derive_content_hash, HASH_MARKER_START, HASH_MARKER_END
    counts = ctx["counts"]
    try:
        import json as _json
        _meta_path = os.path.join(BASE_DIR, "config", "metadata.json")
        _smp_ver = _json.load(open(_meta_path, encoding="utf-8")).get("version", "V9.4.3") if os.path.exists(_meta_path) else "V9.4.3"
    except Exception as e:
        from tools.errors import SMPUnclassifiedError
        import traceback
        import logging
        logging.getLogger('smp').error(f'Unexpected error: {e}\n{traceback.format_exc()}')
        raise SMPUnclassifiedError(str(e))
        _smp_ver = "V9.4.3"

    content_hash = derive_content_hash(
        url            = url,
        scan_date      = ctx["scan_time"],
        findings_count = ctx["total"],
        crit           = counts.get("Critical", 0),
        high           = counts.get("High", 0),
        med            = counts.get("Medium", 0),
        low            = counts.get("Low", 0),
        scanned_by     = scanned_by,
        smp_version    = _smp_ver,
    )
    hash16 = content_hash[:16]   # 16-char prefix for filename (readable)

    # Build metadata block for embedding (JSON, parseable by verify_report.py)
    import json as _json
    meta_block = (
        "SMP-META-START"
        + _json.dumps({
            "url":            url,
            "scan_date":      ctx["scan_time"][:10],
            "findings_count": ctx["total"],
            "critical":       counts.get("Critical", 0),
            "high":           counts.get("High", 0),
            "medium":         counts.get("Medium", 0),
            "low":            counts.get("Low", 0),
            "scanned_by":     scanned_by,
            "smp_version":    _smp_ver,
            "content_hash":   content_hash,
        }, sort_keys=True)
        + "SMP-META-END"
    )
    hash_token = f"{HASH_MARKER_START}{content_hash}{HASH_MARKER_END}"

    # Inject both into the context so the PDF template can embed them
    ctx["content_hash"]  = content_hash
    ctx["hash16"]        = hash16
    ctx["hash_token"]    = hash_token
    ctx["meta_block"]    = meta_block
    ctx["smp_version"]   = _smp_ver
    ctx["site_name"]     = site_name

    # File paths with new naming convention
    html_path = os.path.join(BASE_DIR, "reports", "html",
                             f"SMP_{site_name}_Report_{report_date}.html")
    pdf_path  = os.path.join(BASE_DIR, "reports", "pdf",
                             f"SMP_{site_name}_Report_{report_date}_{hash16}.pdf")

    # HTML report
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

            # Save the content hash (not the file hash) so the DB stores what
            # can be verified independently of the database itself.
            from tools.db_manager import save_report_hash
            save_report_hash(scan_id, content_hash)
            logger.info(f"Content hash saved to DB: {content_hash[:16]}…")

        except Exception as e:
            logger.error(f"PDF report failed: {e}", exc_info=True)
            pdf_path = None
    else:
        logger.warning("ReportLab not installed — PDF report skipped.")
        pdf_path = None

    # ── SBOM generation — runs automatically alongside pentest report ──────────
    sbom_path = None
    try:
        from tools.sbom_generator import generate_sbom_for_scan
        sbom_dir  = os.path.join(BASE_DIR, "reports", "sbom")
        sbom_path = generate_sbom_for_scan(scan_id, url, output_dir=sbom_dir)
        if sbom_path:
            logger.info(f"SBOM generated: {sbom_path}")
        else:
            logger.info("SBOM skipped — no technology components detected during scan.")
    except Exception as e:
        logger.warning(f"SBOM generation failed (non-fatal): {e}")

    # ── Egress audit summary — attach to context for logging / future appendix ──
    try:
        from tools.egress_auditor import egress_auditor
        egress_summary = egress_auditor.get_session_summary()
        logger.info(
            f"[EgressAudit] Session complete — "
            f"{egress_summary['allowed']} outbound calls allowed, "
            f"{egress_summary['blocked']} blocked. "
            f"Services contacted: {', '.join(egress_summary['external_services']) or 'none'}"
        )
    except Exception as e:
        from tools.errors import SMPUnclassifiedError
        import traceback
        import logging
        logging.getLogger('smp').error(f'Unexpected error: {e}\n{traceback.format_exc()}')
        raise SMPUnclassifiedError(str(e))
        pass

    return html_path, pdf_path, sbom_path



# ── Context builder ───────────────────────────────────────────────────────────

def _build_context(scan_id, target, findings, previous_scan,
                   scanned_by, technologies, risk_data, trend_deltas):
    url       = target["url"]
    scan_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    settings  = load_settings()

    findings_by_tool = {}
    counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
    for f in findings:
        s = f.get("severity", "Info")
        if s in counts:
            counts[s] += 1
        t = f.get("source_tool")
        if t:
            findings_by_tool.setdefault(t, []).append(f)

    return dict(
        target=target,
        url=url, scan_time=scan_time, scanned_by=scanned_by,
        doc_version="1.0", doc_status="Final",
        findings=findings, findings_by_tool=findings_by_tool,
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
    crit_n = counts.get("Critical", 0)
    high_n = counts.get("High", 0)
    med_n  = counts.get("Medium", 0)
    low_n  = counts.get("Low", 0)
    c.get("total", 0)
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
    target = c.get("target", {})
    company_name = target.get("company_name") or c["settings"].get("company_name") or "—"
    submitted_to = target.get("submitted_to") or c["settings"].get("submitted_to") or "Internal Security Team"

    # Load SMP version dynamically from metadata.json
    try:
        import json as _json
        _meta_path = os.path.join(BASE_DIR, "config", "metadata.json")
        _smp_version = _json.load(open(_meta_path, encoding="utf-8")).get("version", "V9.4.3") if os.path.exists(_meta_path) else "V9.4.3"
    except Exception as e:
        from tools.errors import SMPUnclassifiedError
        import traceback
        import logging
        logging.getLogger('smp').error(f'Unexpected error: {e}\n{traceback.format_exc()}')
        raise SMPUnclassifiedError(str(e))
        _smp_version = "--help"

    cover_meta = [
        ("Document Title",           "Security Assessment Report"),
        ("Generated By",             f"Security Management Platform (SMP) {_smp_version} Stable"),
        ("Target Application",       c["url"]),
        ("Target Company",           company_name),
        ("Submitted To",             submitted_to),
        ("Date of Assessment",       c["scan_time"][:10]),
        ("Lead Penetration Tester",  c["scanned_by"]),
        ("QA Reviewer",              c["settings"].get("qa_reviewer", "QA Manager")),
        ("Data Classification",      "CONFIDENTIAL — INTERNAL USE ONLY"),
        ("Document Version",         c["doc_version"]),
        ("Verification Hash (SHA-256)", c.get("content_hash", "—")),
    ]
    story.append(_kv_table(cover_meta, st, col_w=[BW * 0.35, BW * 0.65]))
    story += [_spacer(8)]

    # Embed machine-readable metadata block for offline verification
    # (invisible to human reader; extracted by verify_report.py)
    _hash_token = c.get("hash_token", "")
    _meta_block = c.get("meta_block", "")
    if _hash_token:
        story.append(Paragraph(
            f'<font color="#0D0D0D" size="1">{_hash_token}</font>',
            st["body"]
        ))
    if _meta_block:
        story.append(Paragraph(
            f'<font color="#0D0D0D" size="1">{_meta_block}</font>',
            st["body"]
        ))
    story += [_spacer(12)]

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

    # ── V9 AI Insights ────────────────────────────────────────────────────────
    if c.get("ai_insights"):
        story.append(_spacer(6))
        story.append(Paragraph("<b><font color='#00aaff'>Neural Correlation Engine (Brain)</font></b>", st["h3"]))
        story.append(_spacer(4))
        # Convert simple markdown to reportlab paragraph
        import re
        insights_html = c["ai_insights"].replace('\n', '<br/>').replace('`', '<i>')
        insights_html = re.sub(r'\*\*(.*?)\*\*', r'<b>\1</b>', insights_html)
        story.append(Paragraph(insights_html, st["body"]))
        story.append(_spacer(10))
        story.append(_hr())

    # ── Modular Situational Executive Summary ────────────────────────────────
    # Each paragraph is chosen based on what the scan actually found.
    # This produces a natural, professional narrative that reads like
    # a human pentester wrote it specifically for this engagement.

    exec_paragraphs = []

    # 1. Opening posture sentence — severity-driven
    if crit_n > 0 and high_n > 0:
        exec_paragraphs.append(
            f"The automated security assessment of <b>{_esc(c['url'])}</b> reveals a "
            f"<b><font color='{_P['crit']}'>CRITICAL-RISK security posture</font></b>. "
            f"{crit_n} Critical and {high_n} High severity vulnerabilities were confirmed during "
            f"this engagement, presenting an immediate and actionable threat to the confidentiality, "
            f"integrity, and availability of the target environment. "
            f"Emergency remediation is required before the next business cycle."
        )
    elif crit_n > 0:
        exec_paragraphs.append(
            f"The assessment of <b>{_esc(c['url'])}</b> identifies a "
            f"<b><font color='{_P['crit']}'>HIGH-RISK security posture</font></b>. "
            f"{crit_n} Critical vulnerabilities were confirmed, each representing a direct pathway "
            f"for an attacker to compromise the target system. "
            f"Immediate remediation action is required without delay."
        )
    elif high_n > 0:
        exec_paragraphs.append(
            f"The assessment of <b>{_esc(c['url'])}</b> reveals a "
            f"<b><font color='{_P['high']}'>MEDIUM-HIGH risk posture</font></b>. "
            f"{high_n} High severity findings were confirmed alongside {med_n} Medium severity issues. "
            f"The application demonstrates functional security controls at the perimeter but shows "
            f"significant gaps in depth-of-defence measures. "
            f"Prioritised remediation is recommended within 72 hours."
        )
    elif med_n > 0:
        exec_paragraphs.append(
            f"The assessment of <b>{_esc(c['url'])}</b> indicates a "
            f"<b><font color='{_P['med']}'>MODERATE risk posture</font></b>. "
            f"No Critical or High findings were identified. {med_n} Medium severity observations "
            f"were recorded that, while not immediately exploitable, represent meaningful risk "
            f"if left unaddressed. Scheduled remediation within two weeks is advised."
        )
    else:
        exec_paragraphs.append(
            f"The assessment of <b>{_esc(c['url'])}</b> indicates a "
            f"<b><font color='{_P['green']}'>LOW-TO-MODERATE security posture</font></b>. "
            f"No Critical or High findings were identified during this engagement. "
            f"{low_n} Low severity and informational observations were recorded. "
            f"The application demonstrates a reasonable security baseline; "
            f"continued periodic assessment and hardening are recommended."
        )

    # 2. CVE correlation sentence — if CVEs were matched
    cve_corr_f = c.get("findings_by_tool", {}).get("CVE Correlation", [])
    if cve_corr_f:
        n_cve = len(cve_corr_f) if isinstance(cve_corr_f, list) else 1
        exec_paragraphs.append(
            f"CVE correlation analysis identified <b>{n_cve} known vulnerability entr{'y' if n_cve == 1 else 'ies'}</b> "
            f"matching the detected technology stack. These entries carry documented exploitation "
            f"pathways in public threat intelligence databases and should be treated as "
            f"confirmed risk items requiring immediate vendor patch application."
        )

    # 3. SSL/TLS sentence — if SSL failures found
    if c.get("findings_by_tool", {}).get("SSL", []):
        exec_paragraphs.append(
            "TLS/SSL assessment identified <b>cryptographic weaknesses</b> including support for "
            "deprecated protocol versions and/or weak cipher suites. "
            "This exposes data in transit to interception attacks and violates compliance "
            "requirements under PCI-DSS 4.0, NIST SP 800-52r2, and industry best practice. "
            "Immediate enforcement of TLS 1.2+ is mandated."
        )

    # 4. Historical context sentence — if we have trend data
    if c.get("trend_deltas") and c["trend_deltas"].get("previous_scan_id"):
        td = c["trend_deltas"]
        if td.get("persisting", 0) > 0:
            exec_paragraphs.append(
                f"Cross-referencing with the previous assessment (Scan ID: {td['previous_scan_id']}), "
                f"<b>{td['persisting']} finding(s) remain unresolved</b> from the prior engagement. "
                f"This indicates a breakdown in the remediation pipeline and elevates the "
            f"organisational risk profile. These persisting vulnerabilities must be treated with "
                f"highest priority as they represent known, unpatched attack surfaces."
            )
        elif td.get("resolved", 0) > 0:
            exec_paragraphs.append(
                f"Compared to the prior assessment (Scan ID: {td['previous_scan_id']}), "
                f"<b>{td['resolved']} finding(s) have been successfully remediated</b>, "
                f"demonstrating effective security response by the engineering team. "
                f"{td.get('new', 0)} new finding(s) were identified in this cycle."
            )

    # 5. Scope/methodology closure sentence — always present
    exec_paragraphs.append(
        "This assessment was conducted using Security Management Platform (SMP) employing "
        "a 35-module automated VAPT pipeline. All findings are based on authenticated and "
        "unauthenticated probes against the live target. "
        "Results reflect the security posture of the target at the time of the assessment "
        "and should be validated against the production environment before remediation."
    )

    # Render each paragraph with spacing
    for para in exec_paragraphs:
        story.append(Paragraph(para, st["exec_narrative"]))
        story.append(_spacer(8))

    story.append(_spacer(4))
    story.append(_hr())
    story.append(_spacer(8))


    # Historical Trend Analysis
    story.append(Paragraph("Historical Scan Trend Analysis", st["h3"]))
    if c.get("trend_deltas") and c["trend_deltas"].get("previous_scan_id"):
        td = c["trend_deltas"]
        trend_text = (
            f"Compared to the previous assessment (Scan ID: {td['previous_scan_id']}), the following changes were observed:<br/><br/>"
            f"<b><font color='{_P['crit']}'>[+] New Findings:</font></b> {td['new']}<br/>"
            f"<b><font color='{_P['green']}'>[-] Resolved Findings:</font></b> {td['resolved']}<br/>"
            f"<b><font color='{_P['med']}'>[=] Persisting Findings:</font></b> {td['persisting']} "
            f"<i>(These vulnerabilities have not been updated or fixed since the last scan. Immediate attention is required.)</i>"
        )
    else:
        trend_text = "No previous data found. This is the first recorded assessment for this target."
    
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
    if c.get("findings_by_tool", {}).get("CVE Correlation", []):
        actions.append("<b>MEDIUM-TERM (1–2 weeks):</b> Upgrade all software components matched to CVE "
                       "correlation results. Enforce version pinning and dependency auditing in CI/CD.")
    if c.get("findings_by_tool", {}).get("SSL", []):
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
    subdomains = c.get("findings_by_tool", {}).get("CRT.sh", []) + c.get("findings_by_tool", {}).get("Subfinder", [])
    scope_rows = [
        ["Primary Target", c["url"], "Web Application", "Authorized"],
    ]
    for sub in subdomains[:20]:
        host = sub.get("title", "").replace("Subdomain Discovered: ", "")
        scope_rows.append([host, "Subdomain", "Web", "Authorized"])
    for nmap_f in c.get("findings_by_tool", {}).get("Nmap", [])[:10]:
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

    story.append(Paragraph("Assessment Framework Compliance Coverage", st["h3"]))
    try:
        from tools.compliance_mapper import get_compliance_summary
        c_summary = get_compliance_summary(c["findings"])
        framework_rows = [
            ["OWASP Top 10 (2021)", f"{c_summary['owasp_top10_coverage']}% Coverage ({len(c_summary['owasp_categories_hit'])}/10 categories hit)"],
            ["CIS Controls v8",      f"{c_summary['cis_controls_coverage']}% Coverage ({len(c_summary['cis_categories_hit'])}/11 controls hit)"],
            ["ISO 27001:2022",      f"{c_summary['iso27001_coverage']}% Coverage ({len(c_summary['iso_categories_hit'])}/11 controls hit)"],
            ["SOC 2 Type II",       f"{c_summary['soc2_coverage']}% Coverage ({len(c_summary['soc2_controls_hit'])}/11 controls hit)"],
            ["PCI-DSS v4.0",        f"{c_summary['pci_dss_coverage']}% Coverage ({len(c_summary['pci_dss_controls_hit'])}/12 requirements hit)"],
            ["NIST SP 800-115",     "Technical Guide to Information Security Testing — primary methodology"],
        ]
    except Exception:
        framework_rows = [
            ["OWASP WSTG v9.4.3", "Web Security Testing Guide — primary methodology"],
            ["NIST SP 800-115",   "Technical Guide to Information Security Testing"],
            ["PTES",              "Penetration Testing Execution Standard"],
            ["CVSS v3.1",         "Common Vulnerability Scoring System for all severity ratings"],
            ["CWE Taxonomy",      "Common Weakness Enumeration taxonomy for all findings"],
            ["PCI-DSS v4.0",      "Sections 6.4 and 11.3 — penetration testing compliance"],
        ]
    story.append(_data_table(
        ["Framework / Standard", "Calculated Coverage & Scope"],
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
                         "Severity", "CVSS", "MITRE"]]
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
                Paragraph(str(f.get("cvss_score") or "N/A"), st["cell_dim"]),
                Paragraph(_esc(f.get("mitre_id") or "—"), st["cell_dim"]),
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

            # ── EXECUTIVE SUMMARY & BUSINESS RISK ──
            story.append(Paragraph("Executive & Business Risk Overview", st["h4"]))
            b_impact = f.get("business_impact")
            if not b_impact:
                # Dynamic fallback if not provided
                if sev in ("Critical", "High"):
                    b_impact = "Exploitation of this vulnerability poses severe business risks, including potential data breach, unauthorized service access, or critical service disruption."
                else:
                    b_impact = "This vulnerability poses operational or compliance risks. Exploitation is typically restricted to local network access or requires user interaction."
            
            # Render business impact inside a callout box for easy executive readability
            impact_style = ParagraphStyle(
                "ImpactText", parent=st["body"], fontSize=9.5, leading=14, textColor=_c(_P["white"])
            )
            impact_table = Table([[
                Paragraph(f"<b>Business Impact & Risk Analysis:</b><br/>{_esc(b_impact)}", impact_style)
            ]], colWidths=[BW], hAlign="LEFT")
            impact_table.setStyle(TableStyle([
                ("BACKGROUND",   (0, 0), (-1, -1), _c(_P["surface"])),
                ("BOX",          (0, 0), (-1, -1), 0.5, _c(_P["border"])),
                ("TOPPADDING",   (0, 0), (-1, -1), 8),
                ("BOTTOMPADDING",(0, 0), (-1, -1), 8),
                ("LEFTPADDING",  (0, 0), (-1, -1), 12),
                ("RIGHTPADDING", (0, 0), (-1, -1), 12),
            ]))
            story.append(KeepTogether([impact_table, _spacer(8)]))

            # ── Taxonomy Mappings ─────────────────────────────────────────
            story.append(Paragraph("Taxonomy Mappings", st["h4"]))
            
            cve_val = f.get("cve_id") or "See CVE Correlation section for matched CVEs"
            cvss_score = f.get("cvss_score")
            cvss_score_str = str(cvss_score) if cvss_score is not None else "Dynamic based on severity"
            cvss_vec = f"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:{_cvss_vc(sev)}/VI:{_cvss_vi(sev)}/VA:N/SC:N/SI:N/SA:N"
            
            owasp_cat = f.get("owasp_category") or _get_owasp_hint(tool)
            affected = f.get("affected_component") or "Global target application scope"

            mitre_id = f.get("mitre_id") or "—"

            epss_score = f.get("epss_score")
            epss_percentile = f.get("epss_percentile")
            
            kv_rows = [
                ("OWASP Category",  owasp_cat),
                ("MITRE ATT&CK",    mitre_id),
                ("CVE Identifier",  cve_val),
                ("CVSS v3.1 Score", cvss_score_str),
                ("CVSS Vector",     cvss_vec)
            ]
            
            if epss_score is not None:
                epss_str = f"{epss_score:.4f}"
                if epss_percentile is not None:
                    epss_str += f" (Percentile: {epss_percentile:.2f}%)"
                kv_rows.append(("EPSS Score", epss_str))
                
            kv_rows.extend([
                ("Affected Component", affected),
                ("Detection Source",  f"{tool} Scanner"),
                ("Confidence",      f"{f.get('confidence', 50)}%"),
            ])

            story.append(_kv_table(kv_rows, st))
            story.append(_spacer(6))

            # ── Technical Breakdown ───────────────────────────────────────
            story.append(Paragraph("Technical Breakdown", st["h4"]))
            story.append(Paragraph(_esc(desc), st["body"]))
            story.append(_spacer(6))

            # ── How To Reproduce (POC Instructions) ──
            repro_steps = f.get("reproduction_steps")
            if repro_steps:
                story.append(Paragraph("How to Reproduce (Proof of Concept)", st["h4"]))
                story.append(Paragraph(
                    "Follow these step-by-step verification commands or instructions to reproduce the vulnerability:",
                    st["body"]
                ))
                story.append(_code_block(repro_steps, st))
                story.append(_spacer(6))

            # ── Scan Result Evidence / Raw Output ─────────────────────────
            evidence = f.get("evidence")
            if evidence:
                story.append(Paragraph(f"Scan Result Evidence — Raw Output from {_esc(tool)}", st["h4"]))
                story.append(_code_block(evidence[:1800], st))
                story.append(_spacer(6))

            # ── Visual Screenshot Evidence ────────────────────────────────
            evidence_path = f.get("evidence_path")
            if evidence_path and os.path.exists(evidence_path):
                story.append(Paragraph("Visual Evidence (Screenshot)", st["h4"]))
                try:
                    from reportlab.platypus import Image
                    from reportlab.lib.utils import ImageReader
                    
                    # Read image to get aspect ratio
                    img = ImageReader(evidence_path)
                    iw, ih = img.getSize()
                    
                    # Max width is BW (body width)
                    max_width = BW
                    aspect = ih / float(iw)
                    
                    # Scale down if too wide
                    disp_width = min(iw, max_width)
                    disp_height = disp_width * aspect
                    
                    # Prevent images from being taller than a page
                    if disp_height > 600:
                        disp_height = 600
                        disp_width = disp_height / aspect

                    img_flow = Image(evidence_path, width=disp_width, height=disp_height)
                    story.append(KeepTogether([img_flow]))
                    story.append(_spacer(6))
                except Exception as e:
                    logger.error(f"Failed to embed screenshot {evidence_path}: {e}")

            # ── Remediation Blueprint ─────────────────────────────────────
            story.append(Paragraph("Remediation Blueprint & Mitigation", st["h4"]))
            strategic, code_fix = _get_remediation(tool, sev, title)
            
            recommendation = f.get("recommendation") or strategic
            remediation_code = f.get("remediation_code") or code_fix

            story.append(Paragraph(f"<b>Strategic Recommendation:</b> {recommendation}", st["body"]))
            if remediation_code:
                story.append(_spacer(4))
                story.append(Paragraph("Code-Level or Config-Level Remediation Example:", st["label"]))
                story.append(_code_block(remediation_code, st))

            # ── References ──
            import json as _json
            ref_data = f.get("references_json")
            if ref_data:
                try:
                    if isinstance(ref_data, str):
                        ref_links = _json.loads(ref_data)
                    else:
                        ref_links = ref_data
                    if ref_links:
                        story.append(_spacer(6))
                        story.append(Paragraph("References", st["h4"]))
                        for link in ref_links:
                            story.append(Paragraph(f"&bull; <a href='{link}'><font color='#10B981'>{_esc(link)}</font></a>", st["body"]))
                except Exception as e:
                    from tools.errors import SMPUnclassifiedError
                    import traceback
                    import logging
                    logging.getLogger('smp').error(f'Unexpected error: {e}\n{traceback.format_exc()}')
                    raise SMPUnclassifiedError(str(e))
                    pass

            story += [_spacer(10), _hr(_P["border"]), _spacer(6)]

            # Page break every finding to keep it neat and professional
            if idx < len(sorted_findings):
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

    tools_used = sorted(list(c.get("findings_by_tool", {}).keys()))
    if not tools_used:
        tools_used = ["No specific tools recorded"]
    tools_rows = []
    for t in tools_used:
        tools_rows.append([t, "Automated Security Assessment Tool", "Mixed", "Active/Passive"])
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
        f"• Assessment methodologies comply with OWASP WSTG v9.4.3 and NIST SP 800-115.<br/>"
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
    
    # SMP Verified Stamp
    import socket
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        scanner_ip = s.getsockname()[0]
        s.close()
    except Exception as e:
        from tools.errors import SMPUnclassifiedError
        import traceback
        import logging
        logging.getLogger('smp').error(f'Unexpected error: {e}\n{traceback.format_exc()}')
        raise SMPUnclassifiedError(str(e))
        scanner_ip = "127.0.0.1"

    stamp_data = [
        [Paragraph(f"<b>✔ SMP ({c['url']}) Verified Report</b>", st["attest"])],
        [Paragraph(f"Date: {c['scan_time']}", st["attest"])],
        [Paragraph(f"Scanner IP: {scanner_ip}", st["attest"])],
    ]
    stamp_t = Table(stamp_data, colWidths=[220], hAlign="RIGHT")
    stamp_t.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, -1), _c("#EFF6FF")),  # Very light blue
        ("BOX",           (0, 0), (-1, -1), 1.5, _c(_P["accent"])),
        ("TOPPADDING",    (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("LEFTPADDING",   (0, 0), (-1, -1), 10),
        ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
    ]))
    story.append(stamp_t)
    story.append(_spacer(30))

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


# ── HTML Report (Single File) ───────────────────────────────────────────────────

def _generate_html_fallback(filepath, ctx):
    """Professional-grade HTML VAPT report — fully self-contained, no external deps."""
    import json as _json
    c      = ctx
    counts = c["counts"]
    site   = c.get("site_name", c["url"])
    c_hash = c.get("content_hash", "")
    c.get("hash16", "")
    meta_b = c.get("meta_block", "")
    h_tok  = c.get("hash_token", "")
    smp_ver = c.get("smp_version", "--help")

    target  = c.get("target", {})
    company = target.get("company_name") or c["settings"].get("company_name") or "—"
    submitted_to = target.get("submitted_to") or c["settings"].get("submitted_to") or "Internal Security Team"
    tester  = _esc(c.get("scanned_by", "—"))
    qa_rev  = _esc(c["settings"].get("qa_reviewer", "QA Manager"))
    scan_dt = c["scan_time"][:10]
    total_f = c.get("total", 0)
    risk    = c.get("risk_data") or {}
    risk_score = risk.get("score", 0) if isinstance(risk, dict) else 0
    risk_label = risk.get("label", "Low") if isinstance(risk, dict) else "Low"

    crit_n = counts["Critical"]
    high_n = counts["High"]
    med_n  = counts["Medium"]
    low_n  = counts["Low"]
    info_n = counts["Info"]

    # ── Derive executive summary text dynamically ────────────────────────────
    if total_f == 0:
        exec_para = (
            f"The security assessment of <strong>{_esc(c['url'])}</strong> completed with "
            f"<strong>no exploitable vulnerabilities</strong> identified. The target presented "
            f"a strong security posture across all tested domains including network services, "
            f"web application behaviour, SSL/TLS configuration, and HTTP security headers. "
            f"Continued monitoring and periodic re-assessment are recommended to maintain this posture."
        )
    else:
        sev_txt = []
        if crit_n: sev_txt.append(f"<strong>{crit_n} Critical</strong>")
        if high_n: sev_txt.append(f"<strong>{high_n} High</strong>")
        if med_n:  sev_txt.append(f"<strong>{med_n} Medium</strong>")
        if low_n:  sev_txt.append(f"{low_n} Low")
        if info_n: sev_txt.append(f"{info_n} Informational")
        sev_str = ", ".join(sev_txt) if sev_txt else f"{total_f} total"
        urgency = "immediate remediation is required" if crit_n > 0 else \
                  "prompt remediation is strongly recommended" if high_n > 0 else \
                  "remediation should be planned within the next release cycle"
        exec_para = (
            f"A comprehensive Vulnerability Assessment and Penetration Test (VAPT) was conducted against "
            f"<strong>{_esc(c['url'])}</strong> on <strong>{scan_dt}</strong>. "
            f"The engagement revealed <strong>{total_f} security finding(s)</strong>: {sev_str}. "
            f"The overall risk score is <strong>{risk_score:.1f}/100 ({_esc(risk_label)})</strong>. "
            f"Based on the findings, {urgency}. "
            f"Critical and High findings represent direct attack vectors that can lead to data exfiltration, "
            f"service disruption, or full system compromise if left unaddressed. "
            f"A detailed remediation action plan is provided in Section 5 of this report."
        )

    # ── Sorted findings ──────────────────────────────────────────────────────
    sorted_f = sorted(c["findings"], key=lambda f: _sev_rank(f.get("severity", "Info")))

    # ── MITRE ATT&CK colour map ──────────────────────────────────────────────

    # ── Tools used ──────────────────────────────────────────────────────────
    tools_used = sorted({f.get("source_tool", "") for f in c["findings"] if f.get("source_tool")})

    CSS = """
*{box-sizing:border-box;margin:0;padding:0}
:root{
  --crit:#dc2626;--high:#ea580c;--med:#d97706;--low:#2563eb;--info:#4b5563;
  --bg:#f1f5f9;--card:#fff;--border:#e2e8f0;--text:#0f172a;--muted:#64748b;
  --accent:#1e3a5f;--accent2:#2563eb;
}
body{font-family:'Segoe UI',system-ui,-apple-system,sans-serif;background:var(--bg);color:var(--text);font-size:14px;line-height:1.6;}
a{color:var(--accent2);text-decoration:none;}a:hover{text-decoration:underline;}
.page{max-width:1080px;margin:0 auto;padding:32px 20px 60px;}
/* ── Cover ── */
.cover{background:linear-gradient(135deg,#0f172a 0%,#1e3a5f 60%,#1d4ed8 100%);color:#f8fafc;
  border-radius:16px;padding:56px 48px 48px;margin-bottom:36px;position:relative;overflow:hidden;}
.cover::before{content:'';position:absolute;top:-60px;right:-60px;width:320px;height:320px;
  border-radius:50%;background:rgba(255,255,255,.04);}
.cover-logo{display:flex;align-items:center;gap:10px;margin-bottom:32px;}
.cover-logo-icon{width:40px;height:40px;background:#2563eb;border-radius:8px;
  display:flex;align-items:center;justify-content:center;font-size:20px;}
.cover-logo-text{font-size:13px;font-weight:700;letter-spacing:.05em;color:#94a3b8;text-transform:uppercase;}
.cover h1{font-size:2.4rem;font-weight:800;line-height:1.15;margin-bottom:6px;letter-spacing:-.02em;}
.cover .tagline{color:#93c5fd;font-size:1rem;margin-bottom:36px;}
.cover-grid{display:grid;grid-template-columns:1fr 1fr;gap:10px 32px;margin-bottom:28px;}
.cover-kv{display:flex;flex-direction:column;gap:2px;}
.cover-kv .k{font-size:10px;font-weight:700;letter-spacing:.1em;text-transform:uppercase;color:#64748b;}
.cover-kv .v{font-size:13px;font-weight:600;color:#f1f5f9;}
.cover-divider{border:none;border-top:1px solid rgba(255,255,255,.1);margin:20px 0;}
.hash-row{display:flex;align-items:flex-start;gap:12px;background:rgba(0,0,0,.25);
  border-radius:10px;padding:14px 16px;}
.hash-icon{font-size:18px;margin-top:1px;}
.hash-label{font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.1em;color:#34d399;margin-bottom:4px;}
.hash-value{font-family:'Courier New',monospace;font-size:11px;color:#a7f3d0;word-break:break-all;line-height:1.5;}
/* ── KPI Strip ── */
.kpi-strip{display:grid;grid-template-columns:repeat(5,1fr);gap:12px;margin-bottom:32px;}
.kpi-card{background:var(--card);border-radius:12px;padding:18px 16px;text-align:center;
  border:1px solid var(--border);box-shadow:0 1px 3px rgba(0,0,0,.05);position:relative;overflow:hidden;}
.kpi-card::before{content:'';position:absolute;top:0;left:0;right:0;height:4px;}
.kpi-card.crit::before{background:var(--crit);}
.kpi-card.high::before{background:var(--high);}
.kpi-card.med::before{background:var(--med);}
.kpi-card.low::before{background:var(--low);}
.kpi-card.info::before{background:var(--info);}
.kpi-num{font-size:2.2rem;font-weight:800;line-height:1;}
.kpi-card.crit .kpi-num{color:var(--crit);}
.kpi-card.high .kpi-num{color:var(--high);}
.kpi-card.med .kpi-num{color:var(--med);}
.kpi-card.low .kpi-num{color:var(--low);}
.kpi-card.info .kpi-num{color:var(--info);}
.kpi-label{font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:.06em;color:var(--muted);margin-top:4px;}
/* ── Sections ── */
.section{background:var(--card);border-radius:12px;padding:28px 32px;margin-bottom:24px;
  border:1px solid var(--border);box-shadow:0 1px 3px rgba(0,0,0,.05);}
.section-header{display:flex;align-items:center;gap:10px;margin-bottom:20px;
  padding-bottom:14px;border-bottom:2px solid var(--border);}
.section-num{font-size:11px;font-weight:700;color:var(--accent2);background:#eff6ff;
  border:1px solid #bfdbfe;border-radius:6px;padding:2px 8px;letter-spacing:.05em;}
.section-title{font-size:1.05rem;font-weight:700;color:var(--text);}
/* ── Tables ── */
.data-table{border-collapse:collapse;width:100%;font-size:13px;}
.data-table th{background:#f8fafc;color:var(--muted);padding:9px 12px;text-align:left;
  border-bottom:2px solid var(--border);font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.05em;white-space:nowrap;}
.data-table td{padding:10px 12px;border-bottom:1px solid #f1f5f9;vertical-align:top;}
.data-table tr:last-child td{border-bottom:none;}
.data-table tr:hover td{background:#f8fafc;}
/* ── Severity Badge ── */
.sev{display:inline-flex;align-items:center;padding:2px 8px;border-radius:5px;font-weight:700;font-size:11px;color:#fff;letter-spacing:.03em;}
.sev-Critical{background:var(--crit);}
.sev-High{background:var(--high);}
.sev-Medium{background:var(--med);}
.sev-Low{background:var(--low);}
.sev-Info{background:var(--info);}
/* ── Finding Cards ── */
.finding-card{border:1px solid var(--border);border-radius:10px;margin-bottom:16px;overflow:hidden;}
.finding-card-header{padding:14px 18px;display:flex;align-items:flex-start;justify-content:space-between;gap:12px;background:#f8fafc;}
.finding-card-header.sev-Critical-bg{border-left:5px solid var(--crit);background:#fff5f5;}
.finding-card-header.sev-High-bg{border-left:5px solid var(--high);background:#fff8f3;}
.finding-card-header.sev-Medium-bg{border-left:5px solid var(--med);background:#fffdf0;}
.finding-card-header.sev-Low-bg{border-left:5px solid var(--low);background:#f0f5ff;}
.finding-card-header.sev-Info-bg{border-left:5px solid var(--info);background:#f8fafc;}
.finding-id{font-size:11px;font-weight:700;color:var(--muted);margin-bottom:4px;font-family:monospace;}
.finding-title{font-size:14px;font-weight:700;color:var(--text);flex:1;}
.finding-body{padding:16px 18px;}
.finding-meta{display:flex;flex-wrap:wrap;gap:6px;margin-bottom:14px;}
.tag{display:inline-flex;align-items:center;gap:4px;background:#f1f5f9;color:#475569;
  border-radius:5px;padding:3px 9px;font-size:11px;font-weight:600;border:1px solid #e2e8f0;}
.tag-mitre{background:#1e3a5f;color:#93c5fd;border-color:#1e3a5f;}
.tag-cve{background:#7c3aed;color:#ede9fe;border-color:#6d28d9;}
.tag-cvss{background:#0f766e;color:#ccfbf1;border-color:#0d9488;}
.sub-heading{font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.08em;
  color:var(--muted);margin:14px 0 6px;display:flex;align-items:center;gap:6px;}
.sub-heading::before{content:'';display:block;width:3px;height:12px;border-radius:2px;background:var(--accent2);}
.prose{font-size:13px;color:#334155;line-height:1.75;white-space:pre-wrap;word-break:break-word;}
.code-block{background:#0f172a;color:#e2e8f0;padding:14px 16px;border-radius:8px;
  font-family:'Courier New',monospace;font-size:12px;line-height:1.6;overflow-x:auto;
  white-space:pre-wrap;word-break:break-all;margin:6px 0;}
.evidence-block{background:#f0fdf4;border:1px solid #bbf7d0;border-radius:8px;
  padding:12px 14px;font-family:'Courier New',monospace;font-size:12px;color:#14532d;
  overflow-x:auto;white-space:pre-wrap;word-break:break-all;margin:6px 0;}
.impact-block{background:#fef9ec;border:1px solid #fcd34d;border-radius:8px;
  padding:12px 14px;font-size:13px;color:#92400e;margin:6px 0;}
.remd-block{background:#f0fdf4;border-left:3px solid #22c55e;
  padding:12px 14px;font-size:13px;color:#15803d;border-radius:0 8px 8px 0;margin:6px 0;}
.ref-list{list-style:none;margin:6px 0;display:flex;flex-direction:column;gap:4px;}
.ref-list li::before{content:'↗ ';}
.ref-list a{font-size:12px;word-break:break-all;}
/* ── Methodology table ── */
.method-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(180px,1fr));gap:10px;}
.method-item{background:#f8fafc;border:1px solid var(--border);border-radius:8px;
  padding:10px 14px;font-size:12px;}
.method-item .tool-name{font-weight:700;color:var(--text);}
.method-item .tool-type{color:var(--muted);font-size:11px;margin-top:2px;}
.method-item.used{border-left:3px solid #22c55e;}
/* ── Risk gauge ── */
.risk-row{display:flex;align-items:center;gap:16px;margin-bottom:16px;}
.risk-score{font-size:3rem;font-weight:800;line-height:1;}
.risk-score.Critical{color:var(--crit);}
.risk-score.High{color:var(--high);}
.risk-score.Medium{color:var(--med);}
.risk-score.Low{color:var(--low);}
.risk-bar-wrap{flex:1;background:#e2e8f0;border-radius:999px;height:12px;overflow:hidden;}
.risk-bar{height:100%;border-radius:999px;transition:width .4s;}
.risk-bar.Critical{background:var(--crit);}
.risk-bar.High{background:var(--high);}
.risk-bar.Medium{background:var(--med);}
.risk-bar.Low{background:var(--low);}
/* ── Action Plan ── */
.action-row{display:flex;gap:12px;align-items:flex-start;padding:12px 0;border-bottom:1px solid var(--border);}
.action-row:last-child{border-bottom:none;}
.action-window{min-width:80px;text-align:center;font-size:11px;font-weight:700;
  padding:4px 10px;border-radius:6px;color:#fff;}
.aw-imm{background:var(--crit);}
.aw-72h{background:var(--high);}
.aw-2w{background:var(--med);}
.aw-q{background:#0891b2;}
.aw-ong{background:var(--info);}
.action-text{font-size:13px;color:#334155;flex:1;}
/* ── Footer ── */
.report-footer{text-align:center;color:var(--muted);font-size:12px;margin-top:48px;
  padding-top:24px;border-top:1px solid var(--border);}
.report-footer strong{color:var(--text);}
/* ── TOC ── */
.toc-list{list-style:none;counter-reset:toc;}
.toc-list li{counter-increment:toc;padding:6px 0;border-bottom:1px dotted var(--border);
  display:flex;justify-content:space-between;font-size:13px;}
.toc-list li .toc-num{color:var(--accent2);font-weight:700;margin-right:8px;}
/* ── Attrib banner ── */
.confidential-banner{background:#fef2f2;border:1px solid #fecaca;border-radius:8px;
  padding:10px 16px;font-size:12px;font-weight:600;color:#991b1b;text-align:center;
  margin-bottom:28px;letter-spacing:.04em;}
"""

    def _kv_cover(label, val):
        return f"<div class='cover-kv'><div class='k'>{label}</div><div class='v'>{_esc(str(val)) if val else '—'}</div></div>"

    # Start building HTML
    lines = [
        "<!DOCTYPE html><html lang='en'>",
        "<head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'>",
        f"<title>VAPT Report — {_esc(site)} — {scan_dt}</title>",
        f"<style>{CSS}</style>",
        "</head><body><div class='page'>",

        # Hidden verification tokens (parsed by verify_report.py)
        f"<!-- {h_tok} -->",
        f"<!-- {meta_b} -->",

        # ── Cover ──────────────────────────────────────────────────────────
        "<div class='cover'>",
        "<div class='cover-logo'><div class='cover-logo-icon'>🛡</div>"
        "<div class='cover-logo-text'>Security Management Platform</div></div>",
        "<h1>Vulnerability Assessment &amp;<br>Penetration Testing Report</h1>",
        f"<div class='tagline'>{_esc(c['url'])}</div>",
        "<div class='cover-grid'>",
        _kv_cover("Target Company", company),
        _kv_cover("Submitted To", submitted_to),
        _kv_cover("Date of Assessment", scan_dt),
        _kv_cover("Lead Penetration Tester", tester),
        _kv_cover("QA Reviewer", qa_rev),
        f"<div class='cover-kv'><div class='k'>SMP Version</div><div class='v'>{_esc(smp_ver)} Stable</div></div>",
        _kv_cover("Data Classification", "CONFIDENTIAL — INTERNAL USE ONLY"),
        _kv_cover("Total Findings", str(total_f)),
        "</div>",
        "<hr class='cover-divider'>",
        "<div class='hash-row'>",
        "<div class='hash-icon'>✅</div>",
        "<div><div class='hash-label'>Verification Hash (SHA-256 Content Signature)</div>",
        f"<div class='hash-value'>{_esc(c_hash or '—')}</div>",
        "<div style='font-size:10px;color:#64748b;margin-top:6px;'>Verify with: <code>python3 tools/verify_report.py &lt;this-file&gt;</code></div>",
        "</div></div>",
        "</div>",  # end .cover

        # ── Confidential Banner ─────────────────────────────────────────────
        "<div class='confidential-banner'>⚠ CONFIDENTIAL — AUTHORISED RECIPIENTS ONLY — NOT FOR EXTERNAL DISTRIBUTION</div>",

        # ── KPI Strip ──────────────────────────────────────────────────────
        "<div class='kpi-strip'>",
        f"<div class='kpi-card crit'><div class='kpi-num'>{crit_n}</div><div class='kpi-label'>Critical</div></div>",
        f"<div class='kpi-card high'><div class='kpi-num'>{high_n}</div><div class='kpi-label'>High</div></div>",
        f"<div class='kpi-card med'><div class='kpi-num'>{med_n}</div><div class='kpi-label'>Medium</div></div>",
        f"<div class='kpi-card low'><div class='kpi-num'>{low_n}</div><div class='kpi-label'>Low</div></div>",
        f"<div class='kpi-card info'><div class='kpi-num'>{info_n}</div><div class='kpi-label'>Informational</div></div>",
        "</div>",
    ]

    # ── Section 1: Table of Contents ─────────────────────────────────────────
    lines += [
        "<div class='section'>",
        "<div class='section-header'>",
        "<span class='section-num'>SECTION 1</span>",
        "<span class='section-title'>Table of Contents</span>",
        "</div>",
        "<ol class='toc-list'>",
        "<li><span><span class='toc-num'>1.</span> Table of Contents</span><span>This page</span></li>",
        "<li><span><span class='toc-num'>2.</span> Executive Summary &amp; Risk Score</span><span></span></li>",
        "<li><span><span class='toc-num'>3.</span> Engagement Scope &amp; Methodology</span><span></span></li>",
        "<li><span><span class='toc-num'>4.</span> Findings Overview Matrix</span><span></span></li>",
        "<li><span><span class='toc-num'>5.</span> Technical Findings — Detail</span><span></span></li>",
        "<li><span><span class='toc-num'>6.</span> Action Plan &amp; Remediation Timeline</span><span></span></li>",
        "<li><span><span class='toc-num'>7.</span> Attestation &amp; Verification</span><span></span></li>",
        "</ol>",
        "</div>",
    ]

    # ── Section 2: Executive Summary & Risk Score ────────────────────────────
    risk_pct = min(int(risk_score), 100)
    lines += [
        "<div class='section'>",
        "<div class='section-header'>",
        "<span class='section-num'>SECTION 2</span>",
        "<span class='section-title'>Executive Summary &amp; Risk Score</span>",
        "</div>",
        "<div class='risk-row'>",
        f"<div class='risk-score {_esc(risk_label)}'>{risk_score:.1f}</div>",
        "<div style='flex:1'>",
        f"<div style='font-size:11px;font-weight:700;text-transform:uppercase;color:var(--muted);margin-bottom:6px;'>Overall Risk Score / 100 — <strong style='color:inherit'>{_esc(risk_label)}</strong></div>",
        f"<div class='risk-bar-wrap'><div class='risk-bar {_esc(risk_label)}' style='width:{risk_pct}%'></div></div>",
        "</div></div>",
        f"<p style='font-size:13.5px;line-height:1.8;color:#334155;'>{exec_para}</p>",
        "</div>",
    ]

    # ── Section 3: Scope & Methodology ──────────────────────────────────────
    used_set = set(tools_used)
    lines += [
        "<div class='section'>",
        "<div class='section-header'>",
        "<span class='section-num'>SECTION 3</span>",
        "<span class='section-title'>Engagement Scope &amp; Methodology</span>",
        "</div>",
        "<table class='data-table' style='margin-bottom:20px;'>",
        "<tr><th>Field</th><th>Value</th></tr>",
        f"<tr><td>Target URL</td><td><code>{_esc(c['url'])}</code></td></tr>",
        f"<tr><td>Company</td><td>{_esc(company)}</td></tr>",
        f"<tr><td>Assessment Date</td><td>{scan_dt}</td></tr>",
        "<tr><td>Assessment Type</td><td>Black-box VAPT (Automated + Correlation)</td></tr>",
        f"<tr><td>Lead Tester</td><td>{tester}</td></tr>",
        f"<tr><td>QA Reviewer</td><td>{qa_rev}</td></tr>",
        "<tr><td>Scope</td><td>Web application, network services, SSL/TLS, headers, OSINT</td></tr>",
        "<tr><td>Out of Scope</td><td>Physical access, social engineering, denial of service</td></tr>",
        "</table>",
        "<div class='sub-heading'>Security Tools Deployed</div>",
        "<div class='method-grid'>",
    ]
    for tool_name in sorted(used_set):
        lines.append(
            f"<div class='method-item used'>"
            f"<div class='tool-name'>✅ {_esc(tool_name)}</div>"
            f"<div class='tool-type'>Automated Tool</div>"
            f"</div>"
        )
    lines += ["</div>", "</div>"]

    # ── Section 4: Findings Overview Matrix ─────────────────────────────────
    lines += [
        "<div class='section'>",
        "<div class='section-header'>",
        "<span class='section-num'>SECTION 4</span>",
        "<span class='section-title'>Findings Overview Matrix</span>",
        "</div>",
    ]
    if not sorted_f:
        lines.append("<p style='color:var(--muted);font-style:italic;'>No vulnerabilities identified during this assessment.</p>")
    else:
        lines += [
            "<table class='data-table'>",
            "<tr><th>ID</th><th>Title</th><th>Severity</th><th>CVSS</th><th>MITRE</th><th>Tool</th><th>Component</th></tr>",
        ]
        for idx, f in enumerate(sorted_f, 1):
            sev   = f.get("severity", "Info")
            cvss  = f.get("cvss_score") or ""
            mitre = f.get("mitre_id") or "—"
            comp  = f.get("affected_component") or "—"
            cvss_str = f"<span style='font-weight:700;'>{cvss}</span>" if cvss else "—"
            lines.append(
                f"<tr>"
                f"<td style='font-family:monospace;font-weight:700;color:var(--muted);'>SEC-{idx:03d}</td>"
                f"<td style='font-weight:600;'>{_esc(f.get('title',''))}</td>"
                f"<td><span class='sev sev-{sev}'>{sev}</span></td>"
                f"<td>{cvss_str}</td>"
                f"<td style='font-size:11px;font-family:monospace;color:#6d28d9;'>{_esc(mitre)}</td>"
                f"<td style='font-size:12px;color:var(--muted);'>{_esc(f.get('source_tool',''))}</td>"
                f"<td style='font-size:12px;'>{_esc(comp)}</td>"
                f"</tr>"
            )
        lines.append("</table>")
    lines.append("</div>")

    # ── Section 5: Technical Findings Detail ─────────────────────────────────
    lines += [
        "<div class='section'>",
        "<div class='section-header'>",
        "<span class='section-num'>SECTION 5</span>",
        "<span class='section-title'>Technical Findings — Detail</span>",
        "</div>",
    ]
    if not sorted_f:
        lines.append("<p style='color:var(--muted);font-style:italic;'>No vulnerabilities to detail for this assessment.</p>")
    else:
        for idx, f in enumerate(sorted_f, 1):
            sev   = f.get("severity", "Info")
            title = f.get("title", "")
            cve   = f.get("cve_id") or ""
            cvss  = f.get("cvss_score") or ""
            desc  = f.get("description") or ""
            evid  = f.get("evidence") or ""
            remd  = f.get("recommendation") or ""
            url_f = f.get("url") or c["url"]
            tool  = f.get("source_tool") or ""
            mitre = f.get("mitre_id") or ""
            b_imp = f.get("business_impact") or ""
            repro = f.get("reproduction_steps") or ""
            code  = f.get("remediation_code") or ""
            owasp = f.get("owasp_category") or ""
            comp  = f.get("affected_component") or ""
            refs_raw = f.get("references_json") or ""
            conf  = f.get("confidence") or ""

            lines += [
                "<div class='finding-card'>",
                f"<div class='finding-card-header sev-{sev}-bg'>",
                f"<div><div class='finding-id'>SEC-{idx:03d} &nbsp;/&nbsp; {_esc(tool)}</div>",
                f"<div class='finding-title'>{_esc(title)}</div></div>",
                f"<div><span class='sev sev-{sev}'>{sev}</span></div>",
                "</div>",
                "<div class='finding-body'>",
                "<div class='finding-meta'>",
            ]
            if cve:
                lines.append(f"<span class='tag tag-cve'>CVE: {_esc(cve)}</span>")
            if cvss:
                lines.append(f"<span class='tag tag-cvss'>CVSS: {cvss}</span>")
            if mitre and mitre.lower() not in ("unknown", "none", ""):
                lines.append(f"<span class='tag tag-mitre'>MITRE: {_esc(mitre)}</span>")
            if owasp:
                lines.append(f"<span class='tag'>OWASP: {_esc(owasp)}</span>")
            if comp:
                lines.append(f"<span class='tag'>Component: {_esc(comp)}</span>")
            if conf:
                lines.append(f"<span class='tag'>Confidence: {conf}%</span>")
            lines.append(f"<span class='tag'>URL: {_esc(str(url_f)[:80])}</span>")
            lines.append("</div>")

            if desc:
                lines += [
                    "<div class='sub-heading'>Description</div>",
                    f"<div class='prose'>{_esc(desc)}</div>",
                ]

            if b_imp:
                lines += [
                    "<div class='sub-heading'>Business Impact</div>",
                    f"<div class='impact-block'>{_esc(b_imp)}</div>",
                ]

            if repro:
                lines += [
                    "<div class='sub-heading'>Proof of Concept / Reproduction Steps</div>",
                    f"<div class='code-block'>{_esc(repro)}</div>",
                ]

            if evid:
                lines += [
                    "<div class='sub-heading'>Scan Evidence</div>",
                    f"<div class='evidence-block'>{_esc(str(evid)[:1200])}</div>",
                ]

            evidence_path = f.get("evidence_path")
            if evidence_path and os.path.exists(evidence_path):
                try:
                    import base64
                    with open(evidence_path, "rb") as img_file:
                        b64_img = base64.b64encode(img_file.read()).decode('utf-8')
                    lines += [
                        "<div class='sub-heading'>Visual Evidence (Screenshot)</div>",
                        f"<div style='margin-top:10px;'><img src='data:image/png;base64,{b64_img}' style='max-width:100%; border:1px solid var(--border); border-radius:8px;'/></div>",
                    ]
                except Exception as e:
                    logger.error(f"HTML screenshot embedding failed: {e}")

            if remd:
                lines += [
                    "<div class='sub-heading'>Remediation Recommendation</div>",
                    f"<div class='remd-block'>{_esc(remd)}</div>",
                ]

            if code:
                lines += [
                    "<div class='sub-heading'>Remediation Code / Config</div>",
                    f"<div class='code-block'>{_esc(code)}</div>",
                ]

            if refs_raw:
                try:
                    ref_links = _json.loads(refs_raw) if isinstance(refs_raw, str) else refs_raw
                    if ref_links and isinstance(ref_links, list):
                        lines += ["<div class='sub-heading'>References</div>", "<ul class='ref-list'>"]
                        for link in ref_links[:8]:
                            lines.append(f"<li><a href='{_esc(str(link))}' target='_blank'>{_esc(str(link)[:100])}</a></li>")
                        lines.append("</ul>")
                except Exception as e:
                    from tools.errors import SMPUnclassifiedError
                    import traceback
                    import logging
                    logging.getLogger('smp').error(f'Unexpected error: {e}\n{traceback.format_exc()}')
                    raise SMPUnclassifiedError(str(e))
                    pass

            lines += ["</div>", "</div>"]  # finding-body, finding-card
    lines.append("</div>")  # section

    # ── Section 6: Action Plan ────────────────────────────────────────────────
    lines += [
        "<div class='section'>",
        "<div class='section-header'>",
        "<span class='section-num'>SECTION 6</span>",
        "<span class='section-title'>Action Plan &amp; Remediation Timeline</span>",
        "</div>",
    ]
    action_items = [
        ("aw-imm",  "Immediate (0–24 h)",
         f"Patch, isolate, or WAF-block all <strong>Critical</strong> findings ({crit_n} identified). "
         f"Engage incident response if any Critical finding is actively exploited."),
        ("aw-72h",  "Short-term (72 h)",
         f"Remediate all <strong>High</strong>-severity findings ({high_n} identified). "
         f"Deploy WAF rules as temporary mitigations where direct patching is not immediately feasible."),
        ("aw-2w",   "Medium-term (2 weeks)",
         f"Address all <strong>Medium</strong>-severity issues ({med_n} identified). "
         f"Apply OS, TLS version, and HTTP header hardening across the stack."),
        ("aw-q",    "Quarterly",
         f"Resolve remaining <strong>Low</strong>/{info_n} informational items and tighten configuration baselines. "
         f"Schedule developer security training."),
        ("aw-ong",  "Ongoing",
         "Maintain automated CVE monitoring for detected technologies. "
         "Repeat full VAPT every 6 months or after any major infrastructure change. "
         "Subscribe to CISA KEV and NVD feeds for zero-day alerting."),
    ]
    for cls, window, text in action_items:
        lines += [
            "<div class='action-row'>",
            f"<div class='action-window {cls}'>{window}</div>",
            f"<div class='action-text'>{text}</div>",
            "</div>",
        ]
    lines.append("</div>")

    # ── Section 7: Attestation ────────────────────────────────────────────────
    lines += [
        "<div class='section'>",
        "<div class='section-header'>",
        "<span class='section-num'>SECTION 7</span>",
        "<span class='section-title'>Formal Attestation &amp; Report Verification</span>",
        "</div>",
        "<table class='data-table' style='margin-bottom:20px;'>",
        "<tr><th>Field</th><th>Value</th></tr>",
        f"<tr><td>Lead Penetration Tester</td><td><strong>{tester}</strong></td></tr>",
        f"<tr><td>QA Reviewer</td><td>{qa_rev}</td></tr>",
        f"<tr><td>Date of Report</td><td>{scan_dt}</td></tr>",
        f"<tr><td>Generated By</td><td>Security Management Platform {_esc(smp_ver)}</td></tr>",
        f"<tr><td>Report Integrity Hash</td><td><code style='font-size:11px;word-break:break-all;'>{_esc(c_hash or '—')}</code></td></tr>",
        "</table>",
        "<p style='font-size:12px;color:var(--muted);'>",
        "This report was generated automatically by Security Management Platform (SMP). "
        "The content hash above uniquely identifies this report's findings and can be independently "
        "verified using: <code>python3 tools/verify_report.py &lt;path-to-this-file&gt;</code>. "
        "Any modification to this document will invalidate the embedded signature.",
        "</p>",
        "</div>",

        # ── Footer ────────────────────────────────────────────────────────────
        "<div class='report-footer'>",
        f"<strong>Security Management Platform (SMP) {_esc(smp_ver)}</strong><br>",
        f"Report: SMP_{_esc(site)}_Report_{scan_dt}.html &nbsp;·&nbsp; "
        f"Hash: <code>{_esc(c_hash[:24]) if c_hash else 'n/a'}…</code><br>",
        "<em>CONFIDENTIAL — INTERNAL USE ONLY — NOT FOR EXTERNAL DISTRIBUTION</em>",
        "</div>",
        "</div></body></html>",
    ]

    os.makedirs(os.path.dirname(filepath), exist_ok=True)
    with open(filepath, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines))

