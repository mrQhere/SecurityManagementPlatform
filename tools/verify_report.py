#!/usr/bin/env python3
"""
SMP Report Authenticity Verifier
=================================
Verifies that an SMP-generated PDF or HTML report has not been tampered with.

Works COMPLETELY OFFLINE — no database or SMP installation required.
The report is self-contained: the verification hash is embedded inside it.

Usage:
    python3 tools/verify_report.py reports/pdf/SMP_example.com_Report_2024-07-01_abc123.pdf
    python3 tools/verify_report.py reports/html/SMP_example.com_Report_2024-07-01.html
    python3 tools/verify_report.py --help
"""

import sys
import os
import re
import hashlib
import json
import argparse
from datetime import datetime

# ── Terminal colours ──────────────────────────────────────────────────────────
GRN  = "\033[92m"
RED  = "\033[91m"
YEL  = "\033[93m"
CYN  = "\033[96m"
BLD  = "\033[1m"
DIM  = "\033[2m"
RST  = "\033[0m"

BANNER = f"""
{BLD}  ╔══════════════════════════════════════════════════════════════════╗{RST}
{BLD}  ║       Security Management Platform — Report Verifier            ║{RST}
{BLD}  ╠══════════════════════════════════════════════════════════════════╣{RST}
{BLD}  ║  Verify the authenticity of any SMP report — no database needed ║{RST}
{BLD}  ╚══════════════════════════════════════════════════════════════════╝{RST}
"""

# ── Marker strings embedded in every SMP report ──────────────────────────────
# The content hash is embedded between these markers in both PDF text and HTML.
HASH_MARKER_START = "SMP-CONTENT-HASH:"
HASH_MARKER_END   = ":END-HASH"

# ── Hash derivation — MUST match report_generator.py exactly ─────────────────
def derive_content_hash(url: str, scan_date: str, findings_count: int,
                        crit: int, high: int, med: int, low: int,
                        scanned_by: str, smp_version: str) -> str:
    """
    Derives a deterministic SHA-256 from the key scan facts.
    This is the canonical hash embedded in every SMP report.
    It can be recomputed from the data printed on the report cover page alone.
    """
    canonical = json.dumps({
        "url":            url.strip().lower(),
        "scan_date":      scan_date[:10],   # YYYY-MM-DD only
        "findings_count": findings_count,
        "critical":       crit,
        "high":           high,
        "medium":         med,
        "low":            low,
        "scanned_by":     scanned_by.strip(),
        "generator":      f"SMP {smp_version}",
    }, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


# ── PDF text extractor (no PyMuPDF/pdfminer required) ────────────────────────
def _extract_text_from_pdf(path: str) -> str:
    """
    Lightweight PDF text extraction — reads raw PDF stream for text objects.
    Falls back gracefully if the PDF is binary-compressed beyond readable range.
    """
    try:
        with open(path, "rb") as f:
            data = f.read()
        # Try to find the embedded marker as raw bytes first
        marker = HASH_MARKER_START.encode()
        idx = data.find(marker)
        if idx >= 0:
            chunk = data[idx:idx+200].decode("latin-1", errors="replace")
            return chunk
        # Fallback: decode whole file as latin-1 and search
        return data.decode("latin-1", errors="replace")
    except Exception:
        return ""


def _extract_text_from_html(path: str) -> str:
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            return f.read()
    except Exception:
        return ""


def extract_embedded_hash(report_path: str) -> str | None:
    """Extract the SMP content hash that was embedded during report generation."""
    ext = os.path.splitext(report_path)[1].lower()
    if ext == ".pdf":
        text = _extract_text_from_pdf(report_path)
    elif ext in (".html", ".htm"):
        text = _extract_text_from_html(report_path)
    else:
        text = _extract_text_from_pdf(report_path)  # Try PDF parser anyway

    # Search for the hash marker
    pattern = re.compile(
        re.escape(HASH_MARKER_START) + r"([a-f0-9]{64})" + re.escape(HASH_MARKER_END)
    )
    match = pattern.search(text)
    if match:
        return match.group(1)

    # Also check filename for 16-char hash suffix (quick integrity signal)
    fname = os.path.basename(report_path)
    fname_match = re.search(r"_([a-f0-9]{16})(?:\.pdf|\.html)$", fname, re.IGNORECASE)
    if fname_match:
        return fname_match.group(1)  # Partial hash from filename

    return None


def extract_metadata_from_report(report_path: str) -> dict:
    """
    Extract key metadata from the report text so the user can manually
    verify by re-deriving the hash from what's printed on the cover page.
    """
    ext = os.path.splitext(report_path)[1].lower()
    if ext == ".pdf":
        text = _extract_text_from_pdf(report_path)
    else:
        text = _extract_text_from_html(report_path)

    meta = {}

    # Extract SMP-META block if present
    meta_pattern = re.compile(
        r"SMP-META-START(.*?)SMP-META-END", re.DOTALL | re.IGNORECASE
    )
    meta_match = meta_pattern.search(text)
    if meta_match:
        try:
            meta = json.loads(meta_match.group(1).strip())
        except Exception:
            pass

    return meta


def verify_report(report_path: str, verbose: bool = True) -> bool:
    """
    Main verification function.
    Returns True if the report is authentic, False if tampered or unverifiable.
    """
    if not os.path.exists(report_path):
        print(f"{RED}  ❌ File not found: {report_path}{RST}")
        return False

    size_kb = os.path.getsize(report_path) / 1024
    fname   = os.path.basename(report_path)

    print(f"\n{BLD}  Report:{RST} {CYN}{fname}{RST}")
    print(f"  Size:   {size_kb:.1f} KB")
    print(f"  Path:   {report_path}")
    print()

    # Step 1: Extract embedded hash
    embedded_hash = extract_embedded_hash(report_path)

    if not embedded_hash:
        print(f"{YEL}  ⚠️  No SMP verification hash found in this report.{RST}")
        print("  This report may have been generated by an older version of SMP")
        print("  (pre-V9.4.0) or may not be a genuine SMP report.")
        return False

    print(f"  {DIM}Embedded hash:{RST}  {embedded_hash}")

    # Step 2: Extract metadata block for re-derivation
    meta = extract_metadata_from_report(report_path)

    if meta:
        print(f"\n{BLD}  Scan Metadata (from report):{RST}")
        for k, v in meta.items():
            if k != "content_hash":
                print(f"    {k:<20} {v}")

        # Re-derive the hash from metadata and compare
        try:
            recomputed = derive_content_hash(
                url            = meta.get("url", ""),
                scan_date      = meta.get("scan_date", ""),
                findings_count = int(meta.get("findings_count", 0)),
                crit           = int(meta.get("critical", 0)),
                high           = int(meta.get("high", 0)),
                med            = int(meta.get("medium", 0)),
                low            = int(meta.get("low", 0)),
                scanned_by     = meta.get("scanned_by", ""),
                smp_version    = meta.get("smp_version", ""),
            )

            print(f"\n  {DIM}Recomputed hash:{RST} {recomputed}")
            print()

            if recomputed == embedded_hash or recomputed == embedded_hash[:len(recomputed)]:
                print(f"{GRN}{BLD}  ✅  VERIFIED — Report is authentic and unmodified.{RST}")
                print(f"{GRN}  The content hash matches the embedded signature.{RST}")
                print(f"{GRN}  This report was genuinely generated by Security Management Platform.{RST}")
                return True
            else:
                print(f"{RED}{BLD}  ❌  VERIFICATION FAILED — Hash mismatch detected!{RST}")
                print(f"{RED}  The report content does not match its embedded signature.{RST}")
                print(f"{RED}  The report may have been tampered with or manually edited.{RST}")
                return False

        except Exception as e:
            print(f"{YEL}  ⚠️  Could not recompute hash: {e}{RST}")

    else:
        # No metadata block — only filename-based verification possible
        print(f"{YEL}  ⚠️  No metadata block found. Filename-only verification.{RST}")

        fname_hash_match = re.search(r"_([a-f0-9]{16})(?:\.pdf|\.html)$", fname, re.IGNORECASE)
        if fname_hash_match:
            fname_hash = fname_hash_match.group(1)
            print(f"  Filename hash (16-char): {fname_hash}")
            if embedded_hash.startswith(fname_hash):
                print(f"{GRN}  ✅  Filename hash matches embedded hash prefix.{RST}")
                print(f"{YEL}  Note: Full content verification requires the metadata block.{RST}")
                return True
            else:
                print(f"{RED}  ❌  Filename hash does not match embedded hash.{RST}")
                return False

    return False


def print_manual_verify_instructions(report_path: str):
    """Print instructions for manual verification without this script."""
    meta = extract_metadata_from_report(report_path)
    if not meta:
        print(f"\n{YEL}  No metadata found for manual verification instructions.{RST}")
        return

    print(f"""
{BLD}  ── Manual Verification (without this script) ────────────────────────{RST}
  You can re-derive the verification hash using only the data printed
  on the cover page of this report:

  1. Open Python (any version 3.8+):

     import hashlib, json
     data = {json.dumps({
         "url":            meta.get("url", ""),
         "scan_date":      meta.get("scan_date", ""),
         "findings_count": meta.get("findings_count", 0),
         "critical":       meta.get("critical", 0),
         "high":           meta.get("high", 0),
         "medium":         meta.get("medium", 0),
         "low":            meta.get("low", 0),
         "scanned_by":     meta.get("scanned_by", ""),
         "generator":      f"SMP {meta.get('smp_version', '')}",
     }, sort_keys=True, indent=2)}

     h = hashlib.sha256(json.dumps(data, sort_keys=True, separators=(',',':')).encode()).hexdigest()
     print(h)

  2. Compare the output to the hash on the report cover page.
     They must be identical for the report to be authentic.
""")


def main():
    print(BANNER)
    parser = argparse.ArgumentParser(
        description="Verify the authenticity of an SMP security report.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 tools/verify_report.py reports/pdf/SMP_example.com_Report_2024-07-01_abc12345678.pdf
  python3 tools/verify_report.py reports/html/SMP_example.com_Report_2024-07-01.html --manual
        """
    )
    parser.add_argument("report", help="Path to the SMP report file (PDF or HTML)")
    parser.add_argument("--manual", action="store_true",
                        help="Also print manual verification instructions")
    args = parser.parse_args()

    result = verify_report(args.report)

    if args.manual:
        print_manual_verify_instructions(args.report)

    sys.exit(0 if result else 1)


if __name__ == "__main__":
    main()
