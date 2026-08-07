import os
import ssl
import smtplib
import logging
import re
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.application import MIMEApplication

from tools.config_manager import load_settings
from tools.db_manager import add_log_entry, get_db_connection
from intelligence.cve_correlator import does_cve_match_active_targets

logger = logging.getLogger("smp")


def _build_message(subject, sender, receivers, body_text, body_html=None, attachment_path=None):
    """
    Build a MIME email message.

    Uses 'mixed' as the root content type when there is an attachment (required
    by RFC 2045 when combining multipart/alternative body with binary parts).
    Uses 'alternative' when there is no attachment.
    """
    if attachment_path and os.path.exists(attachment_path):
        # Root: multipart/mixed  →  child: multipart/alternative  →  text + html
        root = MIMEMultipart("mixed")
        alt = MIMEMultipart("alternative")
        alt.attach(MIMEText(body_text, "plain", "utf-8"))
        if body_html:
            alt.attach(MIMEText(body_html, "html", "utf-8"))
        root.attach(alt)

        # Attach the file
        filename = os.path.basename(attachment_path)
        try:
            with open(attachment_path, "rb") as f:
                part = MIMEApplication(f.read(), Name=filename)
            part["Content-Disposition"] = f'attachment; filename="{filename}"'
            root.attach(part)
            logger.info(f"Attached report '{filename}' to email.")
        except Exception as ae:
            logger.error(f"Failed to attach report to email: {ae}")
    else:
        # No attachment – simpler multipart/alternative is correct
        root = MIMEMultipart("alternative")
        root.attach(MIMEText(body_text, "plain", "utf-8"))
        if body_html:
            root.attach(MIMEText(body_html, "html", "utf-8"))

    root["Subject"] = subject
    root["From"] = sender
    # Support comma-separated list of recipients in the header
    root["To"] = ", ".join(receivers) if isinstance(receivers, list) else receivers
    return root


# Cache of already warned messages to avoid repeating the exact warning/error in the logs
_logged_alerts = set()


def test_smtp_connection():
    """
    Tests the SMTP connection and returns a (success: bool, message: str) tuple.
    Used by the UI settings tab 'Test Connection' button.
    """
    settings = load_settings()
    smtp_host  = settings.get("smtp_host", "")
    smtp_port  = int(settings.get("smtp_port", 587))
    smtp_user  = settings.get("smtp_user", "")
    smtp_pass  = settings.get("smtp_pass", "")
    smtp_ssl   = settings.get("smtp_ssl", False)
    sender     = settings.get("smtp_sender", "") or smtp_user
    receiver   = settings.get("smtp_receiver", "")

    if not smtp_host or not smtp_user or not smtp_pass:
        return False, "SMTP credentials not configured. Fill in host, user, and password."

    # Gmail-specific guidance
    gmail_hint = ""
    if "gmail" in smtp_host.lower():
        gmail_hint = (
            "\n\nGmail requires an APP PASSWORD (not your regular password):\n"
            "  1. Go to myaccount.google.com → Security\n"
            "  2. Enable 2-Step Verification\n"
            "  3. Go to App Passwords → create one for 'Mail'\n"
            "  4. Use the 16-character App Password here (spaces optional)\n"
            "  Docs: https://support.google.com/accounts/answer/185833"
        )

    try:
        if smtp_ssl or smtp_port == 465:
            context = ssl.create_default_context()
            server = smtplib.SMTP_SSL(smtp_host, smtp_port, timeout=15, context=context)
        else:
            server = smtplib.SMTP(smtp_host, smtp_port, timeout=15)
            server.ehlo()
            server.starttls(context=ssl.create_default_context())

        server.ehlo()
        server.login(smtp_user, smtp_pass)

        # Send a quick test email if receiver is configured
        if receiver:
            msg = _build_message(
                subject="SMP – SMTP Test Connection",
                sender=sender,
                receivers=[r.strip() for r in receiver.split(",") if r.strip()],
                body_text="This is a test email from the Security Management Platform.\nSMTP connection is working correctly.",
                body_html="<html><body><h2 style='color:#22c55e;'>✅ SMTP Connection Successful</h2>"
                          "<p>This is a test email from the Security Management Platform.</p></body></html>",
            )
            server.sendmail(sender, [r.strip() for r in receiver.split(",") if r.strip()], msg.as_string())

        server.quit()
        return True, f"✅ SMTP connection successful! Test email sent to {receiver}."

    except smtplib.SMTPAuthenticationError as e:
        detail = str(e)
        if "535" in detail or "Username and Password not accepted" in detail or "BadCredentials" in detail:
            msg = (f"Authentication failed — Gmail rejected the password.\n"
                   f"Error: {detail}{gmail_hint}")
        else:
            msg = f"Authentication failed: {detail}{gmail_hint}"
        return False, msg
    except smtplib.SMTPConnectError as e:
        return False, f"Cannot connect to {smtp_host}:{smtp_port} — {e}"
    except ssl.SSLError as e:
        return False, f"SSL/TLS error: {e}\nTry toggling smtp_ssl or changing the port."
    except Exception as e:
        return False, f"SMTP error: {e}"


def send_email_alert(subject, body_text, body_html=None, attachment_path=None, receiver_override=None):
    """
    Sends an email alert using the SMTP configuration in settings.json.

    Supports three TLS modes, selected automatically by smtp_port and smtp_ssl:
      • Port 465  / smtp_ssl=true   → SMTP_SSL  (implicit TLS)
      • Port 587  / smtp_ssl=false  → STARTTLS   (explicit TLS / default)
      • Any other / smtp_ssl=false  → plain SMTP (no TLS – not recommended)

    GMAIL NOTE: smtp_pass MUST be a 16-character App Password, not your regular
    Gmail password. Regular passwords are rejected since May 2022.
    Create one at: myaccount.google.com → Security → App Passwords
    """
    settings = load_settings()

    smtp_host    = settings.get("smtp_host", "")
    smtp_port    = int(settings.get("smtp_port", 587))
    smtp_user    = settings.get("smtp_user", "")
    smtp_pass    = settings.get("smtp_pass", "")
    sender       = settings.get("smtp_sender", "") or smtp_user
    receiver_raw = receiver_override or settings.get("smtp_receiver", "")
    receivers    = [r.strip() for r in receiver_raw.split(",") if r.strip()]

    if not all([smtp_host, smtp_user, smtp_pass, receivers]):
        return False
    smtp_ssl     = settings.get("smtp_ssl", False)
    smtp_servers = [
        {"host": smtp_host, "port": smtp_port, "ssl": smtp_ssl},
        {"host": settings.get("smtp_backup_host") or smtp_host, "port": int(settings.get("smtp_backup_port") or (465 if smtp_port==587 else 587)), "ssl": settings.get("smtp_backup_ssl") or False}
    ]

    try:
        msg = _build_message(subject, sender, receivers, body_text, body_html, attachment_path)

        for node in smtp_servers:
            host = node["host"]
            port = node["port"]
            use_ssl = node["ssl"]
            try:
                logger.info(f"Attempting to route security email through: {host}:{port}")
                if use_ssl or port == 465:
                    context = ssl.create_default_context()
                    server  = smtplib.SMTP_SSL(host, port, timeout=12, context=context)
                    server.ehlo()
                else:
                    server = smtplib.SMTP(host, port, timeout=12)
                    server.ehlo()
                    try:
                        server.starttls(context=ssl.create_default_context())
                        server.ehlo()
                    except smtplib.SMTPException:
                        logger.warning(f"SMTP server {host}:{port} does not support STARTTLS. Sending without TLS.")

                server.login(smtp_user, smtp_pass)
                server.sendmail(sender, receivers, msg.as_string())
                server.quit()

                logger.info(f"Email sent successfully through node: {host}.")
                add_log_entry("INFO", f"Email sent successfully through node: {host}.")
                _logged_alerts.clear()
                return True
            except Exception as routing_err:
                logger.warning(f"[⚠️ RELAY WARNING] Server node '{host}' failed to route payload: {routing_err}")

        # If all fail
        err_msg = "All available messaging channels exhausted. Notification delivery failed."
        if err_msg not in _logged_alerts:
            logger.error(err_msg)
            add_log_entry("ERROR", err_msg)
            _logged_alerts.add(err_msg)
            with open("logs/error.log", "", encoding="utf-8") as err_log_stream:
                err_log_stream.write("[SMTP ALERT ENGINE CRIT] All available messaging channels exhausted. Notification delivery failed.\n")
        return False

    except smtplib.SMTPConnectError as e:
        err_msg = f"SMTP Failed: Cannot connect to {smtp_host}:{smtp_port} — {e}"
        if err_msg not in _logged_alerts:
            logger.error(err_msg)
            add_log_entry("ERROR", err_msg)
            _logged_alerts.add(err_msg)
        return False
    except Exception as e:
        err_msg = f"SMTP Failed: {e}"
        if err_msg not in _logged_alerts:
            logger.error(err_msg)
            add_log_entry("ERROR", err_msg)
            _logged_alerts.add(err_msg)
        return False


def _build_professional_email_html(title, target_url, metadata, body_content):
    """Generates a professional, responsive HTML email template."""
    meta_html = "".join([f'<p style="margin:4px 0; color:#4B5563;"><strong>{k}:</strong> {v}</p>' for k, v in metadata.items()])
    return f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
    </head>
    <body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; background-color: #F3F4F6; margin: 0; padding: 20px;">
        <div style="max-width: 600px; margin: 0 auto; background-color: #ffffff; border-radius: 8px; overflow: hidden; box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1);">
            <div style="background-color: #111827; padding: 24px; text-align: center;">
                <h1 style="color: #ffffff; margin: 0; font-size: 24px; letter-spacing: 1px;">{title}</h1>
            </div>
            <div style="padding: 32px; color: #1f2937; line-height: 1.6;">
                <div style="background-color: #F9FAFB; border: 1px solid #E5E7EB; border-radius: 6px; padding: 16px; margin-bottom: 24px;">
                    <p style="margin:0 0 8px 0; font-size: 18px; color: #111827;"><strong>Target:</strong> <a href="{target_url}" style="color: #2563EB;">{target_url}</a></p>
                    {meta_html}
                </div>
                {body_content}
                <hr style="border: none; border-top: 1px solid #E5E7EB; margin: 32px 0;">
                <p style="font-size: 14px; color: #6B7280; text-align: center;">
                    Generated by Security Management Platform (SMP)<br>
                    Please review the attached PDF report for full details.
                </p>
            </div>
        </div>
    </body>
    </html>
    """

def process_alerts_for_scan(
    target, findings, new_findings_detected, severity_escalated,
    is_site_up, html_report_path=None, pdf_report_path=None
):
    """Evaluates scan findings and sends the appropriate email alert.
    
    STRICT MATCHING RULES:
    - Only sends email if there are confirmed HIGH or CRITICAL findings.
    - CVE correlation findings only count if CVSS >= 4.0 AND confidence >= 70.
    - Info-only scans do NOT trigger email alerts.
    """
    url = target["url"]

    # ── Case 1: Site/all scanners unavailable ───────────────────────────────
    if not is_site_up:
        subject = f"CRITICAL ALERT: Website Unavailable / Scan Failure — {url}"
        body_text = (
            f"Critical Security Alert\n\n"
            f"Target: {url}\n"
            f"Issue: Website Unavailable or All Scanners Failed\n"
            f"Severity: Critical\n"
            f"Recommendation: Review local logs and check target network connectivity.\n"
        )
        body_html = f"""
        <html><body>
            <h2 style="color:#ef4444;">Critical Security Alert</h2>
            <p><strong>Target:</strong> {url}</p>
            <p><strong>Issue:</strong> Website Unavailable or All Scanners Failed</p>
            <p><strong>Severity:</strong> Critical</p>
            <p><strong>Recommendation:</strong> Review local logs and check target network connectivity.</p>
        </body></html>
        """
        send_email_alert(subject, body_text, body_html)
        return

    # ── Strict filtering before email decision ──────────────────────────────
    # Only count findings that are genuinely confirmed and significant
    def _is_reportable(f):
        sev = f.get("severity", "Info")
        conf = f.get("confidence", 50)
        tool = f.get("source_tool", "")
        desc = f.get("description", "") or ""

        # Must be security-relevant severity
        if sev not in ("Low", "Medium", "High", "Critical"):
            return False

        # Must have sufficient confidence
        if conf < 70:
            return False

        # CVE Correlation: only report if CVSS >= 4.0 in the description
        if tool == "CVE Correlation":
            import re
            m = re.search(r"CVSS:\s*([0-9.]+)", desc)
            if m:
                try:
                    cvss = float(m.group(1))
                    if cvss < 4.0:
                        return False
                except ValueError:
                    return False
            else:
                # No CVSS in description — only allow High/Critical severity from CVE correlation
                if sev not in ("High", "Critical"):
                    return False

        return True

    reportable_findings = [f for f in findings if _is_reportable(f)]

    # ── Only send alert if there are actually reportable High/Critical findings or if report_email is set ──
    from tools.config_manager import load_settings
    report_email = load_settings().get("report_email", "")

    has_serious = any(f.get("severity") in ("High", "Critical") for f in reportable_findings)
    if not reportable_findings or not has_serious:
        if not report_email:
            logger.info(f"SMTP: No confirmed High/Critical findings for {url}. Email alert suppressed.")
            add_log_entry("INFO", f"SMTP: No confirmed findings requiring alert for {url}. Skipped.")
            return
        else:
            logger.info("SMTP: No High/Critical findings, but report_email is configured. Sending report.")

    # ── Case 2: New findings or severity escalation ─────────────────────────
    if new_findings_detected or severity_escalated:
        # Derive maximum severity across all reportable findings
        max_severity = "Info"
        sevs = [f["severity"] for f in reportable_findings]
        for s in ("Critical", "High", "Medium", "Low", "Info"):
            if s in sevs:
                max_severity = s
                break

        if new_findings_detected and severity_escalated:
            issue_title = "New Security Findings & Severity Escalation"
        elif new_findings_detected:
            issue_title = "New Security Findings Detected"
        else:
            issue_title = "Severity Escalation in Existing Findings"

        subject = f"{max_severity.upper()} SECURITY ALERT: {issue_title} on {url}"

        body_text = (
            f"Security Alert\n\n"
            f"Target: {url}\n"
            f"Issue: {issue_title}\n"
            f"Max Severity: {max_severity}\n"
            f"Confirmed Findings: {len(reportable_findings)}\n"
            f"Recommendation: Review the attached security report and patch vulnerabilities.\n"
        )

        from tools.config_manager import load_settings
        settings = load_settings()
        comp_name = target.get('company_name') or settings.get('company_name', 'Internal Security Team')
        tester = settings.get('tester_name', 'Security Auditor')
        qa = settings.get('qa_reviewer', 'QA Manager')
        
        meta = {
            "Company": comp_name,
            "Lead Tester": tester,
            "QA Reviewer": qa,
            "Findings": f"{len(reportable_findings)} Confirmed",
            "Max Severity": max_severity
        }

        # Keep email short by only showing Critical/High counts if there are too many
        crit_count = sum(1 for f in reportable_findings if f['severity'] == 'Critical')
        high_count = sum(1 for f in reportable_findings if f['severity'] == 'High')
        
        summary_html = f"<p>Scan completed. Found <strong>{crit_count} Critical</strong> and <strong>{high_count} High</strong> vulnerabilities.</p>"
        if crit_count == 0 and high_count == 0:
            summary_html += "<p>No Critical or High vulnerabilities detected.</p>"

        body_html = _build_professional_email_html(
            title="Security Alert",
            target_url=url,
            metadata=meta,
            body_content=summary_html
        )
        
        # Override receiver if report_email is explicitly set
        if report_email:
            send_email_alert(subject, body_text, body_html, attachment_path=pdf_report_path or html_report_path, receiver_override=report_email)
        else:
            send_email_alert(subject, body_text, body_html, attachment_path=pdf_report_path or html_report_path)
    elif report_email:
        # report_email is set but no serious findings were found
        subject = f"SCAN REPORT: Security Assessment for {url}"
        body_text = f"Security Scan Completed\n\nTarget: {url}\n\nPlease find the detailed security report attached."
        from tools.config_manager import load_settings
        settings = load_settings()
        comp_name = target.get('company_name') or settings.get('company_name', 'Internal Security Team')
        tester = settings.get('tester_name', 'Security Auditor')
        
        meta = {
            "Company": comp_name,
            "Lead Tester": tester,
            "Status": "Completed"
        }
        body_html = _build_professional_email_html(
            title="Security Scan Completed",
            target_url=url,
            metadata=meta,
            body_content="<p>The automated security scan has completed successfully. No critical issues triggered an immediate alert. Please find the detailed security report attached.</p>"
        )
        send_email_alert(subject, body_text, body_html, attachment_path=pdf_report_path or html_report_path, receiver_override=report_email)


def process_cve_alert(cve, severity, description, source):
    """Sends an email alert when a new Critical or High CVE is synchronised."""
    if severity not in ("Critical", "High"):
        return

    if not does_cve_match_active_targets(cve, description):
        return

    subject = f"NEW INTEL ALERT: {severity} {source} Advisory [{cve}]"
    body_text = (
        f"Threat Intelligence Alert\n\n"
        f"Intel Source: {source}\n"
        f"Advisory ID: {cve}\n"
        f"Severity: {severity}\n"
        f"Description: {description}\n"
        f"Recommendation: Review local cache and scan matching local assets.\n"
    )
    meta = {
        "Source": source,
        "Advisory ID": cve,
        "Severity": severity
    }
    
    body_content = f"""
        <p><strong>Description:</strong></p>
        <p style="background-color:#FEE2E2; padding:12px; border-left:4px solid #EF4444; color:#7F1D1D;">{description}</p>
        <p><strong>Recommendation:</strong> Review local cache and scan matching local assets.</p>
    """
    
    body_html = _build_professional_email_html(
        title="Intel Security Alert",
        target_url="Global Infrastructure",
        metadata=meta,
        body_content=body_content
    )
    send_email_alert(subject, body_text, body_html)


def scan_and_alert_matched_technology_cves(target_url, scan_id, smtp_config):
    """Improvement 9: Identifies intersections between CVEs and active local network technology frameworks."""
    db_conn = get_db_connection()
    db_cursor = db_conn.cursor()
    
    db_cursor.execute("SELECT name, version FROM technologies WHERE scan_id = ?", (scan_id,))
    active_tech_stack = db_cursor.fetchall()
    actionable_matches = []
    
    for tech_name, tech_ver in active_tech_stack:
        # Improvement 10: Enforce regular expression cleansing to eliminate downstream database injection vulnerabilities
        sanitized_name = re.sub(r'[^a-zA-Z0-9\s_\-]', '', tech_name)
        db_token = f"%{sanitized_name}%"
        
        db_cursor.execute(
            "SELECT cve, severity, description FROM cve_db.cves WHERE (description LIKE ? OR cve LIKE ?) AND severity IN ('Critical', 'High')",
            (db_token, db_token)
        )
        associated_cves = db_cursor.fetchall()
        for cve_id, severity, desc in associated_cves:
            actionable_matches.append({
                "tech": sanitized_name, "version": tech_ver or "Generic Build",
                "cve": cve_id, "severity": severity, "desc": desc
            })
            
    if not actionable_matches:
        return True # Exit early if system posture is verified secure

    # Construct HTML Notification Body Layout
    email_root = MIMEMultipart('alternative')
    email_root['Subject'] = f"⚠️ [SMP INTEL ALERT] Targeted Vulnerabilities Discovered: {target_url}"
    email_root['From'] = smtp_config['sender']
    email_root['To'] = smtp_config['receiver']
    
    table_rows = ""
    for item in actionable_matches:
        table_rows += f"<tr><td style='padding:8px; border-bottom:1px solid #E5E7EB;'><b>{item['tech']}</b> ({item['version']})</td><td style='padding:8px; border-bottom:1px solid #E5E7EB; color:#2563eb;'>{item['cve']}</td><td style='padding:8px; border-bottom:1px solid #E5E7EB;'><b style='color:#991b1b;'>{item['severity']}</b></td><td style='padding:8px; border-bottom:1px solid #E5E7EB; font-size:12px;'>{item['desc']}</td></tr>"

    body_content = f"""
        <p>The system cross-correlation matching engine identified critical matches targeting the infrastructure profile of the target.</p>
        <div style="overflow-x:auto;">
            <table style="width: 100%; border-collapse: collapse; text-align: left; font-size: 14px;">
                <thead>
                    <tr style="background: #F9FAFB;">
                        <th style="padding:10px; border-bottom:2px solid #E5E7EB;">Component</th>
                        <th style="padding:10px; border-bottom:2px solid #E5E7EB;">CVE ID</th>
                        <th style="padding:10px; border-bottom:2px solid #E5E7EB;">Severity</th>
                        <th style="padding:10px; border-bottom:2px solid #E5E7EB;">Description</th>
                    </tr>
                </thead>
                <tbody>
                    {table_rows}
                </tbody>
            </table>
        </div>
    """
    
    meta = {
        "Status": "Vulnerabilities Found",
        "Matches": f"{len(actionable_matches)} High/Critical CVEs"
    }

    html_markup = _build_professional_email_html(
        title="Targeted CVE Intersection Warning",
        target_url=target_url,
        metadata=meta,
        body_content=body_content
    )
    email_root.attach(MIMEText(html_markup, 'html'))
    
    # Improvement 11: Implement structured primary-to-secondary failover SMTP routing
    smtp_servers = [
        {"host": smtp_config['primary_host'], "port": smtp_config['primary_port']},
        {"host": smtp_config['backup_host'], "port": smtp_config['backup_port']}
    ]
    
    for node in smtp_servers:
        try:
            with smtplib.SMTP(node['host'], node['port'], timeout=12) as router:
                router.starttls()
                router.login(smtp_config['user'], smtp_config['pass'])
                router.sendmail(smtp_config['sender'], smtp_config['receiver'], email_root.as_string())
                print(f"[✅ ALERT SENT] Security email update successfully routed through node: {node['host']}" )
                return True
        except Exception as routing_err:
            print(f"[⚠️ RELAY WARNING] Server node '{node['host']}' failed to route payload: {str(routing_err)}")
            
    with open("logs/error.log", "", encoding="utf-8") as err_log_stream:
        err_log_stream.write("[SMTP ALERT ENGINE CRIT] All available messaging channels exhausted. Notification delivery failed.\n")
    return False
