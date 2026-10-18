"""
tests/test_url_destination_hardening.py — Comprehensive tests for V9.5.11 Hardened URL & Destination Gate.

Table-driven tests covering:
  1. IPv4 (dot-decimal, octal/leading zero rejection, hex rejection, bounds, non-digits)
  2. IPv6 (RFC 3986 bracketed literals, compression, unbracketed rejection, invalid hex)
  3. IDNA & Domain Names (Unicode conversion, Punycode, RFC 1034 label/length validation)
  4. Ports (default 80/443 canonicalization, custom ports 1..65535, invalid/out-of-range ports)
  5. Credentials / Userinfo (rejection of user:pass@ and user@)
  6. Malformed inputs and control characters (CRLF, null, tabs, internal whitespace, unsupported schemes)
  7. Destination security checks (cloud metadata, loopback, link-local, private, DNS rebinding with mocked DNS)
  8. HTTP redirect handling (relative paths, protocol-relative, in-scope, out-of-scope, metadata, loopback, SafeRedirectSession)

CRITICAL RULE: No tests contact real targets or live DNS servers (all DNS calls are strictly mocked).
"""

import ipaddress
import socket
import pytest
from unittest.mock import MagicMock, patch

from tools.errors import SMPInvalidTargetError
from core.scanner_manifest import ActivityLevel
from core.scan_policy import ScanPolicy
from core.scope_engine import ScopeEngine, ScopeRule
from core.url_validator import (
    parse_and_canonicalize_url,
    is_cloud_metadata,
    is_loopback_destination,
    is_link_local_destination,
    is_private_destination,
    is_unspecified_destination,
    check_destination_ip,
    check_destination_allowed,
    resolve_and_validate_destination,
    validate_redirect_destination,
    create_safe_session,
    SafeRedirectSession,
)


# ─────────────────────────────────────────────────────────────────────────────
# 1. Table-Driven IPv4 Tests
# ─────────────────────────────────────────────────────────────────────────────

@pytest.mark.parametrize(
    "url, expected_canonical, expected_host, expected_port",
    [
        ("http://192.168.1.1", "http://192.168.1.1/", "192.168.1.1", 80),
        ("http://192.168.1.1:80/test", "http://192.168.1.1/test", "192.168.1.1", 80),
        ("https://8.8.8.8:8443/api/v1?q=1", "https://8.8.8.8:8443/api/v1?q=1", "8.8.8.8", 8443),
        ("http://127.0.0.1/", "http://127.0.0.1/", "127.0.0.1", 80),
        ("https://1.1.1.1:443/", "https://1.1.1.1/", "1.1.1.1", 443),
        ("http://0.0.0.0:8000/", "http://0.0.0.0:8000/", "0.0.0.0", 8000),
    ],
)
def test_ipv4_valid(url, expected_canonical, expected_host, expected_port):
    target = parse_and_canonicalize_url(url)
    assert target.url == expected_canonical
    assert target.host == expected_host
    assert target.port == expected_port
    assert target.is_ip is True


@pytest.mark.parametrize(
    "url, reason_substr",
    [
        ("http://0177.0.0.1/", "Leading zeros"),            # Octal leading zero
        ("http://192.168.01.1/", "Leading zeros"),          # Octal leading zero in middle octet
        ("http://10.00.0.1/", "Leading zeros"),             # Double zero
        ("http://0x7f.0.0.1/", "Leading zeros, hex"),       # Hex octet
        ("http://0x7f000001/", "Invalid hex numeric"),      # Hex dword
        ("http://2130706433/", "Invalid numeric hostname"), # Decimal dword bypass
        ("http://256.0.0.1/", "out of range"),              # Out of range octet (>255)
        ("http://1.2.3.999/", "out of range"),              # Out of range octet
        ("http://300.1.1.1/", "out of range"),              # Out of range octet
        ("http://127.1/", "exactly 4 octets"),              # 2 octets
        ("http://10.1.2/", "exactly 4 octets"),             # 3 octets
        ("http://1.2.3.4.5/", "exactly 4 octets"),          # 5 octets
        ("http://192.168.1.a/", "non-digits not permitted"),# Alpha in octet
        ("http://192.168.1.-1/", "non-digits not permitted"),# Negative octet
    ],
)
def test_ipv4_rejected(url, reason_substr):
    with pytest.raises(SMPInvalidTargetError) as exc_info:
        parse_and_canonicalize_url(url)
    assert reason_substr.lower() in str(exc_info.value).lower()


# ─────────────────────────────────────────────────────────────────────────────
# 2. Table-Driven IPv6 Tests (RFC 3986 Bracketed Literals)
# ─────────────────────────────────────────────────────────────────────────────

@pytest.mark.parametrize(
    "url, expected_canonical, expected_host, expected_port",
    [
        ("http://[::1]", "http://[::1]/", "::1", 80),
        ("http://[::1]:80/path", "http://[::1]/path", "::1", 80),
        ("https://[::1]:443/", "https://[::1]/", "::1", 443),
        ("https://[2001:db8::1]:8443/status", "https://[2001:db8::1]:8443/status", "2001:db8::1", 8443),
        ("http://[2001:0db8:0000:0000:0000:0000:0000:0001]/", "http://[2001:db8::1]/", "2001:db8::1", 80),
        ("http://[fe80::1ff:fe23:4567:890a]:8080/", "http://[fe80::1ff:fe23:4567:890a]:8080/", "fe80::1ff:fe23:4567:890a", 8080),
    ],
)
def test_ipv6_valid(url, expected_canonical, expected_host, expected_port):
    target = parse_and_canonicalize_url(url)
    assert target.url == expected_canonical
    assert target.host == expected_host
    assert target.port == expected_port
    assert target.is_ip is True


@pytest.mark.parametrize(
    "url, reason_substr",
    [
        ("http://2001:db8::1/", "IPv6 literals must be bracketed"), # Unbracketed IPv6
        ("http://[2001:db8::1/", "missing closing bracket"),        # Missing closing bracket
        ("http://2001:db8::1]/", "unexpected closing bracket"),     # Missing opening bracket
        ("http://[gggg::1]/", "Invalid IPv6"),                      # Non-hex characters
        ("http://[::zz]/", "Invalid IPv6"),                         # Non-hex characters
        ("http://[::1]trailing/", "Malformed authority"),           # Garbage after bracket
        ("http://[::1]:80:90/", "Invalid non-numeric port"),       # Extra colon in port
    ],
)
def test_ipv6_rejected(url, reason_substr):
    with pytest.raises(SMPInvalidTargetError) as exc_info:
        parse_and_canonicalize_url(url)
    assert reason_substr.lower() in str(exc_info.value).lower()


# ─────────────────────────────────────────────────────────────────────────────
# 3. Table-Driven IDNA and Domain Name Tests
# ─────────────────────────────────────────────────────────────────────────────

@pytest.mark.parametrize(
    "url, expected_canonical, expected_host",
    [
        ("http://example.com", "http://example.com/", "example.com"),
        ("https://sub.domain.example.com/api", "https://sub.domain.example.com/api", "sub.domain.example.com"),
        ("http://my-service-app.example.com:8080/", "http://my-service-app.example.com:8080/", "my-service-app.example.com"),
        ("http://service_name.internal/", "http://service_name.internal/", "service_name.internal"),
        ("http://münchen.de/", "http://xn--mnchen-3ya.de/", "xn--mnchen-3ya.de"),      # German umlaut
        ("http://россия.рф/", "http://xn--h1alffa9f.xn--p1ai/", "xn--h1alffa9f.xn--p1ai"), # Cyrillic IDNA
        ("http://xn--mnchen-3ya.de/", "http://xn--mnchen-3ya.de/", "xn--mnchen-3ya.de"), # Pre-encoded punycode
        ("http://example.com./", "http://example.com/", "example.com"),                   # Trailing dot stripped
    ],
)
def test_domain_valid(url, expected_canonical, expected_host):
    target = parse_and_canonicalize_url(url)
    assert target.url == expected_canonical
    assert target.host == expected_host
    assert target.is_ip is False


@pytest.mark.parametrize(
    "url, reason_substr",
    [
        ("http://example..com/", "consecutive dots"),              # Consecutive dots
        ("http://..example.com/", "consecutive dots"),             # Leading empty label
        ("http://-bad.com/", "cannot start or end with a hyphen"), # Leading hyphen
        ("http://bad-.com/", "cannot start or end with a hyphen"), # Trailing hyphen
        ("http://sub.-bad-.com/", "cannot start or end with a hyphen"),
        ("http://" + "a" * 64 + ".com/", "exceeds maximum 63"),   # Label > 63 chars
        ("http://" + ("a" * 60 + ".") * 5 + "com/", "exceeds maximum allowed"), # Host > 253 chars
        ("http://bad*host.com/", "invalid characters"),            # Asterisk in label
        ("http://bad$host.com/", "invalid characters"),            # Dollar sign in label
        ("http://bad!host.com/", "invalid characters"),            # Exclamation mark
        ("http:///path", "valid authority"),                       # Empty authority
    ],
)
def test_domain_rejected(url, reason_substr):
    with pytest.raises(SMPInvalidTargetError) as exc_info:
        parse_and_canonicalize_url(url)
    assert reason_substr.lower() in str(exc_info.value).lower()


# ─────────────────────────────────────────────────────────────────────────────
# 4. Table-Driven Port Tests
# ─────────────────────────────────────────────────────────────────────────────

@pytest.mark.parametrize(
    "url, expected_canonical, expected_port",
    [
        ("http://example.com:80/", "http://example.com/", 80),          # Default HTTP stripped
        ("https://example.com:443/", "https://example.com/", 443),      # Default HTTPS stripped
        ("http://example.com:443/", "http://example.com:443/", 443),    # Non-default 443 on HTTP preserved
        ("https://example.com:80/", "https://example.com:80/", 80),     # Non-default 80 on HTTPS preserved
        ("http://example.com:1/", "http://example.com:1/", 1),          # Port 1
        ("http://example.com:65535/", "http://example.com:65535/", 65535), # Port 65535
        ("http://example.com:8080/app", "http://example.com:8080/app", 8080),
    ],
)
def test_port_valid(url, expected_canonical, expected_port):
    target = parse_and_canonicalize_url(url)
    assert target.url == expected_canonical
    assert target.port == expected_port


@pytest.mark.parametrize(
    "url, reason_substr",
    [
        ("http://example.com:0/", "out of range"),              # Port 0
        ("http://example.com:65536/", "out of range"),          # Port > 65535
        ("http://example.com:999999/", "out of range"),         # Large port
        ("http://example.com:-80/", "out of range"),           # Negative port
        ("http://example.com:abc/", "Invalid non-numeric port"),# Alpha port
        ("http://example.com:80a/", "Invalid non-numeric port"),# Alphanumeric port
        ("http://example.com:/", "Malformed empty port"),       # Empty port
    ],
)
def test_port_rejected(url, reason_substr):
    with pytest.raises(SMPInvalidTargetError) as exc_info:
        parse_and_canonicalize_url(url)
    assert reason_substr.lower() in str(exc_info.value).lower()


# ─────────────────────────────────────────────────────────────────────────────
# 5. Table-Driven Credentials / Userinfo Tests
# ─────────────────────────────────────────────────────────────────────────────

@pytest.mark.parametrize(
    "url",
    [
        "http://user:pass@example.com/",
        "http://admin@example.com/",
        "http://:secret@example.com/",
        "http://user:pass@192.168.1.1:8080/",
        "http://user:pass@[::1]/",
        "http://evil.com@legit.com/",
        "https://test%3Apass@example.com/",
    ],
)
def test_credentials_rejected(url):
    with pytest.raises(SMPInvalidTargetError) as exc_info:
        parse_and_canonicalize_url(url)
    assert "userinfo/credentials" in str(exc_info.value).lower()


def test_at_symbol_in_path_is_permitted():
    """An @ symbol in the URL path (e.g. social handle or routing) is not userinfo."""
    target = parse_and_canonicalize_url("http://example.com/@security/profile")
    assert target.url == "http://example.com/@security/profile"
    assert target.host == "example.com"


# ─────────────────────────────────────────────────────────────────────────────
# 6. Table-Driven Malformed Inputs & Control Characters Tests
# ─────────────────────────────────────────────────────────────────────────────

@pytest.mark.parametrize(
    "url, reason_substr",
    [
        ("http://example.com/\r\nInjected-Header: evil", "control characters"),
        ("http://example.com/\r/path", "control characters"),
        ("http://example.com/\n/path", "control characters"),
        ("http://example.com/\0admin", "control characters"),
        ("http://example.com/\tpath", "control characters"),
        ("http://example.com/\x7f", "control characters"),
        ("http://example .com/", "internal whitespace"),
        ("http://example.com/ my path", "internal whitespace"),
        ("", "cannot be empty"),
        ("   ", "cannot be empty"),
        ("ftp://example.com/", "Unsupported scheme 'ftp'"),
        ("file:///etc/passwd", "Unsupported scheme 'file'"),
        ("gopher://127.0.0.1:70/", "Unsupported scheme 'gopher'"),
        ("javascript:alert(1)", "Unsupported scheme 'javascript'"),
        ("data:text/html,payload", "Unsupported scheme 'data'"),
        ("ssh://git@github.com/", "Unsupported scheme 'ssh'"),
    ],
)
def test_malformed_and_control_chars_rejected(url, reason_substr):
    with pytest.raises(SMPInvalidTargetError) as exc_info:
        parse_and_canonicalize_url(url)
    assert reason_substr.lower() in str(exc_info.value).lower()


@pytest.mark.parametrize("invalid_arg", [None, 12345, ["http://example.com"], {}])
def test_non_string_target_rejected(invalid_arg):
    with pytest.raises(SMPInvalidTargetError):
        parse_and_canonicalize_url(invalid_arg)


# ─────────────────────────────────────────────────────────────────────────────
# 7. Table-Driven Destination Security Checks (Metadata, Loopback, SSRF, DNS)
# ─────────────────────────────────────────────────────────────────────────────

@pytest.mark.parametrize(
    "target_url, expected_error_substr",
    [
        # Cloud Metadata Services
        ("http://169.254.169.254/latest/meta-data/", "cloud metadata"),
        ("http://169.254.169.250/", "cloud metadata"),
        ("http://100.100.100.200/latest/meta-data/", "cloud metadata"), # Alibaba
        ("http://[fd00:ec2::254]/latest/meta-data/", "cloud metadata"), # AWS IPv6
        ("http://metadata.google.internal/computeMetadata/v1/", "cloud metadata"),
        ("http://metadata/", "cloud metadata"),
        ("http://instance-data/", "cloud metadata"),

        # Loopback interfaces
        ("http://127.0.0.1/", "loopback"),
        ("http://127.0.0.2:8080/", "loopback"),
        ("http://[::1]/", "loopback"),
        ("http://localhost/", "loopback"),
        ("http://app.localhost/", "loopback"),

        # Link-Local interfaces
        ("http://169.254.1.1/", "link-local"),
        ("http://[fe80::1]/", "link-local"),

        # Unspecified / Broadcast
        ("http://0.0.0.0/", "unspecified or broadcast"),
        ("http://[::]/", "unspecified or broadcast"),
        ("http://255.255.255.255/", "unspecified or broadcast"),

        # Private RFC 1918 / CGNAT / ULA (when allow_private=False)
        ("http://10.0.0.1/", "private"),
        ("http://172.16.0.1/", "private"),
        ("http://192.168.1.1/", "private"),
        ("http://100.64.1.1/", "private"), # CGNAT
        ("http://[fc00::1]/", "private"),  # IPv6 ULA
    ],
)
def test_forbidden_destinations_blocked_by_default(target_url, expected_error_substr):
    allowed, reason = check_destination_allowed(target_url)
    assert allowed is False
    assert expected_error_substr.lower() in reason.lower()


def test_allow_loopback_policy_flag():
    """Policy setting allow_loopback=True permits loopback when explicitly desired."""
    policy = ScanPolicy({
        "name": "LocalLabPolicy",
        "engagement_id": "ENG-LAB",
        "allow_loopback": True,
    })
    allowed, _ = check_destination_allowed("http://127.0.0.1:8000/", policy=policy)
    assert allowed is True

    # Cloud metadata remains blocked even if allow_loopback is True
    allowed_meta, _ = check_destination_allowed("http://169.254.169.254/", policy=policy)
    assert allowed_meta is False


def test_allow_private_policy_flag():
    """Policy setting allow_private=True permits RFC 1918 internal networks."""
    policy = ScanPolicy({
        "name": "InternalPolicy",
        "engagement_id": "ENG-INT",
        "allow_private": True,
    })
    allowed, _ = check_destination_allowed("http://192.168.1.50:8080/", policy=policy)
    assert allowed is True

    # Cloud metadata remains blocked even if allow_private is True
    allowed_meta, _ = check_destination_allowed("http://169.254.169.254/", policy=policy)
    assert allowed_meta is False


def test_private_destination_authorized_by_scope_engine():
    """Private target is allowed if the engagement scope rule explicitly authorizes it."""
    engine = ScopeEngine("eng_scope_test")
    engine.rules = [ScopeRule("R1", "cidr", "10.0.0.0/8", "allow")]

    allowed, reason = check_destination_allowed(
        "http://10.5.5.5/",
        scope_engine=engine,
        allow_private=False,
    )
    assert allowed is True


def test_dns_rebinding_mixed_records_denied(monkeypatch):
    """
    Defend against DNS rebinding: if a host resolves to both a public IP and a
    private/loopback IP (mixed A records), the entire destination is denied.
    Strictly mocked — no live network activity.
    """
    mock_addrs = [
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 80)),
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 80)),
    ]
    monkeypatch.setattr(socket, "getaddrinfo", lambda *args, **kwargs: mock_addrs)

    policy = ScanPolicy({
        "name": "StrictRebindPolicy",
        "engagement_id": "ENG-REBIND",
        "enforce_dns_rebinding": True,
    })

    allowed, reason = check_destination_allowed("http://rebind.attacker.com/", policy=policy)
    assert allowed is False
    assert "DNS rebinding" in reason or "loopback" in reason


def test_dns_rebinding_metadata_ip_denied(monkeypatch):
    """Host resolving to cloud metadata IP is rejected during rebinding check."""
    mock_addrs = [
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("169.254.169.254", 80)),
    ]
    monkeypatch.setattr(socket, "getaddrinfo", lambda *args, **kwargs: mock_addrs)

    policy = ScanPolicy({
        "name": "StrictRebindPolicy",
        "engagement_id": "ENG-REBIND",
        "enforce_dns_rebinding": True,
    })

    allowed, reason = check_destination_allowed("http://metadata.attacker.com/", policy=policy)
    assert allowed is False
    assert "cloud metadata service" in reason


def test_dns_rebinding_clean_ips_allowed(monkeypatch):
    """Host resolving exclusively to valid public IPs passes rebinding check."""
    mock_addrs = [
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 80)),
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.35", 80)),
    ]
    monkeypatch.setattr(socket, "getaddrinfo", lambda *args, **kwargs: mock_addrs)

    policy = ScanPolicy({
        "name": "StrictRebindPolicy",
        "engagement_id": "ENG-REBIND",
        "enforce_dns_rebinding": True,
    })

    allowed, reason = check_destination_allowed("http://valid-public.com/", policy=policy)
    assert allowed is True


# ─────────────────────────────────────────────────────────────────────────────
# 8. Table-Driven HTTP Redirect Tests
# ─────────────────────────────────────────────────────────────────────────────

@pytest.fixture
def scoped_engine():
    """ScopeEngine configured with *.target.com and 192.168.10.0/24."""
    engine = ScopeEngine("eng_redirect_test", max_activity_level=ActivityLevel.ACTIVE)
    engine.rules = [
        ScopeRule("R1", "domain", "*.target.com", "allow"),
        ScopeRule("R2", "cidr", "192.168.10.0/24", "allow"),
    ]
    return engine


@pytest.mark.parametrize(
    "original_url, redirect_target, expected_canonical",
    [
        ("http://target.com/login", "/dashboard", "http://target.com/dashboard"),
        ("http://target.com/a/b/", "../c", "http://target.com/a/c"),
        ("http://target.com/", "https://target.com/secure", "https://target.com/secure"),
        ("http://target.com/", "http://api.target.com/v1", "http://api.target.com/v1"),
        ("http://target.com/page", "?tab=settings", "http://target.com/page?tab=settings"),
    ],
)
def test_redirect_in_scope_allowed(scoped_engine, original_url, redirect_target, expected_canonical):
    allowed, reason, canonical = validate_redirect_destination(
        original_url=original_url,
        redirect_target=redirect_target,
        scope_engine=scoped_engine,
    )
    assert allowed is True
    assert canonical == expected_canonical


@pytest.mark.parametrize(
    "original_url, redirect_target, reason_substr",
    [
        # Out-of-scope external targets
        ("http://target.com/", "https://evil.com/phish", "out of scope"),
        ("http://target.com/", "http://unauthorized.target.org/", "out of scope"),

        # Protocol-relative redirect to cloud metadata
        ("http://target.com/", "//169.254.169.254/latest/meta-data", "cloud metadata"),

        # Redirect to loopback
        ("http://target.com/", "http://127.0.0.1:8080/admin", "loopback"),
        ("http://target.com/", "http://localhost/admin", "loopback"),

        # Redirect with embedded credentials
        ("http://target.com/", "http://user:pass@target.com/login", "userinfo/credentials"),

        # Redirect with control characters
        ("http://target.com/", "http://target.com/\r\nSet-Cookie: evil", "control characters"),

        # Unsupported redirect schemes
        ("http://target.com/", "javascript:alert(1)", "Unsupported scheme"),
        ("http://target.com/", "gopher://127.0.0.1:70/", "Unsupported scheme"),
        ("http://target.com/", "file:///etc/shadow", "Unsupported scheme"),

        # Malformed redirect authority
        ("http://target.com/", "http://[2001:db8::1/path", "missing closing bracket"),
    ],
)
def test_redirect_forbidden_blocked_before_network(scoped_engine, original_url, redirect_target, reason_substr):
    allowed, reason, canonical = validate_redirect_destination(
        original_url=original_url,
        redirect_target=redirect_target,
        scope_engine=scoped_engine,
    )
    assert allowed is False
    assert reason_substr.lower() in reason.lower()
    assert canonical is None


def test_scope_engine_check_redirect_method(scoped_engine):
    """ScopeEngine.check_redirect integrates with validate_redirect_destination."""
    # In scope
    ok, _ = scoped_engine.check_redirect("http://target.com/", "/account")
    assert ok is True

    # Out of scope
    ok, reason = scoped_engine.check_redirect("http://target.com/", "http://attacker.com/")
    assert ok is False
    assert "out of scope" in reason.lower()


def test_safe_redirect_session_blocks_forbidden_redirects(scoped_engine):
    """SafeRedirectSession intercepts and aborts forbidden redirects before dispatch."""
    session = create_safe_session(scope_engine=scoped_engine)
    assert isinstance(session, SafeRedirectSession)

    # 1. Sending to forbidden metadata target raises SMPInvalidTargetError
    dummy_req = MagicMock()
    dummy_req.url = "http://169.254.169.254/latest/meta-data"

    with pytest.raises(SMPInvalidTargetError) as exc_info:
        session.send(dummy_req)
    assert "blocked by security gate" in str(exc_info.value).lower()

    # 2. Sending to out-of-scope target raises SMPInvalidTargetError
    dummy_req.url = "http://evil.com/leak"
    with pytest.raises(SMPInvalidTargetError) as exc_info:
        session.send(dummy_req)
    assert "out of scope" in str(exc_info.value).lower()
