"""
core/url_validator.py — Target URL Parsing, Canonicalization, and Destination Checks.

V9.5.11 Hardened URL & Destination Security Gate:
  1. Standard URL parsing and canonicalization.
  2. Strict scheme enforcement (HTTP and HTTPS only).
  3. Rejection of control characters, userinfo (credentials), malformed authorities,
     and invalid/out-of-range ports.
  4. Robust validation for IPv4, IPv6 (RFC 3986 bracketed literals), and IDNA domain names.
  5. Policy-aware destination checks defending against:
     - Cloud metadata services (e.g., 169.254.169.254, metadata.google.internal)
     - Loopback destinations (127.0.0.0/8, ::1, localhost)
     - Link-local destinations (169.254.0.0/16, fe80::/10)
     - Unspecified/broadcast addresses (0.0.0.0, 255.255.255.255)
     - Unauthorized private networks (10/8, 172.16/12, 192.168/16, fc00::/7, 100.64/10)
     - DNS rebinding attacks (resolving all IPs and re-validating at execution/redirect time)
  6. In-scope redirect enforcement resolving relative paths and validating every redirect hop.
"""

import ipaddress
import logging
import re
import socket
import urllib.parse
from dataclasses import dataclass
from typing import Any, List, Optional, Set, Tuple, Union

from tools.errors import SMPInvalidTargetError

logger = logging.getLogger("smp.url_validator")

# Supported URL schemes
ALLOWED_SCHEMES = {"http", "https"}

# Cloud metadata destinations (IPs and hostnames) that must NEVER be accessed
CLOUD_METADATA_IPS = {
    ipaddress.ip_address("169.254.169.254"),   # AWS, GCP, Azure, OpenStack, etc.
    ipaddress.ip_address("100.100.100.200"),   # Alibaba Cloud
    ipaddress.ip_address("169.254.169.250"),
    ipaddress.ip_address("169.254.169.251"),
    ipaddress.ip_address("169.254.169.253"),
    ipaddress.ip_address("fd00:ec2::254"),     # AWS IPv6 metadata
}

CLOUD_METADATA_HOSTS = {
    "metadata.google.internal",
    "metadata",
    "instance-data",
}

CARRIER_GRADE_NAT = ipaddress.IPv4Network("100.64.0.0/10")


@dataclass(frozen=True)
class ParsedTarget:
    """Canonical representation of a validated target."""
    url: str
    scheme: str
    host: str
    port: int
    raw_host: str
    is_ip: bool
    ip_address: Optional[Union[ipaddress.IPv4Address, ipaddress.IPv6Address]]
    path: str
    query: str


def parse_and_canonicalize_url(url: str, require_scheme: bool = True) -> ParsedTarget:
    """
    Standard URL parsing, validation, and canonicalization.

    Enforces:
      - Valid HTTP or HTTPS scheme
      - Valid hostname, IPv4 dot-decimal, or IPv6 literal
      - Valid port (1-65535)
      - Rejection of control characters, userinfo (credentials), and malformed authorities

    Raises SMPInvalidTargetError on any validation failure.
    """
    if not url or not isinstance(url, str):
        raise SMPInvalidTargetError("Target URL cannot be empty or non-string")

    # 1. Reject ASCII control characters and DEL (< 32, 127)
    if any(ord(c) < 32 or ord(c) == 127 for c in url):
        raise SMPInvalidTargetError("Target URL contains forbidden control characters")

    raw = url.strip()
    if not raw:
        raise SMPInvalidTargetError("Target URL cannot be empty")

    # Whitespace inside URL is forbidden
    if any(c.isspace() for c in raw):
        raise SMPInvalidTargetError("Target URL cannot contain internal whitespace")

    # Reject mismatched IPv6 brackets before urlsplit
    if "[" in raw or "]" in raw:
        if raw.count("[") < raw.count("]"):
            raise SMPInvalidTargetError("Malformed IPv6 authority: unexpected closing bracket ']'")
        if raw.count("[") > raw.count("]"):
            raise SMPInvalidTargetError("Malformed IPv6 authority: missing closing bracket ']'")

    # 2. Parse URL with standard urlsplit
    try:
        parsed = urllib.parse.urlsplit(raw)
    except Exception as e:
        raise SMPInvalidTargetError(f"Malformed URL structure / Malformed authority (Invalid IPv6): {e}")

    # 3. Scheme validation
    scheme = parsed.scheme.lower()
    if require_scheme and not scheme:
        raise SMPInvalidTargetError("Target URL must specify a scheme (http:// or https://)")

    if scheme and scheme not in ALLOWED_SCHEMES:
        raise SMPInvalidTargetError(f"Unsupported scheme '{scheme}'. Only http and https are permitted.")

    if not scheme:
        scheme = "http"

    # 4. Userinfo / credentials check
    if parsed.username is not None or parsed.password is not None or "@" in parsed.netloc:
        raise SMPInvalidTargetError("Userinfo/credentials (user:pass@) are not allowed in target URLs")

    # 5. Authority / Host extraction & checks
    netloc = parsed.netloc
    if not netloc:
        raise SMPInvalidTargetError("Target URL must contain a valid authority / hostname")

    # Detect IPv6 brackets in netloc
    is_ipv6_literal = False
    raw_host = ""
    port_str = None

    if netloc.startswith("["):
        closing_idx = netloc.find("]")
        if closing_idx == -1:
            raise SMPInvalidTargetError("Malformed IPv6 authority: missing closing bracket ']'")
        raw_host = netloc[1:closing_idx]
        is_ipv6_literal = True
        remaining = netloc[closing_idx + 1:]
        if remaining:
            if not remaining.startswith(":"):
                raise SMPInvalidTargetError("Malformed authority after IPv6 literal")
            port_str = remaining[1:]
    else:
        if "]" in netloc:
            raise SMPInvalidTargetError("Malformed authority: unexpected closing bracket ']'")
        if ":" in netloc:
            parts = netloc.split(":")
            if len(parts) > 2:
                raise SMPInvalidTargetError("Malformed authority: multiple colons in hostname (IPv6 literals must be bracketed)")
            raw_host = parts[0]
            port_str = parts[1]
        else:
            raw_host = netloc

    if not raw_host:
        raise SMPInvalidTargetError("Target URL must have a valid non-empty hostname")

    # 6. Port validation
    port = 443 if scheme == "https" else 80
    if port_str is not None:
        if not port_str:
            raise SMPInvalidTargetError("Malformed empty port specification in target URL")
        try:
            port = int(port_str)
        except ValueError:
            raise SMPInvalidTargetError(f"Invalid non-numeric port '{port_str}' in target URL")
        if port < 1 or port > 65535:
            raise SMPInvalidTargetError(f"Port '{port}' out of range. Must be between 1 and 65535.")

    # 7. Host validation and canonicalization (IPv4, IPv6, or Domain)
    is_ip = False
    ip_obj = None
    canonical_host = ""

    # Check for IPv6
    if is_ipv6_literal:
        try:
            ip_obj = ipaddress.IPv6Address(raw_host)
            is_ip = True
            canonical_host = ip_obj.compressed.lower()
        except ValueError:
            raise SMPInvalidTargetError(f"Invalid IPv6 literal address '[{raw_host}]'")

    # Check for IPv4
    elif _is_potential_ipv4(raw_host):
        try:
            # Enforce strict 4-octet dot-decimal without leading zeros
            parts = raw_host.split(".")
            if len(parts) != 4:
                raise ValueError("IPv4 must have exactly 4 octets")
            for p in parts:
                if not p.isdigit() or (len(p) > 1 and p.startswith("0")):
                    raise ValueError("Leading zeros, hex representations, or non-digits not permitted in IPv4 octet")
                octet_val = int(p)
                if octet_val < 0 or octet_val > 255:
                    raise ValueError("IPv4 octet out of range (0-255)")
            ip_obj = ipaddress.IPv4Address(raw_host)
            is_ip = True
            canonical_host = str(ip_obj)
        except ValueError as ip_err:
            raise SMPInvalidTargetError(f"Invalid IPv4 address '{raw_host}': {ip_err}")

    # Check for Domain name
    else:
        # Decimal integer IP bypass check (e.g. 2130706433)
        if raw_host.isdigit():
            raise SMPInvalidTargetError(f"Invalid numeric hostname representation '{raw_host}'")
        if raw_host.lower().startswith("0x") and all(c in "0123456789abcdef" for c in raw_host[2:]):
            raise SMPInvalidTargetError(f"Invalid hex numeric hostname representation '{raw_host}'")

        # Detect consecutive dots and empty labels before IDNA
        if ".." in raw_host or raw_host.startswith("."):
            raise SMPInvalidTargetError("Hostname cannot contain consecutive dots or empty labels")

        # Check label lengths
        for lab in raw_host.split("."):
            if len(lab) > 63:
                raise SMPInvalidTargetError(f"Domain label '{lab[:10]}...' exceeds maximum 63 characters")

        # Normalize via IDNA (converts unicode labels to ASCII punycode)
        try:
            canonical_host = raw_host.encode("idna").decode("ascii").lower()
        except Exception:
            raise SMPInvalidTargetError(f"Invalid internationalized domain name '{raw_host}'")

        if canonical_host.endswith("."):
            canonical_host = canonical_host[:-1]

        # Validate domain labels
        _validate_domain_syntax(canonical_host)

    # 8. Path and Query Canonicalization
    path = parsed.path
    if not path:
        path = "/"
    elif not path.startswith("/"):
        path = "/" + path

    query = parsed.query

    # Build canonical netloc
    default_port = (scheme == "http" and port == 80) or (scheme == "https" and port == 443)
    if is_ip and isinstance(ip_obj, ipaddress.IPv6Address):
        canonical_authority = f"[{canonical_host}]" if default_port else f"[{canonical_host}]:{port}"
    else:
        canonical_authority = canonical_host if default_port else f"{canonical_host}:{port}"

    canonical_url = f"{scheme}://{canonical_authority}{path}"
    if query:
        canonical_url += f"?{query}"

    return ParsedTarget(
        url=canonical_url,
        scheme=scheme,
        host=canonical_host,
        port=port,
        raw_host=raw_host,
        is_ip=is_ip,
        ip_address=ip_obj,
        path=path,
        query=query,
    )


def _is_potential_ipv4(host: str) -> bool:
    """Returns True if string looks like an IPv4 address (digits, hex, dots, or numeric-prefix)."""
    if not host:
        return False
    parts = host.split(".")
    if len(parts) >= 2:
        if all(
            p.isdigit() or (p.lower().startswith("0x") and all(c in "0123456789abcdef" for c in p[2:]))
            for p in parts if p
        ):
            return True
        numeric_count = sum(1 for p in parts if p.isdigit())
        if numeric_count >= 2 and (len(parts) == 4 or parts[-1].isdigit()):
            return True
    return False


def _validate_domain_syntax(domain: str) -> None:
    """Enforce RFC 1034 / 1123 domain syntax rules."""
    # Strip optional trailing root dot
    d = domain[:-1] if domain.endswith(".") else domain
    if not d:
        raise SMPInvalidTargetError("Hostname cannot be empty")

    if len(d) > 253:
        raise SMPInvalidTargetError(f"Hostname length ({len(d)}) exceeds maximum allowed (253 characters)")

    labels = d.split(".")
    for label in labels:
        if not label:
            raise SMPInvalidTargetError("Hostname cannot contain consecutive dots or empty labels")
        if len(label) > 63:
            raise SMPInvalidTargetError(f"Domain label '{label}' exceeds maximum 63 characters")
        if label.startswith("-") or label.endswith("-"):
            raise SMPInvalidTargetError(f"Domain label '{label}' cannot start or end with a hyphen")
        if not re.match(r"^[a-z0-9_-]+$", label):
            raise SMPInvalidTargetError(f"Domain label '{label}' contains invalid characters")


# ─────────────────────────────────────────────────────────────────────────────
# Destination Security Checks (SSRF, Metadata, Loopback, Private, DNS Rebind)
# ─────────────────────────────────────────────────────────────────────────────

def is_cloud_metadata(ip_or_host: Union[str, ipaddress.IPv4Address, ipaddress.IPv6Address]) -> bool:
    """Check if address or host targets cloud metadata services."""
    if isinstance(ip_or_host, str):
        lower_host = ip_or_host.strip().lower()
        if lower_host in CLOUD_METADATA_HOSTS:
            return True
        try:
            ip_obj = ipaddress.ip_address(lower_host)
            return ip_obj in CLOUD_METADATA_IPS
        except ValueError:
            return False
    elif isinstance(ip_or_host, (ipaddress.IPv4Address, ipaddress.IPv6Address)):
        return ip_or_host in CLOUD_METADATA_IPS
    return False


def is_loopback_destination(ip_or_host: Union[str, ipaddress.IPv4Address, ipaddress.IPv6Address]) -> bool:
    """Check if address or host targets loopback interfaces."""
    if isinstance(ip_or_host, str):
        lower_host = ip_or_host.strip().lower()
        if lower_host == "localhost" or lower_host.endswith(".localhost"):
            return True
        try:
            ip_obj = ipaddress.ip_address(lower_host)
            return ip_obj.is_loopback
        except ValueError:
            return False
    elif isinstance(ip_or_host, (ipaddress.IPv4Address, ipaddress.IPv6Address)):
        return ip_or_host.is_loopback
    return False


def is_link_local_destination(ip_or_host: Union[str, ipaddress.IPv4Address, ipaddress.IPv6Address]) -> bool:
    """Check if address targets link-local network."""
    if isinstance(ip_or_host, str):
        try:
            ip_obj = ipaddress.ip_address(ip_or_host.strip())
            return ip_obj.is_link_local
        except ValueError:
            return False
    elif isinstance(ip_or_host, (ipaddress.IPv4Address, ipaddress.IPv6Address)):
        return ip_or_host.is_link_local
    return False


def is_unspecified_destination(ip_or_host: Union[str, ipaddress.IPv4Address, ipaddress.IPv6Address]) -> bool:
    """Check if address targets unspecified (0.0.0.0, ::) or broadcast (255.255.255.255)."""
    if isinstance(ip_or_host, str):
        try:
            ip_obj = ipaddress.ip_address(ip_or_host.strip())
            return ip_obj.is_unspecified or str(ip_obj) == "255.255.255.255"
        except ValueError:
            return False
    elif isinstance(ip_or_host, (ipaddress.IPv4Address, ipaddress.IPv6Address)):
        return ip_or_host.is_unspecified or str(ip_or_host) == "255.255.255.255"
    return False


def is_private_destination(ip_or_host: Union[str, ipaddress.IPv4Address, ipaddress.IPv6Address]) -> bool:
    """Check if address belongs to private RFC 1918 / ULA / CGNAT ranges."""
    if isinstance(ip_or_host, str):
        try:
            ip_obj = ipaddress.ip_address(ip_or_host.strip())
        except ValueError:
            return False
    else:
        ip_obj = ip_or_host

    if ip_obj.is_private:
        return True
    if isinstance(ip_obj, ipaddress.IPv4Address) and ip_obj in CARRIER_GRADE_NAT:
        return True
    return False


def check_destination_ip(
    ip_obj: Union[ipaddress.IPv4Address, ipaddress.IPv6Address],
    allow_private: bool = False,
    allow_loopback: bool = False,
    scope_engine: Optional[Any] = None,
) -> Tuple[bool, str]:
    """
    Evaluate a concrete IP destination against security boundaries.
    """
    # 1. Cloud metadata is strictly forbidden
    if is_cloud_metadata(ip_obj):
        return False, f"Destination '{ip_obj}' is a protected cloud metadata service (forbidden)"

    # 2. Unspecified / Broadcast is forbidden
    if is_unspecified_destination(ip_obj):
        return False, f"Destination '{ip_obj}' is unspecified or broadcast (forbidden)"

    # 3. Link-local is forbidden
    if is_link_local_destination(ip_obj):
        return False, f"Destination '{ip_obj}' is a link-local address (forbidden)"

    # 4. Loopback check
    if is_loopback_destination(ip_obj):
        if not allow_loopback:
            return False, f"Destination '{ip_obj}' is a loopback address (forbidden by policy)"
        return True, ""

    # 5. Private IP check
    if is_private_destination(ip_obj):
        if not allow_private:
            # Check if engagement scope explicitly authorizes this private destination
            if scope_engine is not None:
                scope_ok, _ = scope_engine.is_allowed(str(ip_obj), "PASSIVE")
                if not scope_ok:
                    return False, f"Destination '{ip_obj}' is a private address not permitted by scope"
            else:
                return False, f"Destination '{ip_obj}' is a private network address (forbidden by policy)"

    return True, ""


def resolve_and_validate_destination(
    host: str,
    allow_private: bool = False,
    allow_loopback: bool = False,
    scope_engine: Optional[Any] = None,
) -> Tuple[bool, str, List[str]]:
    """
    Resolve all IP addresses for a host and validate each one against forbidden destinations.
    Defends against DNS rebinding (rejecting if ANY resolved address is forbidden).
    """
    # Hostname metadata check
    if is_cloud_metadata(host):
        return False, f"Hostname '{host}' targets cloud metadata service (forbidden)", []

    # If already an IP address, validate directly without network resolution
    try:
        direct_ip = ipaddress.ip_address(host)
        allowed, reason = check_destination_ip(
            direct_ip,
            allow_private=allow_private,
            allow_loopback=allow_loopback,
            scope_engine=scope_engine,
        )
        return allowed, reason, [str(direct_ip)]
    except ValueError:
        pass

    # Hostname resolution (both IPv4 and IPv6)
    resolved_ips: List[str] = []
    try:
        addr_info = socket.getaddrinfo(host, None, family=socket.AF_UNSPEC, type=socket.SOCK_STREAM)
        for family, _, _, _, sockaddr in addr_info:
            ip_str = sockaddr[0]
            if ip_str not in resolved_ips:
                resolved_ips.append(ip_str)
    except socket.gaierror as e:
        return False, f"DNS resolution failed for '{host}': {e}", []
    except Exception as e:
        return False, f"DNS resolution error for '{host}': {e}", []

    if not resolved_ips:
        return False, f"DNS resolution returned no IP addresses for '{host}'", []

    # Defend against DNS rebinding / mixed-A records: every resolved IP must pass
    for ip_str in resolved_ips:
        try:
            ip_obj = ipaddress.ip_address(ip_str)
        except ValueError:
            return False, f"Invalid resolved IP '{ip_str}' for host '{host}'", resolved_ips

        allowed, reason = check_destination_ip(
            ip_obj,
            allow_private=allow_private,
            allow_loopback=allow_loopback,
            scope_engine=scope_engine,
        )
        if not allowed:
            return False, f"DNS rebinding/destination violation: {reason}", resolved_ips

    return True, "", resolved_ips


def check_destination_allowed(
    target: Union[str, ParsedTarget],
    policy: Optional[Any] = None,
    scope_engine: Optional[Any] = None,
    allow_private: Optional[bool] = None,
    allow_loopback: Optional[bool] = None,
    resolve_dns: Optional[bool] = None,
) -> Tuple[bool, str]:
    """
    High-level destination security gate evaluating a target string or ParsedTarget.
    Evaluates IP destinations against cloud metadata, loopback, link-local,
    unspecified, and private network boundaries.
    Defends against DNS rebinding when appropriate for product policy.
    """
    if isinstance(target, str):
        try:
            parsed = parse_and_canonicalize_url(target)
        except SMPInvalidTargetError as e:
            return False, str(e)
    else:
        parsed = target

    # Determine policy flags
    priv_allowed = allow_private if allow_private is not None else False
    loop_allowed = allow_loopback if allow_loopback is not None else False
    rebind_enforce = resolve_dns if resolve_dns is not None else False

    if policy is not None:
        policy_data = getattr(policy, "data", policy) if hasattr(policy, "data") else policy
        if isinstance(policy_data, dict):
            if allow_private is None and "allow_private" in policy_data:
                priv_allowed = bool(policy_data["allow_private"])
            if allow_loopback is None and "allow_loopback" in policy_data:
                loop_allowed = bool(policy_data["allow_loopback"])
            if resolve_dns is None and "enforce_dns_rebinding" in policy_data:
                rebind_enforce = bool(policy_data["enforce_dns_rebinding"])

    # If the target is a concrete IP address, check it directly
    if parsed.is_ip and parsed.ip_address is not None:
        return check_destination_ip(
            parsed.ip_address,
            allow_private=priv_allowed,
            allow_loopback=loop_allowed,
            scope_engine=scope_engine,
        )

    # Check known metadata hostnames
    if is_cloud_metadata(parsed.host):
        return False, f"Hostname '{parsed.host}' targets cloud metadata service (forbidden)"

    # Check loopback hostnames
    if is_loopback_destination(parsed.host):
        if not loop_allowed:
            return False, f"Hostname '{parsed.host}' is a loopback destination (forbidden by policy)"

    # If DNS rebinding defense is enforced by policy or explicitly requested
    if rebind_enforce:
        allowed, reason, _ = resolve_and_validate_destination(
            parsed.host,
            allow_private=priv_allowed,
            allow_loopback=loop_allowed,
            scope_engine=scope_engine,
        )
        return allowed, reason

    return True, ""


def validate_redirect_destination(
    original_url: str,
    redirect_target: str,
    scope_engine: Optional[Any] = None,
    scanner_activity: Optional[Any] = None,
    allow_private: bool = False,
    allow_loopback: bool = False,
    enforce_dns_rebinding: bool = False,
) -> Tuple[bool, str, Optional[str]]:
    """
    Validate an HTTP redirect immediately prior to following it.

    1. Resolves relative redirects against the original target base URL.
    2. Parses and canonicalizes the destination URL.
    3. Rejects control characters, userinfo, and unsupported schemes.
    4. Evaluates destination against metadata, loopback, link-local, and private boundaries.
    5. Validates the normalized host against the engagement scope rules.

    Returns:
        tuple (allowed: bool, reason: str, canonical_redirect_url: Optional[str])
    """
    if not redirect_target or not isinstance(redirect_target, str):
        return False, "Empty or invalid redirect destination", None

    # Check for raw control characters
    if any(ord(c) < 32 or ord(c) == 127 for c in redirect_target):
        return False, "Malformed redirect destination: Target URL contains forbidden control characters", None

    # Check for unmatched brackets in redirect
    if "[" in redirect_target or "]" in redirect_target:
        if redirect_target.count("[") != redirect_target.count("]"):
            return False, "Malformed redirect destination: Malformed IPv6 authority: missing closing bracket", None

    orig = original_url.strip() if (original_url and isinstance(original_url, str)) else ""
    if orig and "://" not in orig:
        orig = f"http://{orig}"

    red = redirect_target.strip()
    has_scheme = False
    if ":" in red:
        possible_scheme = red.split(":", 1)[0].lower()
        if re.match(r"^[a-z][a-z0-9+.-]*$", possible_scheme):
            has_scheme = True

    if not has_scheme and not red.startswith("/") and not red.startswith("."):
        # Bare hostname or relative path without scheme
        red = f"http://{red}"

    # Resolve relative URL against original URL
    try:
        resolved_target = urllib.parse.urljoin(orig, red)
    except Exception as e:
        return False, f"Malformed redirect destination: {e}", None

    try:
        parsed_redirect = parse_and_canonicalize_url(resolved_target)
    except SMPInvalidTargetError as e:
        return False, f"Malformed redirect destination: {e}", None

    # Evaluate destination IP & hostname boundaries
    dest_ok, dest_reason = check_destination_allowed(
        parsed_redirect,
        scope_engine=scope_engine,
        allow_private=allow_private,
        allow_loopback=allow_loopback,
        resolve_dns=enforce_dns_rebinding,
    )
    if not dest_ok:
        return False, f"Redirect destination blocked: {dest_reason}", None

    # Enforce engagement scope on normalized host / redirect URL
    if scope_engine is not None:
        activity = scanner_activity if scanner_activity is not None else scope_engine.max_activity_level
        scope_ok, scope_reason = scope_engine.is_allowed(parsed_redirect.url, activity)
        if not scope_ok:
            return False, f"Redirect destination out of scope: {scope_reason}", None

    return True, "Redirect destination authorized", parsed_redirect.url


# ─────────────────────────────────────────────────────────────────────────────
# Safe HTTP Client / Redirect Handler
# ─────────────────────────────────────────────────────────────────────────────

try:
    import requests
    from requests.sessions import Session
    _REQUESTS_AVAILABLE = True
except ImportError:
    _REQUESTS_AVAILABLE = False


if _REQUESTS_AVAILABLE:
    class SafeRedirectSession(requests.Session):
        """
        Hardened requests.Session that enforces destination safety and scope
        on initial requests and every subsequent redirect hop.
        """
        def __init__(
            self,
            scope_engine: Optional[Any] = None,
            scan_policy: Optional[Any] = None,
            allow_private: bool = False,
            allow_loopback: bool = False,
            enforce_dns_rebinding: bool = False,
            *args,
            **kwargs,
        ):
            super().__init__(*args, **kwargs)
            self.scope_engine = scope_engine
            self.scan_policy = scan_policy
            self.allow_private = allow_private
            self.allow_loopback = allow_loopback
            self.enforce_dns_rebinding = enforce_dns_rebinding

        def send(self, request, **kwargs):
            allowed, reason, _ = validate_redirect_destination(
                original_url=request.url,
                redirect_target=request.url,
                scope_engine=self.scope_engine,
                allow_private=self.allow_private,
                allow_loopback=self.allow_loopback,
                enforce_dns_rebinding=self.enforce_dns_rebinding,
            )
            if not allowed:
                raise SMPInvalidTargetError(f"Outbound request blocked by security gate: {reason}")
            return super().send(request, **kwargs)

        def resolve_redirects(self, resp, req, stream=False, timeout=None, verify=True, cert=None, proxies=None, yield_requests=False, **adapter_kwargs):
            for redirect_req in super().resolve_redirects(
                resp, req, stream=stream, timeout=timeout, verify=verify, cert=cert, proxies=proxies, yield_requests=yield_requests, **adapter_kwargs
            ):
                url_to_check = redirect_req.url if hasattr(redirect_req, "url") else str(redirect_req)
                allowed, reason, canonical = validate_redirect_destination(
                    original_url=req.url,
                    redirect_target=url_to_check,
                    scope_engine=self.scope_engine,
                    allow_private=self.allow_private,
                    allow_loopback=self.allow_loopback,
                    enforce_dns_rebinding=self.enforce_dns_rebinding,
                )
                if not allowed:
                    raise SMPInvalidTargetError(f"Redirect blocked by security gate: {reason}")
                yield redirect_req


def create_safe_session(
    scope_engine: Optional[Any] = None,
    scan_policy: Optional[Any] = None,
    allow_private: bool = False,
    allow_loopback: bool = False,
    enforce_dns_rebinding: bool = False,
) -> Any:
    """Factory creating a hardened, scoped requests.Session."""
    if not _REQUESTS_AVAILABLE:
        raise RuntimeError("The 'requests' package is not installed.")
    return SafeRedirectSession(
        scope_engine=scope_engine,
        scan_policy=scan_policy,
        allow_private=allow_private,
        allow_loopback=allow_loopback,
        enforce_dns_rebinding=enforce_dns_rebinding,
    )

