import re
import ipaddress
from typing import List, Tuple, Dict, Optional, Union, Any
from core.scanner_manifest import ActivityLevel
from core.authorization import is_authorization_currently_valid

# Strict ranking order for activity levels (least to most intrusive)
ACTIVITY_LEVEL_ORDER = {
    ActivityLevel.PASSIVE: 1,
    ActivityLevel.LOW_IMPACT_ACTIVE: 2,
    ActivityLevel.ACTIVE: 3,
    ActivityLevel.INTRUSIVE: 4,
    ActivityLevel.DESTRUCTIVE: 5,
}

def resolve_activity_level(val: Any) -> Optional[ActivityLevel]:
    """
    Resolve an ActivityLevel enum instance from an enum, string, or returns None.
    Rejects any unknown, empty, or unmapped value (fail closed).
    """
    if isinstance(val, ActivityLevel):
        return val
    if isinstance(val, str):
        try:
            return ActivityLevel(val.strip().upper())
        except (ValueError, KeyError, AttributeError):
            return None
    return None

def is_activity_allowed(
    scanner_activity: Any,
    max_allowed_activity: Any,
) -> Tuple[bool, str]:
    """
    Strict, documented comparison and enforcement of scanner activity against policy limit.
    
    Ranking order:
      1. PASSIVE
      2. LOW_IMPACT_ACTIVE
      3. ACTIVE
      4. INTRUSIVE
      5. DESTRUCTIVE
      
    Rules:
      - Both scanner_activity and max_allowed_activity must resolve to known ActivityLevel values.
      - Any unknown, None, malformed, or unmapped value immediately fails closed (denies by default).
      - Returns (True, "") if scanner_activity rank <= max_allowed_activity rank.
      - Returns (False, reason) if scanner_activity rank > max_allowed_activity rank, or if any value is invalid.
    """
    scanner_enum = resolve_activity_level(scanner_activity)
    if scanner_enum is None or scanner_enum not in ACTIVITY_LEVEL_ORDER:
        return False, f"Unknown scanner activity level: {scanner_activity!r} (denied by default)"

    limit_enum = resolve_activity_level(max_allowed_activity)
    if limit_enum is None or limit_enum not in ACTIVITY_LEVEL_ORDER:
        return False, f"Unknown policy activity level limit: {max_allowed_activity!r} (denied by default)"

    scanner_rank = ACTIVITY_LEVEL_ORDER[scanner_enum]
    limit_rank = ACTIVITY_LEVEL_ORDER[limit_enum]

    if scanner_rank > limit_rank:
        return (
            False,
            f"Scanner activity '{scanner_enum.value}' exceeds engagement policy limit '{limit_enum.value}'",
        )

    return True, ""

_UNSET = object()

class ScopeRule:
    def __init__(self, rule_id: str, rule_type: str, rule_value: str, action: str, priority: int = 100):
        self.rule_id = rule_id
        self.rule_type = rule_type
        self.rule_value = rule_value
        self.action = action
        self.priority = priority

class ScopeEngine:
    def __init__(
        self,
        engagement_id: str,
        policy: Optional[Any] = None,
        max_activity_level: Optional[Any] = _UNSET,
    ):
        self.engagement_id = engagement_id
        self.diagnostic: Optional[str] = None
        self.policy = policy
        self.max_activity_level: Optional[Union[ActivityLevel, str]] = None
        
        if policy is not None:
            self.set_policy(policy)
        elif max_activity_level is not _UNSET:
            self.set_max_activity_level(max_activity_level)
        else:
            self.max_activity_level = ActivityLevel.ACTIVE
            
        self.rules: List[ScopeRule] = self._load_scope_rules()

    def set_policy(self, policy: Any):
        """Set or update engagement scan policy and synchronize max activity level."""
        self.policy = policy
        if hasattr(policy, "data") and isinstance(policy.data, dict):
            self.max_activity_level = policy.data.get("activity_level_limit", ActivityLevel.ACTIVE)
        elif isinstance(policy, dict):
            self.max_activity_level = policy.get("activity_level_limit", ActivityLevel.ACTIVE)
        elif isinstance(policy, (ActivityLevel, str)):
            self.max_activity_level = policy
        else:
            self.max_activity_level = None

    def set_max_activity_level(self, level: Any):
        """Explicitly set maximum allowed activity level."""
        self.max_activity_level = level

    def _load_scope_rules(self) -> List[ScopeRule]:
        """Load and cache scope rules for engagement."""
        try:
            from tools.db_manager import get_authorizations_for_engagement
            
            rules = []
            authorizations = get_authorizations_for_engagement(self.engagement_id)
            if authorizations is None:
                self.diagnostic = "Authorizations query returned None"
                return []
            if not authorizations:
                return rules
            
            # Only use authorizations that are active, unexpired, and not revoked
            active_auths = [a for a in authorizations if is_authorization_currently_valid(a)]
            
            for auth in active_auths:
                scope = auth.get("scope", "")
                if not scope or not isinstance(scope, str):
                    continue
                rule_id = str(auth.get("auth_id", ""))
                
                # Determine rule type based on scope string
                if "/" in scope:
                    rule_type = "cidr"
                elif scope.startswith("*."):
                    rule_type = "domain"
                elif re.match(r'^\d+\.\d+\.\d+\.\d+$', scope):
                    rule_type = "ip"
                elif scope.startswith("http"):
                    rule_type = "url"
                else:
                    rule_type = "domain"
                    
                rules.append(ScopeRule(rule_id=rule_id, rule_type=rule_type, rule_value=scope, action="allow", priority=100))
                
            return rules
        except Exception as e:
            self.diagnostic = f"Authorization load failed: {type(e).__name__}"
            return []

    def _check_ip_in_cidr(self, target_ip: str, cidr: str) -> bool:
        try:
            return ipaddress.ip_address(target_ip) in ipaddress.ip_network(cidr)
        except ValueError:
            return False

    def _check_domain_match(self, target: str, pattern: str) -> bool:
        # Simple wildcard domain match (e.g. *.example.com)
        if pattern.startswith("*."):
            base_domain = pattern[2:]
            return target == base_domain or target.endswith("." + base_domain)
        return target == pattern

    def is_allowed(
        self,
        target: str,
        scanner_activity: Union[ActivityLevel, str],
        max_activity_level: Optional[Union[ActivityLevel, str]] = None,
    ) -> Tuple[bool, str]:
        """
        Check if target is allowed for given scanner activity under engagement policy.
        
        Enforces supplied scanner_activity against engagement policy's maximum activity level.
        Access is never granted based solely on a target string match.
        
        Args:
            target: str (URL, IP, domain)
            scanner_activity: ActivityLevel or string representation
            max_activity_level: Optional override for policy limit (defaults to self.max_activity_level)
            
        Returns:
            tuple (allowed: bool, reason: str)
        """
        # 1. Enforce scanner activity against engagement policy limit
        effective_limit = max_activity_level if max_activity_level is not None else self.max_activity_level
        activity_ok, act_reason = is_activity_allowed(scanner_activity, effective_limit)
        if not activity_ok:
            return False, act_reason

        # 2. Scope rules check
        if not self.rules:
            if self.diagnostic:
                return False, f"Scope check failed closed: {self.diagnostic}"
            # Default deny if no rules are configured
            return False, "No scope rules defined for engagement"
            
        sorted_rules = sorted(self.rules, key=lambda x: x.priority, reverse=True)

        # Extract normalized host and canonical URL if target is a URL
        norm_host = target
        norm_url = target
        is_cidr = False
        try:
            if "/" in target:
                ipaddress.ip_network(target, strict=False)
                is_cidr = True
        except ValueError:
            is_cidr = False

        if not is_cidr:
            try:
                from core.url_validator import parse_and_canonicalize_url
                if "://" in target:
                    parsed = parse_and_canonicalize_url(target)
                    norm_host = parsed.host
                    norm_url = parsed.url
                elif "/" in target:
                    parsed = parse_and_canonicalize_url(f"http://{target}")
                    norm_host = parsed.host
                    norm_url = parsed.url
            except Exception:
                pass
        
        for rule in sorted_rules:
            match = False
            
            if rule.rule_type == 'ip':
                match = (target == rule.rule_value) or (norm_host == rule.rule_value)
            elif rule.rule_type == 'cidr':
                match = self._check_ip_in_cidr(target, rule.rule_value) or self._check_ip_in_cidr(norm_host, rule.rule_value)
            elif rule.rule_type == 'domain':
                match = self._check_domain_match(target, rule.rule_value) or self._check_domain_match(norm_host, rule.rule_value)
            elif rule.rule_type == 'url':
                try:
                    match = bool(re.match(rule.rule_value, target)) or bool(re.match(rule.rule_value, norm_url))
                except re.error:
                    pass
            
            if match:
                if rule.action == 'deny':
                    return False, f"Target explicitly denied by rule {rule.rule_id}"
                elif rule.action == 'allow':
                    return True, f"Target allowed by rule {rule.rule_id}"
                elif rule.action == 'log_only':
                    return True, f"Target allowed (log_only) by rule {rule.rule_id}"

        return False, "Target not matched by any allow rules (default deny)"

    def check_redirect(
        self,
        original_target: str,
        redirect_target: str,
        scanner_activity: Optional[Union[ActivityLevel, str]] = None,
    ) -> Tuple[bool, str]:
        """Check if redirect is within scope and safe from forbidden destinations."""
        activity = scanner_activity if scanner_activity is not None else self.max_activity_level
        from core.url_validator import validate_redirect_destination
        
        allow_private = False
        allow_loopback = False
        enforce_dns_rebinding = False
        if self.policy is not None:
            policy_data = getattr(self.policy, "data", self.policy) if hasattr(self.policy, "data") else self.policy
            if isinstance(policy_data, dict):
                allow_private = bool(policy_data.get("allow_private", False))
                allow_loopback = bool(policy_data.get("allow_loopback", False))
                enforce_dns_rebinding = bool(policy_data.get("enforce_dns_rebinding", False))

        allowed, reason, canonical_redirect = validate_redirect_destination(
            original_url=original_target,
            redirect_target=redirect_target,
            scope_engine=self,
            scanner_activity=activity,
            allow_private=allow_private,
            allow_loopback=allow_loopback,
            enforce_dns_rebinding=enforce_dns_rebinding,
        )
        return allowed, reason

    def add_rule(self, rule_type: str, rule_value: str, action: str, priority: int = 100):
        """Add new scope rule."""
        import uuid
        rule = ScopeRule(rule_id=str(uuid.uuid4()), rule_type=rule_type, rule_value=rule_value, action=action, priority=priority)
        self.rules.append(rule)

    def remove_rule(self, rule_id: str):
        """Remove scope rule."""
        self.rules = [r for r in self.rules if r.rule_id != rule_id]
