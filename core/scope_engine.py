import re
import ipaddress
from typing import List, Tuple, Dict
from core.scanner_manifest import ActivityLevel

class ScopeRule:
    def __init__(self, rule_id: str, rule_type: str, rule_value: str, action: str, priority: int = 100):
        self.rule_id = rule_id
        self.rule_type = rule_type
        self.rule_value = rule_value
        self.action = action
        self.priority = priority

class ScopeEngine:
    def __init__(self, engagement_id: str):
        self.engagement_id = engagement_id
        self.rules: List[ScopeRule] = self._load_scope_rules()

    def _load_scope_rules(self) -> List[ScopeRule]:
        """Load and cache scope rules for engagement."""
        try:
            from tools.db_manager import get_authorizations_for_engagement
            from core.authorization import AuthStatus
            
            rules = []
            authorizations = get_authorizations_for_engagement(self.engagement_id)
            if not authorizations:
                return rules
            
            # Only use active authorizations
            active_auths = [a for a in authorizations if a.get("status") == AuthStatus.ACTIVE.value]
            
            for auth in active_auths:
                scope = auth.get("scope", "")
                rule_id = auth.get("auth_id", "")
                
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
        except Exception:
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

    def is_allowed(self, target: str, scanner_activity: ActivityLevel) -> Tuple[bool, str]:
        """
        Check if target is allowed for given scanner activity.
        
        Args:
            target: str (URL, IP, domain)
            scanner_activity: ActivityLevel enum
            
        Returns:
            tuple (allowed: bool, reason: str)
        """
        if not self.rules:
            # Default deny if no rules are configured
            return False, "No scope rules defined for engagement"
            
        sorted_rules = sorted(self.rules, key=lambda x: x.priority, reverse=True)
        
        for rule in sorted_rules:
            match = False
            
            if rule.rule_type == 'ip':
                match = target == rule.rule_value
            elif rule.rule_type == 'cidr':
                match = self._check_ip_in_cidr(target, rule.rule_value)
            elif rule.rule_type == 'domain':
                match = self._check_domain_match(target, rule.rule_value)
            elif rule.rule_type == 'url':
                try:
                    match = bool(re.match(rule.rule_value, target))
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

    def check_redirect(self, original_target: str, redirect_target: str) -> Tuple[bool, str]:
        """Check if redirect is within scope."""
        # Redirect check just uses the highest intrusive activity level to be safe
        return self.is_allowed(redirect_target, ActivityLevel.INTRUSIVE)

    def add_rule(self, rule_type: str, rule_value: str, action: str, priority: int = 100):
        """Add new scope rule."""
        import uuid
        rule = ScopeRule(rule_id=str(uuid.uuid4()), rule_type=rule_type, rule_value=rule_value, action=action, priority=priority)
        self.rules.append(rule)

    def remove_rule(self, rule_id: str):
        """Remove scope rule."""
        self.rules = [r for r in self.rules if r.rule_id != rule_id]
