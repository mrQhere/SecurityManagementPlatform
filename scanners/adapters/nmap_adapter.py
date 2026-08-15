"""
Nmap Scanner Adapter — SMP V9.5
Parses Nmap XML output into structured Observation objects.

Unlike other scanners, Nmap is treated as the authoritative asset and
service discovery source. Its output is decomposed into:
  - AssetObservation  — discovered hosts/IPs
  - PortObservation   — open ports
  - ServiceObservation — service + product + version
  - CPEObservation    — CPE strings for CVE matching
  - VulnObservation   — NSE script vulnerability results
"""

import xml.etree.ElementTree as ET
import logging
import subprocess
from typing import List, Dict, Optional
from abc import ABC, abstractmethod

logger = logging.getLogger("smp")

# ─────────────────────────────────────────────────────────────────────────────
# Observation Type Constants (mirrors core/observation.py ObservationType)
# Using string constants here to avoid circular import chains during early load
# ─────────────────────────────────────────────────────────────────────────────
OBS_ASSET = "asset"
OBS_PORT = "port"
OBS_SERVICE = "service"
OBS_CPE = "cpe"
OBS_VULNERABILITY_CANDIDATE = "vulnerability_candidate"


def _make_observation(
    scan_id: str,
    obs_type: str,
    title: str,
    raw_value: dict,
    confidence: float = 1.0,
    asset_id: Optional[str] = None,
    service_id: Optional[str] = None,
) -> dict:
    """Build an observation dict compatible with ObservationBase."""
    import uuid
    from datetime import datetime, timezone
    return {
        "observation_id": str(uuid.uuid4()),
        "scan_id": scan_id,
        "scanner_id": "nmap",
        "scanner_version": None,
        "observation_type": obs_type,
        "title": title,
        "raw_value": raw_value,
        "normalized_value": None,
        "confidence": confidence,
        "observed_at": datetime.now(timezone.utc).isoformat(),
        "evidence_ids": [],
        "raw_output_hash": None,
        "parser_version": "1.0",
        "asset_id": asset_id,
        "service_id": service_id,
    }


class NmapParser:
    """
    Parses Nmap XML output into multiple typed Observation dicts.
    
    Does NOT depend on pydantic at import time — safe for use before
    the full application environment is initialized.
    """

    def parse(self, raw_output: str, scanner_context: dict) -> List[dict]:
        """
        Parse Nmap XML string into a list of Observation dicts.
        
        Args:
            raw_output: Nmap -oX - XML string
            scanner_context: dict with at least {"scan_id": str}
            
        Returns:
            List of observation dicts
        """
        if not raw_output or not raw_output.strip():
            logger.warning("NmapParser: empty output received")
            return []

        try:
            root = ET.fromstring(raw_output)
        except ET.ParseError as e:
            logger.error(f"NmapParser: XML parse error: {e}")
            return []

        scan_id = scanner_context.get("scan_id", "unknown")
        observations = []

        for host in root.findall(".//host"):
            host_obs, host_id = self._parse_host(host, scan_id)
            if host_obs:
                observations.extend(host_obs)

            for port in host.findall(".//port"):
                port_obs = self._parse_port(port, scan_id, host_id)
                observations.extend(port_obs)

        return observations

    def _get_host_ip(self, host) -> Optional[str]:
        for addr in host.findall("address"):
            if addr.get("addrtype") in ("ipv4", "ipv6"):
                return addr.get("addr")
        return None

    def _get_host_hostname(self, host) -> Optional[str]:
        for hn in host.findall(".//hostname"):
            return hn.get("name")
        return None

    def _parse_host(self, host, scan_id: str):
        """Return (list_of_observations, asset_id) for a host element."""
        ip = self._get_host_ip(host)
        if not ip:
            return [], None

        status = host.find("status")
        state = status.get("state", "unknown") if status is not None else "unknown"
        if state not in ("up", "up|filtered"):
            return [], None

        hostname = self._get_host_hostname(host)
        asset_id = f"asset-{ip.replace('.', '-')}"

        obs = _make_observation(
            scan_id=scan_id,
            obs_type=OBS_ASSET,
            title=f"Discovered Host: {ip}" + (f" ({hostname})" if hostname else ""),
            raw_value={"ip": ip, "hostname": hostname, "state": state},
            confidence=1.0,
        )
        obs["asset_id"] = asset_id
        return [obs], asset_id

    def _parse_port(self, port, scan_id: str, asset_id: Optional[str]) -> List[dict]:
        portid = port.get("portid")
        protocol = port.get("protocol", "tcp")
        state_elem = port.find("state")
        state = state_elem.get("state", "unknown") if state_elem is not None else "unknown"

        observations = []

        # Port observation (all states)
        port_obs = _make_observation(
            scan_id=scan_id,
            obs_type=OBS_PORT,
            title=f"Port {portid}/{protocol.upper()} [{state}]",
            raw_value={"port": portid, "protocol": protocol, "state": state},
            confidence=1.0,
            asset_id=asset_id,
        )
        observations.append(port_obs)

        if state != "open":
            return observations

        # Service detection
        service = port.find("service")
        if service is not None:
            name = service.get("name", "")
            product = service.get("product", "")
            version = service.get("version", "")
            extra = service.get("extrainfo", "")
            tunnel = service.get("tunnel", "")

            if product or name:
                service_title = f"Service: {product or name}" + (f" {version}".rstrip() if version else "")
                if tunnel:
                    service_title += f" ({tunnel.upper()})"

                svc_obs = _make_observation(
                    scan_id=scan_id,
                    obs_type=OBS_SERVICE,
                    title=service_title,
                    raw_value={
                        "port": portid,
                        "protocol": protocol,
                        "service_name": name,
                        "product": product,
                        "version": version,
                        "extrainfo": extra,
                        "tunnel": tunnel,
                    },
                    confidence=0.95,
                    asset_id=asset_id,
                )
                observations.append(svc_obs)

            # CPE strings → CVE matching
            for cpe_elem in service.findall("cpe"):
                cpe_str = cpe_elem.text
                if cpe_str:
                    cpe_obs = _make_observation(
                        scan_id=scan_id,
                        obs_type=OBS_CPE,
                        title=f"CPE: {cpe_str}",
                        raw_value={
                            "cpe": cpe_str,
                            "port": portid,
                            "product": product,
                            "version": version,
                        },
                        confidence=0.85,
                        asset_id=asset_id,
                    )
                    observations.append(cpe_obs)

        # NSE script results — vulnerability candidates
        for script in port.findall("script"):
            script_id = script.get("id", "")
            output = script.get("output", "")

            if not output:
                continue

            # Only surface scripts that look like vuln findings
            is_vuln = any(kw in script_id.lower() for kw in ("vuln", "exploit", "cve", "ms", "auth"))
            confidence = 0.80 if is_vuln else 0.40

            vuln_obs = _make_observation(
                scan_id=scan_id,
                obs_type=OBS_VULNERABILITY_CANDIDATE,
                title=f"NSE Script: {script_id}",
                raw_value={
                    "script_id": script_id,
                    "output": output[:2048],  # cap to 2KB
                    "port": portid,
                    "protocol": protocol,
                },
                confidence=confidence,
                asset_id=asset_id,
            )
            observations.append(vuln_obs)

        return observations

    def validate_observation(self, observation: dict) -> bool:
        return bool(observation.get("observation_id") and observation.get("title"))

    def normalize_observation(self, observation: dict) -> dict:
        return observation


class NmapAdapter:
    """
    Nmap Scanner Adapter for SMP V9.5.
    
    Implements the ScannerAdapter interface without inheriting from it
    to avoid circular import issues during early boot.
    """

    MANIFEST = {
        "id": "nmap",
        "name": "Nmap Network Scanner",
        "adapter_version": "1.1",
        "tool_version": "7.90",
        "category": "network",
        "input_type": "host",
        "output_format": "xml",
        "activity_level": "ACTIVE",
        "requires_network": True,
        "external_services": [],
        "requires_credentials": False,
        "requires_root": False,
        "supports_offline": True,
        "default_timeout": 300,
        "max_timeout": 1800,
        "max_concurrency": 3,
        "max_requests": 10000,
        "max_output_bytes": 50 * 1024 * 1024,  # 50MB
        "supported_profiles": ["standard", "full", "osint"],
        "parser": "scanners.adapters.nmap_adapter.NmapParser",
        "dependencies": ["nmap"],
    }

    def get_manifest(self) -> dict:
        return self.MANIFEST.copy()

    def verify_binary(self) -> tuple:
        """Verify nmap is installed and get its version."""
        import shutil
        nmap_path = shutil.which("nmap")
        if not nmap_path:
            return False, ""
        try:
            result = subprocess.run(
                ["nmap", "--version"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            # "Nmap version 7.92 ( https://nmap.org )"
            for line in result.stdout.splitlines():
                if "Nmap version" in line:
                    version = line.split("Nmap version")[1].strip().split()[0]
                    return True, version
            return True, "unknown"
        except Exception as e:
            logger.error(f"NmapAdapter: binary verification failed: {e}")
            return False, ""

    def prepare_execution(self, target: str, config: dict) -> dict:
        """
        Build the nmap command based on config/profile.
        
        Config keys:
          - profile: standard (default) | full | stealth
          - ports: port range string (default: top 1000)
          - extra_args: list of additional nmap flags
        """
        profile = config.get("profile", "standard")
        ports = config.get("ports", "")
        extra_args = config.get("extra_args", [])

        base_flags = ["-sV", "--version-intensity", "5", "-oX", "-"]

        if profile == "full":
            base_flags = ["-sV", "-sC", "-O", "--version-intensity", "9", "-p-", "-oX", "-"]
        elif profile == "stealth":
            base_flags = ["-sS", "-sV", "--version-intensity", "3", "-T2", "-oX", "-"]

        if ports and "--p-" not in base_flags:
            base_flags = [f for f in base_flags if f != "-p-"]
            base_flags = ["-p", ports] + base_flags

        cmd = ["nmap"] + base_flags + extra_args + [target]
        return {"command": cmd, "target": target, "profile": profile}

    def execute(self, target: str, config: dict) -> dict:
        """Execute nmap and return raw result dict."""
        prep = self.prepare_execution(target, config)
        cmd = prep["command"]
        timeout = config.get("timeout", self.MANIFEST["default_timeout"])

        logger.info(f"NmapAdapter: running {' '.join(cmd)}")
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
            return {
                "exit_code": result.returncode,
                "raw_output": result.stdout,
                "stderr": result.stderr,
                "command": cmd,
            }
        except subprocess.TimeoutExpired:
            logger.error(f"NmapAdapter: scan timed out after {timeout}s")
            return {"exit_code": -1, "raw_output": "", "stderr": "Timeout", "command": cmd}
        except FileNotFoundError:
            logger.error("NmapAdapter: nmap binary not found")
            return {"exit_code": -2, "raw_output": "", "stderr": "nmap not found", "command": cmd}
        except Exception as e:
            logger.error(f"NmapAdapter: unexpected error: {e}")
            return {"exit_code": -3, "raw_output": "", "stderr": str(e), "command": cmd}

    def parse_output(self, raw_output: str, scan_id: str = "unknown") -> List[dict]:
        """Parse XML output into observation dicts."""
        parser = NmapParser()
        return parser.parse(raw_output, {"scan_id": scan_id})

    def cleanup(self, workspace: str):
        """No temporary files to clean up (output piped to stdout)."""
        pass
