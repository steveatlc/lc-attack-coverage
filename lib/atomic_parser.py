"""Parse Atomic Red Team test definitions and extract observable indicators."""

import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import yaml

logger = logging.getLogger(__name__)

# Regex patterns for extracting indicators from atomic test commands
INDICATOR_PATTERNS = {
    "windows_path": re.compile(
        r"[A-Za-z]:\\(?:[^\s\\\"']+\\)*[^\s\\\"']+", re.IGNORECASE
    ),
    "unix_path": re.compile(r"(?:/[\w.\-]+){2,}"),
    "registry_key": re.compile(
        r"(?:HKLM|HKCU|HKCR|HKU|HKCC)\\[^\s\"']+", re.IGNORECASE
    ),
    "ip_address": re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b"),
    "domain": re.compile(
        r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:com|net|org|io|xyz|top|ru|cn|tk)\b",
        re.IGNORECASE,
    ),
    "known_tools": re.compile(
        r"\b(?:mimikatz|lazagne|rubeus|seatbelt|sharphound|bloodhound|"
        r"cobalt\s*strike|psexec|wmic|certutil|bitsadmin|mshta|regsvr32|"
        r"rundll32|cscript|wscript|powershell|cmd\.exe|msbuild|installutil|"
        r"regasm|regsvcs|msiexec|cmstp|esentutl|expand|extrac32|findstr|"
        r"forfiles|ieexec|infdefaultinstall|mavinject|microsoft\.workflow\.compiler|"
        r"msdeploy|msconfig|msiexec|netsh|odbcconf|pcalua|pcwrun|"
        r"presentationhost|rasautou|reg\.exe|regsvr32|replace|rpcping|"
        r"schtasks|scriptrunner|syncappvpublishingserver|verclsid|"
        r"wab|xwizard)\b",
        re.IGNORECASE,
    ),
    "command_line_pattern": re.compile(
        r"(?:-(?:enc|encodedcommand|e)\s+[A-Za-z0-9+/=]+|"
        r"-(?:nop|noni|w\s+hidden|ep\s+bypass|exec\s+bypass)|"
        r"invoke-(?:expression|command|webrequest|mimikatz)|"
        r"iex\s*\(|"
        r"downloadstring|downloadfile|"
        r"net\s+(?:user|localgroup|group)\s|"
        r"whoami|systeminfo|ipconfig\s+/all|"
        r"tasklist|netstat\s+-|"
        r"sc\s+(?:create|config|start|stop|delete)\s)",
        re.IGNORECASE,
    ),
}


@dataclass
class AtomicIndicator:
    type: str  # "path", "registry", "process", "network", "command_pattern"
    value: str
    platform: str  # "windows", "linux", "macos"
    context: str = ""  # Description of where this was found


@dataclass
class AtomicTest:
    technique_id: str
    test_name: str
    test_number: int
    description: str
    supported_platforms: list[str] = field(default_factory=list)
    executor_name: str = ""
    executor_command: str = ""
    elevation_required: bool = False
    input_arguments: dict = field(default_factory=dict)
    indicators: list[AtomicIndicator] = field(default_factory=list)


def extract_indicators(
    command: str, platforms: list[str]
) -> list[AtomicIndicator]:
    """Extract observable indicators from an atomic test command string."""
    indicators = []
    if not command:
        return indicators

    for platform in platforms:
        plat = platform.lower()

        # File paths
        if plat == "windows":
            for match in INDICATOR_PATTERNS["windows_path"].findall(command):
                # Skip common system paths that would be too noisy
                if not _is_noisy_path(match):
                    indicators.append(
                        AtomicIndicator("path", match, plat, "file path from command")
                    )
        else:
            for match in INDICATOR_PATTERNS["unix_path"].findall(command):
                if not _is_noisy_path(match):
                    indicators.append(
                        AtomicIndicator("path", match, plat, "file path from command")
                    )

        # Registry keys (Windows only)
        if plat == "windows":
            for match in INDICATOR_PATTERNS["registry_key"].findall(command):
                indicators.append(
                    AtomicIndicator("registry", match, plat, "registry key from command")
                )

        # Network indicators
        for match in INDICATOR_PATTERNS["ip_address"].findall(command):
            if not _is_internal_ip(match):
                indicators.append(
                    AtomicIndicator("network", match, plat, "IP address from command")
                )

        for match in INDICATOR_PATTERNS["domain"].findall(command):
            indicators.append(
                AtomicIndicator("network", match, plat, "domain from command")
            )

        # Known tools
        for match in INDICATOR_PATTERNS["known_tools"].findall(command):
            indicators.append(
                AtomicIndicator("process", match.lower(), plat, "known tool reference")
            )

        # Command-line patterns
        for match in INDICATOR_PATTERNS["command_line_pattern"].findall(command):
            indicators.append(
                AtomicIndicator(
                    "command_pattern", match.strip(), plat, "suspicious command pattern"
                )
            )

    return indicators


def _is_noisy_path(path: str) -> bool:
    """Filter out extremely common paths that would generate too much noise."""
    noisy = [
        "C:\\Windows\\System32",
        "C:\\Windows\\SysWOW64",
        "/usr/bin",
        "/usr/sbin",
        "/bin",
        "/sbin",
        "/tmp",
        "/etc",
    ]
    path_lower = path.lower().replace("\\", "/")
    for n in noisy:
        if path_lower == n.lower().replace("\\", "/"):
            return True
    return False


def _is_internal_ip(ip: str) -> bool:
    """Check if an IP is RFC1918 or loopback (not useful as IOC)."""
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    try:
        first, second = int(parts[0]), int(parts[1])
    except ValueError:
        return False
    if first == 10:
        return True
    if first == 172 and 16 <= second <= 31:
        return True
    if first == 192 and second == 168:
        return True
    if first == 127:
        return True
    return False


def parse_atomic_directory(atomics_dir: Path) -> dict[str, list[AtomicTest]]:
    """Parse all Atomic Red Team technique directories.

    Returns dict mapping technique ID → list of AtomicTest.
    """
    results = {}
    if not atomics_dir.exists():
        logger.warning("Atomics directory not found: %s", atomics_dir)
        return results

    for technique_dir in sorted(atomics_dir.iterdir()):
        if not technique_dir.is_dir():
            continue
        # Look for the technique YAML file (e.g., T1059.001/T1059.001.yaml)
        yaml_files = list(technique_dir.glob("T*.yaml"))
        for yaml_file in yaml_files:
            try:
                tests = _parse_atomic_yaml(yaml_file)
                if tests:
                    tid = tests[0].technique_id
                    results[tid] = tests
            except Exception as e:
                logger.warning("Failed to parse %s: %s", yaml_file, e)

    logger.info("Parsed atomic tests for %d techniques", len(results))
    return results


def _parse_atomic_yaml(yaml_path: Path) -> list[AtomicTest]:
    """Parse a single Atomic Red Team YAML file."""
    with open(yaml_path, "r") as f:
        data = yaml.safe_load(f)

    if not data:
        return []

    technique_id = data.get("attack_technique", "")
    if not technique_id:
        return []

    tests = []
    for i, test_data in enumerate(data.get("atomic_tests", []), start=1):
        platforms = [p.lower() for p in test_data.get("supported_platforms", [])]

        executor = test_data.get("executor", {})
        command = executor.get("command", "") or ""
        cleanup = executor.get("cleanup_command", "") or ""

        # Substitute default input argument values into command for indicator extraction
        input_args = test_data.get("input_arguments", {}) or {}
        resolved_command = command
        for arg_name, arg_data in input_args.items():
            default_val = str(arg_data.get("default", ""))
            resolved_command = resolved_command.replace(
                f"#{{{arg_name}}}", default_val
            )

        indicators = extract_indicators(resolved_command, platforms)
        # Also check cleanup command
        if cleanup:
            resolved_cleanup = cleanup
            for arg_name, arg_data in input_args.items():
                default_val = str(arg_data.get("default", ""))
                resolved_cleanup = resolved_cleanup.replace(
                    f"#{{{arg_name}}}", default_val
                )
            indicators.extend(extract_indicators(resolved_cleanup, platforms))

        test = AtomicTest(
            technique_id=technique_id,
            test_name=test_data.get("name", ""),
            test_number=i,
            description=test_data.get("description", ""),
            supported_platforms=platforms,
            executor_name=executor.get("name", ""),
            executor_command=command,
            elevation_required=executor.get("elevation_required", False),
            input_arguments=input_args,
            indicators=indicators,
        )
        tests.append(test)

    return tests
