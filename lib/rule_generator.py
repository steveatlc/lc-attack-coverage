"""Generate LimaCharlie D&R rules from ATT&CK technique and indicator data."""

import logging
import re
from dataclasses import dataclass, field
from typing import Optional

import yaml

logger = logging.getLogger(__name__)

# Map indicator types to LC event types and detection approaches
INDICATOR_STRATEGY = {
    "command_pattern": {
        "event": "NEW_PROCESS",
        "field": "event/COMMAND_LINE",
        "op": "matches",
    },
    "process": {
        "event": "NEW_PROCESS",
        "field": "event/FILE_PATH",
        "op": "matches",
    },
    "path": {
        "event": "FILE_CREATE",
        "field": "event/FILE_PATH",
        "op": "contains",
    },
    "registry": {
        "event": "REGISTRY_WRITE",
        "field": "event/REGISTRY_KEY",
        "op": "contains",
    },
    "network_ip": {
        "event": "NEW_TCP4_CONNECTION",
        "field": "event/IP_ADDRESS",
        "op": "is",
    },
    "network_domain": {
        "event": "DNS_REQUEST",
        "field": "event/DOMAIN_NAME",
        "op": "is",
    },
}

# Platform names used in D&R rules
PLATFORM_MAP = {
    "windows": "windows",
    "linux": "linux",
    "macos": "macos",
}


@dataclass
class GeneratedRule:
    name: str
    technique_id: str
    technique_name: str
    tactic: str
    platform: str
    confidence: str
    priority: int
    detect: dict
    respond: list
    tags: list[str] = field(default_factory=list)
    comment: str = ""


def slugify(text: str) -> str:
    """Convert text to a URL/name-safe slug."""
    text = text.lower()
    text = re.sub(r"[^a-z0-9]+", "-", text)
    text = text.strip("-")
    return text[:60]


def build_rule_name(technique_id: str, technique_name: str, suffix: str = "") -> str:
    """Build a rule name like attack-T1059.001-powershell-execution."""
    slug = slugify(technique_name)
    name = f"attack-{technique_id}-{slug}"
    if suffix:
        name = f"{name}-{suffix}"
    return name


def calculate_priority(
    base: int, threat_group_count: int, elevation_required: bool, cap: int = 10
) -> int:
    """Calculate weighted priority for a rule."""
    priority = base
    if threat_group_count >= 5:
        priority += 2
    elif threat_group_count >= 1:
        priority += 1
    if elevation_required:
        priority += 1
    return min(priority, cap)


def generate_detect_block(
    event_type: str,
    field_path: str,
    op: str,
    value: str,
    platform: Optional[str] = None,
) -> dict:
    """Generate a D&R detect block.

    LC requires 'event' at the detect root level. Additional conditions
    go inside 'op: and' with 'rules'.
    """
    # LC uses 're' for matches op, 'value' for everything else
    if op == "matches":
        core = {
            "op": op,
            "path": field_path,
            "re": value,
        }
    else:
        core = {
            "op": op,
            "path": field_path,
            "value": value,
        }

    # Build rules list for additional conditions
    rules = [core]

    # Add platform filter if specified
    # LC D&R uses shorthand operators: "is windows", "is linux", "is macos"
    if platform and platform in PLATFORM_MAP:
        rules.insert(
            0,
            {
                "op": f"is {PLATFORM_MAP[platform]}",
            },
        )

    # event must be at the detect root
    detect = {
        "event": event_type,
        "op": "and",
        "rules": rules,
    }

    return detect


def priority_to_level(priority: int) -> str:
    """Map numeric priority to ext-cases severity level string.

    ext-cases reads detect_mtd.level to derive case severity.
    """
    if priority >= 8:
        return "critical"
    if priority >= 5:
        return "high"
    if priority >= 3:
        return "medium"
    return "low"


def generate_respond_block(
    rule_name: str,
    technique_id: str,
    technique_name: str,
    tactic: str,
    priority: int,
    confidence: str,
    platforms: str,
    data_sources: str,
    atomic_ref: str = "",
    url: str = "",
    suppression_period: str = "1h",
    suppression_max_count: int = 5,
) -> list:
    """Generate a D&R respond block with report action and suppression."""
    metadata = {
        "mitre_attack_id": technique_id,
        "mitre_technique": technique_name,
        "mitre_tactic": tactic,
        "mitre_url": url or f"https://attack.mitre.org/techniques/{technique_id.replace('.', '/')}/",
        "level": priority_to_level(priority),
        "data_sources": data_sources,
        "platforms": platforms,
        "author": "attack-coverage-generator",
        "version": "1.0",
        "confidence": confidence,
    }
    if atomic_ref:
        metadata["atomic_test_ref"] = atomic_ref

    respond = [
        {
            "action": "report",
            "name": rule_name,
            "priority": priority,
            "metadata": metadata,
            "detect_data": {
                "command_line": "{{ .event.COMMAND_LINE }}",
                "file_path": "{{ .event.FILE_PATH }}",
                "hostname": "{{ .routing.hostname }}",
                "sensor_id": "{{ .routing.sid }}",
            },
            "suppression": {
                "max_count": suppression_max_count,
                "period": suppression_period,
                "is_global": False,
                "keys": [
                    "{{ .routing.sid }}",
                    f"attack-{technique_id}",
                ],
            },
        }
    ]

    return respond


def escape_regex(value: str) -> str:
    """Escape a string for use in a regex pattern, then wrap as partial match."""
    escaped = re.escape(value)
    return f".*{escaped}.*"


def generate_rules_for_technique(
    technique_id: str,
    technique_name: str,
    tactics: list[str],
    platforms: list[str],
    url: str,
    threat_group_count: int,
    indicators: list,
    data_components: list[str],
    base_priority: int = 3,
    priority_cap: int = 10,
    confidence: str = "medium",
    suppression_period: str = "1h",
    suppression_max_count: int = 5,
) -> list[GeneratedRule]:
    """Generate D&R rules for a single ATT&CK technique based on available indicators.

    Returns a list of GeneratedRule objects (may be multiple per technique if
    there are indicators across different event types/platforms).
    """
    rules = []
    tactic = tactics[0] if tactics else "unknown"

    # Group indicators by (type, platform) to avoid duplicate rules
    seen = set()

    for indicator in indicators:
        ind_type = indicator.type if hasattr(indicator, "type") else indicator.get("type", "")
        ind_value = indicator.value if hasattr(indicator, "value") else indicator.get("value", "")
        ind_platform = indicator.platform if hasattr(indicator, "platform") else indicator.get("platform", "")
        ind_context = indicator.context if hasattr(indicator, "context") else indicator.get("context", "")

        # Determine strategy
        if ind_type == "network":
            # Distinguish IP vs domain
            if re.match(r"\d+\.\d+\.\d+\.\d+", ind_value):
                strategy_key = "network_ip"
            else:
                strategy_key = "network_domain"
        elif ind_type in INDICATOR_STRATEGY:
            strategy_key = ind_type
        else:
            continue

        strategy = INDICATOR_STRATEGY[strategy_key]

        # Build dedup key
        dedup_key = (strategy["event"], ind_value, ind_platform)
        if dedup_key in seen:
            continue
        seen.add(dedup_key)

        # For regex ops, escape the value
        if strategy["op"] == "matches":
            detection_value = escape_regex(ind_value)
        else:
            detection_value = ind_value

        elevation = getattr(indicator, "elevation_required", False) if hasattr(indicator, "elevation_required") else False
        priority = calculate_priority(base_priority, threat_group_count, elevation, priority_cap)

        suffix = slugify(ind_value)[:20] if len(seen) > 1 else ""
        rule_name = build_rule_name(technique_id, technique_name, suffix)

        detect = generate_detect_block(
            event_type=strategy["event"],
            field_path=strategy["field"],
            op=strategy["op"],
            value=detection_value,
            platform=ind_platform if ind_platform in PLATFORM_MAP else None,
        )

        respond = generate_respond_block(
            rule_name=rule_name,
            technique_id=technique_id,
            technique_name=technique_name,
            tactic=tactic,
            priority=priority,
            confidence=confidence,
            platforms=ind_platform,
            data_sources=", ".join(data_components),
            url=url,
            suppression_period=suppression_period,
            suppression_max_count=suppression_max_count,
        )

        rule = GeneratedRule(
            name=rule_name,
            technique_id=technique_id,
            technique_name=technique_name,
            tactic=tactic,
            platform=ind_platform,
            confidence=confidence,
            priority=priority,
            detect=detect,
            respond=respond,
            tags=["attack-coverage", tactic],
            comment=f"ATT&CK {technique_id} - {technique_name}",
        )
        rules.append(rule)

    # Skip placeholder rules — a rule that fires on every NEW_PROCESS or
    # DNS_REQUEST with no content filter creates noise with zero detection
    # value.  These techniques are tracked in the coverage report as
    # "coverable but no rule generated" so operators can write targeted
    # detections manually.
    if False and not rules and data_components:
        primary_component = data_components[0]
        rule = _generate_placeholder_rule(
            technique_id=technique_id,
            technique_name=technique_name,
            tactic=tactic,
            platforms=platforms,
            url=url,
            data_component=primary_component,
            threat_group_count=threat_group_count,
            base_priority=base_priority,
            priority_cap=priority_cap,
            confidence="low",
            suppression_period=suppression_period,
            suppression_max_count=suppression_max_count,
        )
        if rule:
            rules.append(rule)

    return rules


# Map data components to a basic event type for placeholder rules
_COMPONENT_TO_EVENT = {
    "Process Creation": "NEW_PROCESS",
    "File Creation": "FILE_CREATE",
    "File Modification": "FILE_MODIFIED",
    "File Deletion": "FILE_DELETE",
    "Windows Registry Key Creation": "REGISTRY_CREATE",
    "Windows Registry Key Modification": "REGISTRY_WRITE",
    "Windows Registry Key Deletion": "REGISTRY_DELETE",
    "Network Connection Creation": "NEW_TCP4_CONNECTION",
    "Network Traffic Content": "DNS_REQUEST",
    "Module Load": "MODULE_LOAD",
    "Service Creation": "SERVICE_CHANGE",
    "Service Modification": "SERVICE_CHANGE",
    "Driver Load": "DRIVER_CHANGE",
    "Process Access": "NEW_REMOTE_THREAD",
    "Logon Session Creation": "WEL",
    "Scheduled Job Creation": "WEL",
    "User Account Authentication": "USER_OBSERVED",
}


def _generate_placeholder_rule(
    technique_id: str,
    technique_name: str,
    tactic: str,
    platforms: list[str],
    url: str,
    data_component: str,
    threat_group_count: int,
    base_priority: int,
    priority_cap: int,
    confidence: str,
    suppression_period: str,
    suppression_max_count: int,
) -> Optional[GeneratedRule]:
    """Generate a basic detection rule based on data component type.

    These are broad rules that fire on event type alone — meant as
    starting points that require tuning.
    """
    event_type = _COMPONENT_TO_EVENT.get(data_component)
    if not event_type:
        return None

    platform = platforms[0] if platforms else None
    rule_name = build_rule_name(technique_id, technique_name)
    priority = calculate_priority(base_priority, threat_group_count, False, priority_cap)

    # Simple detect: match the event type with platform filter (placeholder — needs tuning)
    if platform and platform in PLATFORM_MAP:
        detect = {
            "event": event_type,
            "op": f"is {PLATFORM_MAP[platform]}",
        }
    else:
        detect = {
            "event": event_type,
            "op": "exists",
            "path": "routing/sid",
        }

    respond = generate_respond_block(
        rule_name=rule_name,
        technique_id=technique_id,
        technique_name=technique_name,
        tactic=tactic,
        priority=priority,
        confidence=confidence,
        platforms=", ".join(platforms),
        data_sources=data_component,
        url=url,
        suppression_period=suppression_period,
        suppression_max_count=suppression_max_count,
    )

    return GeneratedRule(
        name=rule_name,
        technique_id=technique_id,
        technique_name=technique_name,
        tactic=tactic,
        platform=platform or "",
        confidence=confidence,
        priority=priority,
        detect=detect,
        respond=respond,
        tags=["attack-coverage", tactic, "placeholder"],
        comment=f"ATT&CK {technique_id} - {technique_name} (placeholder - needs tuning)",
    )


def rule_to_yaml(rule: GeneratedRule) -> str:
    """Serialize a GeneratedRule to YAML string."""
    data = {
        "name": rule.name,
        "detect": rule.detect,
        "respond": rule.respond,
    }
    return yaml.dump(data, default_flow_style=False, sort_keys=False)


def deduplicate_rules(rules: list[GeneratedRule]) -> list[GeneratedRule]:
    """Remove duplicate rules by name, keeping the highest-priority version."""
    by_name = {}
    for rule in rules:
        if rule.name not in by_name or rule.priority > by_name[rule.name].priority:
            by_name[rule.name] = rule
    return list(by_name.values())
