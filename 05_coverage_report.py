#!/usr/bin/env python3
"""Phase 5: Generate gap analysis report and ATT&CK Navigator layer."""

import json
import logging
from collections import defaultdict
from pathlib import Path

import yaml

from lib.attack_parser import load_parsed_data

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger(__name__)

BASE_DIR = Path(__file__).parent
CONFIG_PATH = BASE_DIR / "config.yaml"

# ATT&CK Navigator layer template
NAVIGATOR_LAYER_TEMPLATE = {
    "name": "LimaCharlie ATT&CK Coverage",
    "versions": {"attack": "16", "navigator": "5.1.0", "layer": "4.5"},
    "domain": "enterprise-attack",
    "description": "Auto-generated coverage layer from attack-coverage-generator",
    "sorting": 0,
    "layout": {"layout": "side", "aggregateFunction": "average", "showID": True, "showName": True},
    "hideDisabled": False,
    "techniques": [],
    "gradient": {
        "colors": ["#ff6666", "#ffeb3b", "#66bb6a"],
        "minValue": 0,
        "maxValue": 100,
    },
    "legendItems": [
        {"label": "Fully Covered (rules deployed)", "color": "#66bb6a"},
        {"label": "Partially Covered", "color": "#ffeb3b"},
        {"label": "Not Covered (gap)", "color": "#ff6666"},
        {"label": "Not Coverable (endpoint)", "color": "#9e9e9e"},
    ],
}

# Recommendations for missing data components
DATA_SOURCE_RECOMMENDATIONS = {
    "Command Execution": "Enable PowerShell ScriptBlock Logging (Event ID 4104) and Module Logging via WEL adapter",
    "Active Directory Object Access": "Forward Security Event Log (4661, 4662) via WEL adapter or cloud sensor",
    "Logon Session Creation": "Forward Windows Security Event Log (4624, 4625, 4634) via WEL; enable SSH logging on Linux",
    "User Account Authentication": "Forward Windows Security Log (4776) and Linux auth.log via syslog adapter",
    "User Account Creation": "Forward Windows Security Log (4720) via WEL adapter",
    "User Account Modification": "Forward Windows Security Log (4738) via WEL adapter",
    "Scheduled Job Creation": "Forward Windows Security Log (4698) or Sysmon Event ID 1 for at/cron",
    "Firmware Modification": "Requires specialized firmware monitoring — not typically available via EDR",
    "Cloud Storage Access": "Use LimaCharlie cloud sensor adapters (AWS CloudTrail, GCP Audit, Azure Activity)",
    "Instance Creation": "Ingest cloud provider audit logs via cloud sensor adapters",
    "Snapshot Creation": "Ingest cloud provider audit logs via cloud sensor adapters",
    "Application Log Content": "Forward application-specific logs via syslog or file adapter",
    "Web Credential Usage": "Forward web proxy or authentication logs via syslog adapter",
    "Certificate Creation": "Forward CA audit logs; monitor certutil via process creation",
    "Container Creation": "Ingest Docker/Kubernetes audit logs via adapter",
    "Pod Creation": "Ingest Kubernetes audit logs via cloud sensor adapter",
    "Image Creation": "Ingest container registry audit logs",
    "Group Enumeration": "Forward Windows Security Log (4799) via WEL adapter",
    "Group Modification": "Forward Windows Security Log (4735, 4737) via WEL adapter",
    "Network Share Access": "Forward Windows Security Log (5140, 5145) via WEL adapter",
    "Firewall Enumeration": "Monitor netsh/iptables via process creation events",
    "Firewall Disable": "Monitor netsh/iptables via process creation events",
    "Firewall Rule Modification": "Forward Windows Firewall Log via WEL adapter",
    "WMI Creation": "Enable Sysmon WMI events (19, 20, 21) and forward via WEL",
    "Driver Load": "Enable Sysmon driver load events (Event ID 6) and forward via WEL",
    "Kernel Module Load": "Enable auditd module_load rules on Linux",
}


def load_config() -> dict:
    with open(CONFIG_PATH) as f:
        return yaml.safe_load(f)


def load_technique_coverage() -> dict:
    path = BASE_DIR / "mappings" / "technique_rules.yaml"
    with open(path) as f:
        return yaml.safe_load(f) or {}


def load_generated_rules() -> dict:
    """Load the consolidated rules file and return a name → rule mapping."""
    path = BASE_DIR / "output" / "all_rules.yaml"
    if not path.exists():
        return {}
    with open(path) as f:
        return yaml.safe_load(f) or {}


def count_rules_per_technique(rules: dict) -> dict:
    """Count how many rules exist per technique ID."""
    counts = defaultdict(int)
    for name in rules:
        # Rule names are like attack-T1059.001-powershell-execution
        parts = name.split("-")
        if len(parts) >= 2:
            # Find the technique ID part (starts with T)
            for part in parts[1:]:
                if part.startswith("T"):
                    # Could be T1059 or T1059.001 — reconstruct
                    tid = part
                    idx = parts.index(part)
                    # Check if next part is a sub-technique number
                    if idx + 1 < len(parts) and parts[idx + 1].isdigit():
                        tid = f"{part}.{parts[idx + 1]}"
                    counts[tid] += 1
                    break
    return dict(counts)


def generate_report(
    coverage: dict,
    rules: dict,
    techniques: dict,
) -> str:
    """Generate the coverage report markdown."""
    rules_per_technique = count_rules_per_technique(rules)

    fully = {k: v for k, v in coverage.items() if v["status"] == "fully_covered"}
    partial = {k: v for k, v in coverage.items() if v["status"] == "partially_covered"}
    not_covered = {k: v for k, v in coverage.items() if v["status"] == "not_covered"}
    total = len(coverage)

    # Group by tactic
    by_tactic = defaultdict(lambda: {"fully": 0, "partial": 0, "not_covered": 0, "total": 0})
    for tid, info in coverage.items():
        for tactic in info.get("tactics", ["unknown"]):
            by_tactic[tactic]["total"] += 1
            if info["status"] == "fully_covered":
                by_tactic[tactic]["fully"] += 1
            elif info["status"] == "partially_covered":
                by_tactic[tactic]["partial"] += 1
            else:
                by_tactic[tactic]["not_covered"] += 1

    # Group by platform
    by_platform = defaultdict(lambda: {"fully": 0, "partial": 0, "not_covered": 0, "total": 0})
    for tid, info in coverage.items():
        for plat in info.get("platforms", []):
            by_platform[plat]["total"] += 1
            if info["status"] == "fully_covered":
                by_platform[plat]["fully"] += 1
            elif info["status"] == "partially_covered":
                by_platform[plat]["partial"] += 1
            else:
                by_platform[plat]["not_covered"] += 1

    # Missing data component impact analysis
    missing_impact = defaultdict(list)
    for tid, info in coverage.items():
        for comp in info.get("missing_components", []):
            missing_impact[comp].append(tid)

    lines = []
    lines.append("# ATT&CK Detection Coverage Report")
    lines.append("")
    lines.append("## Executive Summary")
    lines.append("")
    lines.append(f"**Total techniques assessed:** {total}")
    lines.append(f"- Fully covered: {len(fully)} ({100*len(fully)/total:.1f}%)" if total else "")
    lines.append(f"- Partially covered: {len(partial)} ({100*len(partial)/total:.1f}%)" if total else "")
    lines.append(f"- Not covered: {len(not_covered)} ({100*len(not_covered)/total:.1f}%)" if total else "")
    lines.append(f"- **Total D&R rules generated:** {len(rules)}")
    lines.append("")

    # Coverage by tactic table
    lines.append("### Coverage by Tactic")
    lines.append("")
    lines.append("| Tactic | Fully Covered | Partially | Not Covered | Total | Coverage % |")
    lines.append("|--------|--------------|-----------|-------------|-------|------------|")
    for tactic in sorted(by_tactic.keys()):
        t = by_tactic[tactic]
        pct = 100 * t["fully"] / t["total"] if t["total"] else 0
        lines.append(f"| {tactic} | {t['fully']} | {t['partial']} | {t['not_covered']} | {t['total']} | {pct:.0f}% |")
    lines.append("")

    # Coverage by platform table
    lines.append("### Coverage by Platform")
    lines.append("")
    lines.append("| Platform | Fully Covered | Partially | Not Covered | Total | Coverage % |")
    lines.append("|----------|--------------|-----------|-------------|-------|------------|")
    for plat in sorted(by_platform.keys()):
        p = by_platform[plat]
        pct = 100 * p["fully"] / p["total"] if p["total"] else 0
        lines.append(f"| {plat} | {p['fully']} | {p['partial']} | {p['not_covered']} | {p['total']} | {pct:.0f}% |")
    lines.append("")

    # Fully covered techniques
    lines.append("## Fully Covered Techniques")
    lines.append("")
    lines.append("| Technique | Name | Tactics | Rules | Confidence |")
    lines.append("|-----------|------|---------|-------|------------|")
    for tid in sorted(fully.keys()):
        info = fully[tid]
        rule_count = rules_per_technique.get(tid, 0)
        lines.append(
            f"| {tid} | {info['technique_name']} | {', '.join(info['tactics'])} "
            f"| {rule_count} | medium |"
        )
    lines.append("")

    # Partially covered techniques
    lines.append("## Partially Covered Techniques")
    lines.append("")
    lines.append("| Technique | Name | Covered | Missing | Recommendation |")
    lines.append("|-----------|------|---------|---------|----------------|")
    for tid in sorted(partial.keys()):
        info = partial[tid]
        covered = ", ".join(info["covered_components"])
        missing = ", ".join(info["missing_components"])
        recs = "; ".join(
            DATA_SOURCE_RECOMMENDATIONS.get(m, "Research additional data sources")
            for m in info["missing_components"][:2]
        )
        lines.append(f"| {tid} | {info['technique_name']} | {covered} | {missing} | {recs} |")
    lines.append("")

    # Not covered techniques
    lines.append("## Not Covered Techniques")
    lines.append("")
    lines.append("| Technique | Name | Missing Data Sources | Recommendation |")
    lines.append("|-----------|------|---------------------|----------------|")
    for tid in sorted(not_covered.keys()):
        info = not_covered[tid]
        missing = ", ".join(info["missing_components"]) or info.get("reason", "unknown")
        recs = "; ".join(
            DATA_SOURCE_RECOMMENDATIONS.get(m, "Research data source options")
            for m in info.get("missing_components", [])[:2]
        )
        if not recs:
            recs = info.get("reason", "No ATT&CK data components defined")
        lines.append(f"| {tid} | {info['technique_name']} | {missing} | {recs} |")
    lines.append("")

    # Data source recommendations (prioritized)
    lines.append("## Data Source Recommendations")
    lines.append("")
    lines.append("Prioritized by number of currently-uncovered techniques each data source would address:")
    lines.append("")
    lines.append("| Data Component | Uncovered Techniques | Recommendation |")
    lines.append("|---------------|---------------------|----------------|")
    for comp, tids in sorted(missing_impact.items(), key=lambda x: -len(x[1]))[:25]:
        rec = DATA_SOURCE_RECOMMENDATIONS.get(comp, "Research integration options")
        lines.append(f"| {comp} | {len(tids)} | {rec} |")
    lines.append("")

    return "\n".join(lines)


def generate_navigator_layer(coverage: dict) -> dict:
    """Generate ATT&CK Navigator JSON layer."""
    layer = json.loads(json.dumps(NAVIGATOR_LAYER_TEMPLATE))  # deep copy

    for tid, info in coverage.items():
        status = info["status"]

        if status == "fully_covered":
            color = "#66bb6a"
            score = 100
            comment = f"Covered by LC events: {', '.join(info.get('lc_events', []))}"
        elif status == "partially_covered":
            color = "#ffeb3b"
            score = 50
            missing = ", ".join(info.get("missing_components", []))
            comment = f"Partial coverage. Missing: {missing}"
        else:
            # Determine if it's coverable at all
            reason = info.get("reason", "")
            missing = info.get("missing_components", [])
            if reason == "no data components defined in ATT&CK":
                color = "#9e9e9e"
                score = 0
                comment = "No data components defined in ATT&CK"
            elif any(
                m in (
                    "Firmware Modification",
                    "Cloud Storage Access",
                    "Instance Creation",
                    "Container Creation",
                    "Pod Creation",
                )
                for m in missing
            ):
                color = "#9e9e9e"
                score = 0
                comment = f"Requires non-endpoint telemetry: {', '.join(missing)}"
            else:
                color = "#ff6666"
                score = 0
                comment = f"Gap: missing {', '.join(missing)}"

        technique_entry = {
            "techniqueID": tid,
            "color": color,
            "score": score,
            "comment": comment,
            "enabled": True,
            "showSubtechniques": False,
        }

        # Add tactic information
        tactics = info.get("tactics", [])
        if tactics:
            technique_entry["tactic"] = tactics[0]

        layer["techniques"].append(technique_entry)

    return layer


def main():
    config = load_config()
    cache_dir = BASE_DIR / config["attack_data"]["cache_dir"]

    # Load data
    coverage = load_technique_coverage()
    rules = load_generated_rules()

    parsed = load_parsed_data(cache_dir / "parsed_attack.json")
    techniques = parsed["techniques"]

    if not coverage:
        logger.error("No coverage data found. Run 02_map_telemetry.py first.")
        return

    output_dir = BASE_DIR / "output"
    output_dir.mkdir(parents=True, exist_ok=True)

    # Generate markdown report
    report = generate_report(coverage, rules, techniques)
    report_path = output_dir / "coverage_report.md"
    with open(report_path, "w") as f:
        f.write(report)
    logger.info("Coverage report written to %s", report_path)

    # Generate Navigator layer
    layer = generate_navigator_layer(coverage)
    layer_path = output_dir / "navigator_layer.json"
    with open(layer_path, "w") as f:
        json.dump(layer, f, indent=2)
    logger.info("ATT&CK Navigator layer written to %s", layer_path)

    # Print summary
    total = len(coverage)
    fully = sum(1 for v in coverage.values() if v["status"] == "fully_covered")
    logger.info("--- Phase 5 Summary ---")
    logger.info("Report: %s", report_path)
    logger.info("Navigator layer: %s", layer_path)
    logger.info("Overall coverage: %d/%d techniques (%.1f%%)", fully, total, 100 * fully / total if total else 0)
    logger.info("Upload navigator_layer.json to https://mitre-attack.github.io/attack-navigator/ for visualization")


if __name__ == "__main__":
    main()
