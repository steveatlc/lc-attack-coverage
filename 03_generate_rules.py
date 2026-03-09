#!/usr/bin/env python3
"""Phase 3: Generate D&R rules from ATT&CK technique mappings and Atomic Red Team indicators."""

import json
import logging
from pathlib import Path

import yaml

from lib.attack_parser import load_parsed_data
from lib.rule_generator import (
    GeneratedRule,
    deduplicate_rules,
    generate_rules_for_technique,
    rule_to_yaml,
)

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger(__name__)

BASE_DIR = Path(__file__).parent
CONFIG_PATH = BASE_DIR / "config.yaml"


def load_config() -> dict:
    with open(CONFIG_PATH) as f:
        return yaml.safe_load(f)


def load_technique_coverage() -> dict:
    path = BASE_DIR / "mappings" / "technique_rules.yaml"
    with open(path) as f:
        return yaml.safe_load(f) or {}


def load_atomic_data(cache_dir: Path) -> dict:
    path = cache_dir / "parsed_atomics.json"
    if not path.exists():
        return {}
    with open(path) as f:
        return json.load(f)


def main():
    config = load_config()
    cache_dir = BASE_DIR / config["attack_data"]["cache_dir"]
    rules_config = config.get("rules", {})

    base_priority = rules_config.get("priority_base", 3)
    priority_cap = rules_config.get("priority_cap", 10)
    default_confidence = rules_config.get("default_confidence", "medium")
    suppression_period = rules_config.get("default_suppression_period", "1h")
    suppression_max_count = rules_config.get("default_suppression_max_count", 5)

    # Load data
    parsed = load_parsed_data(cache_dir / "parsed_attack.json")
    techniques = parsed["techniques"]
    coverage = load_technique_coverage()
    atomic_data = load_atomic_data(cache_dir)

    output_dir = BASE_DIR / "output" / "rules"
    output_dir.mkdir(parents=True, exist_ok=True)

    all_rules: list[GeneratedRule] = []
    skipped = 0

    for tid, tech in techniques.items():
        cov = coverage.get(tid)
        if not cov:
            skipped += 1
            continue

        # Only generate rules for techniques with at least partial coverage
        if cov["status"] == "not_covered" and cov.get("reason") != "no data components defined in ATT&CK":
            skipped += 1
            continue

        # Gather indicators from atomic tests
        indicators = []
        atomic_tests = atomic_data.get(tid, [])
        for test in atomic_tests:
            for ind in test.get("indicators", []):
                indicators.append(ind)

        tactics = tech.tactics if hasattr(tech, "tactics") else tech.get("tactics", [])
        platforms = tech.platforms if hasattr(tech, "platforms") else tech.get("platforms", [])
        url = tech.url if hasattr(tech, "url") else tech.get("url", "")
        name = tech.name if hasattr(tech, "name") else tech.get("name", "")
        group_count = tech.threat_group_count if hasattr(tech, "threat_group_count") else tech.get("threat_group_count", 0)
        data_comps = cov.get("covered_components", [])

        rules = generate_rules_for_technique(
            technique_id=tid,
            technique_name=name,
            tactics=tactics,
            platforms=platforms,
            url=url,
            threat_group_count=group_count,
            indicators=indicators,
            data_components=data_comps,
            base_priority=base_priority,
            priority_cap=priority_cap,
            confidence=default_confidence,
            suppression_period=suppression_period,
            suppression_max_count=suppression_max_count,
        )
        all_rules.extend(rules)

    # Deduplicate
    all_rules = deduplicate_rules(all_rules)

    # Write individual rule files
    for rule in all_rules:
        filename = f"{rule.name}.yaml"
        filepath = output_dir / filename
        rule_data = {
            "name": rule.name,
            "detect": rule.detect,
            "respond": rule.respond,
            "tags": rule.tags,
            "comment": rule.comment,
        }
        with open(filepath, "w") as f:
            yaml.dump(rule_data, f, default_flow_style=False, sort_keys=False)

    # Write consolidated rules file
    consolidated_path = BASE_DIR / "output" / "all_rules.yaml"
    consolidated = {}
    for rule in all_rules:
        consolidated[rule.name] = {
            "detect": rule.detect,
            "respond": rule.respond,
            "tags": rule.tags,
            "comment": rule.comment,
        }
    with open(consolidated_path, "w") as f:
        yaml.dump(consolidated, f, default_flow_style=False, sort_keys=True)

    # Summary
    by_tactic = {}
    by_confidence = {}
    by_platform = {}
    for rule in all_rules:
        by_tactic[rule.tactic] = by_tactic.get(rule.tactic, 0) + 1
        by_confidence[rule.confidence] = by_confidence.get(rule.confidence, 0) + 1
        by_platform[rule.platform] = by_platform.get(rule.platform, 0) + 1

    logger.info("--- Phase 3 Summary ---")
    logger.info("Total rules generated: %d", len(all_rules))
    logger.info("Techniques skipped (no coverage): %d", skipped)
    logger.info("\nRules by tactic:")
    for tactic, count in sorted(by_tactic.items(), key=lambda x: -x[1]):
        logger.info("  %s: %d", tactic, count)
    logger.info("\nRules by confidence:")
    for conf, count in sorted(by_confidence.items()):
        logger.info("  %s: %d", conf, count)
    logger.info("\nRules by platform:")
    for plat, count in sorted(by_platform.items(), key=lambda x: -x[1]):
        logger.info("  %s: %d", plat or "(all)", count)
    logger.info("\nIndividual rule files: %s", output_dir)
    logger.info("Consolidated file: %s", consolidated_path)


if __name__ == "__main__":
    main()
