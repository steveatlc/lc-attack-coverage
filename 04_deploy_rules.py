#!/usr/bin/env python3
"""Phase 4: Deploy generated D&R rules to a LimaCharlie test org."""

import argparse
import logging
import os
import sys
from pathlib import Path

import yaml

from lib.lc_client import deploy_rule, get_manager, delete_rules_by_tag

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger(__name__)

BASE_DIR = Path(__file__).parent
CONFIG_PATH = BASE_DIR / "config.yaml"


def load_config() -> dict:
    with open(CONFIG_PATH) as f:
        return yaml.safe_load(f)


def load_rules(rules_dir: Path, technique_filter: str = None, tactic_filter: str = None) -> list[dict]:
    """Load rule YAML files from output/rules/, optionally filtered."""
    rules = []
    for rule_file in sorted(rules_dir.glob("*.yaml")):
        with open(rule_file) as f:
            rule = yaml.safe_load(f)
        if not rule:
            continue

        # Apply filters
        if technique_filter:
            name = rule.get("name", "")
            if technique_filter.upper() not in name.upper():
                continue

        if tactic_filter:
            tags = rule.get("tags", [])
            if tactic_filter.lower() not in [t.lower() for t in tags]:
                continue

        rules.append(rule)

    return rules


def main():
    parser = argparse.ArgumentParser(description="Deploy ATT&CK D&R rules to LimaCharlie")
    parser.add_argument("--dry-run", action="store_true", help="Validate rules without deploying")
    parser.add_argument("--filter-technique", type=str, help="Only deploy rules matching this technique ID (e.g., T1059)")
    parser.add_argument("--filter-tactic", type=str, help="Only deploy rules matching this tactic (e.g., execution)")
    parser.add_argument("--clean", action="store_true", help="Remove all existing attack-coverage rules before deploying")
    parser.add_argument("--org-id", type=str, help="Override org ID from config")
    parser.add_argument("--api-key-env", type=str, help="Override API key env var name")
    args = parser.parse_args()

    config = load_config()
    deploy_config = config.get("deployment", {})

    org_id = args.org_id or deploy_config.get("org_id", "")
    api_key_env = args.api_key_env or deploy_config.get("api_key_env", "LC_API_KEY")
    api_key = os.environ.get(api_key_env, "")

    if org_id == "your-org-id-here":
        logger.error("Please set a real org ID in config.yaml or via --org-id")
        sys.exit(1)

    # Load rules
    rules_dir = BASE_DIR / "output" / "rules"
    if not rules_dir.exists():
        logger.error("No rules found. Run 03_generate_rules.py first.")
        sys.exit(1)

    rules = load_rules(rules_dir, args.filter_technique, args.filter_tactic)
    logger.info("Loaded %d rules to deploy", len(rules))

    if not rules:
        logger.warning("No rules match the specified filters.")
        return

    # Connect to LC
    try:
        manager = get_manager(org_id, api_key)
    except Exception as e:
        logger.error("Failed to connect to LimaCharlie: %s", e)
        sys.exit(1)

    # Clean existing rules if requested
    if args.clean:
        logger.info("Cleaning existing attack-coverage rules...")
        results = delete_rules_by_tag(manager, "attack-coverage", dry_run=args.dry_run)
        deleted = sum(1 for r in results if r.success)
        logger.info("Cleaned %d existing rules", deleted)

    # Deploy rules
    success = 0
    failed = 0
    for rule in rules:
        result = deploy_rule(
            manager=manager,
            rule_name=rule["name"],
            detect=rule["detect"],
            respond=rule["respond"],
            tags=rule.get("tags", []),
            comment=rule.get("comment", ""),
            dry_run=args.dry_run,
        )
        if result.success:
            success += 1
        else:
            failed += 1
            logger.warning("  Failed: %s - %s", result.rule_name, result.message)

    # Summary
    mode = "[DRY RUN] " if args.dry_run else ""
    logger.info("--- Phase 4 Summary ---")
    logger.info("%sSuccessful: %d", mode, success)
    logger.info("%sFailed: %d", mode, failed)
    logger.info("%sTotal: %d", mode, success + failed)


if __name__ == "__main__":
    main()
