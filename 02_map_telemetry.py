#!/usr/bin/env python3
"""Phase 2: Map ATT&CK data sources to LimaCharlie events. Identify coverage gaps."""

import json
import logging
from pathlib import Path

import yaml

from lib.attack_parser import load_parsed_data

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger(__name__)

BASE_DIR = Path(__file__).parent
CONFIG_PATH = BASE_DIR / "config.yaml"
MAPPING_PATH = BASE_DIR / "mappings" / "lc_event_to_datasource.yaml"


def load_config() -> dict:
    with open(CONFIG_PATH) as f:
        return yaml.safe_load(f)


def load_lc_mapping() -> dict:
    """Load the hand-authored LC event → ATT&CK data component mapping."""
    with open(MAPPING_PATH) as f:
        return yaml.safe_load(f)


def build_component_coverage(lc_mapping: dict) -> dict:
    """Build a set of ATT&CK data component names that LC can observe.

    Returns dict: component_name → list of LC events that provide it.
    """
    coverage = {}
    for event_type, config in lc_mapping.items():
        for component in config.get("data_components", []):
            coverage.setdefault(component, []).append(event_type)
    return coverage


def assess_technique_coverage(
    techniques: dict,
    component_coverage: dict,
    config: dict,
) -> dict:
    """Assess coverage for each technique.

    Returns dict with technique_id → {
        status: "fully_covered" | "partially_covered" | "not_covered",
        covered_components: [...],
        missing_components: [...],
        lc_events: [...],
    }
    """
    full_threshold = config["coverage"]["fully_covered_min_components"]
    partial_threshold = config["coverage"]["partial_covered_min_components"]
    allowed_platforms = set(config.get("platforms", ["windows", "linux", "macos"]))

    results = {}
    for tid, tech in techniques.items():
        # Filter by platforms
        tech_platforms = set(tech.platforms) if hasattr(tech, "platforms") else set(tech.get("platforms", []))
        if not tech_platforms & allowed_platforms:
            continue

        required = tech.data_components if hasattr(tech, "data_components") else tech.get("data_components", [])
        if not required:
            results[tid] = {
                "status": "not_covered",
                "reason": "no data components defined in ATT&CK",
                "covered_components": [],
                "missing_components": [],
                "lc_events": [],
                "technique_name": tech.name if hasattr(tech, "name") else tech.get("name", ""),
                "tactics": tech.tactics if hasattr(tech, "tactics") else tech.get("tactics", []),
                "platforms": list(tech_platforms),
            }
            continue

        covered = []
        missing = []
        lc_events = set()

        for comp in required:
            if comp in component_coverage:
                covered.append(comp)
                lc_events.update(component_coverage[comp])
            else:
                missing.append(comp)

        if len(required) > 0:
            ratio = len(covered) / len(required)
        else:
            ratio = 0

        if ratio >= full_threshold:
            status = "fully_covered"
        elif ratio >= partial_threshold:
            status = "partially_covered"
        else:
            status = "not_covered"

        results[tid] = {
            "status": status,
            "covered_components": covered,
            "missing_components": missing,
            "lc_events": sorted(lc_events),
            "coverage_ratio": round(ratio, 2),
            "technique_name": tech.name if hasattr(tech, "name") else tech.get("name", ""),
            "tactics": tech.tactics if hasattr(tech, "tactics") else tech.get("tactics", []),
            "platforms": list(tech_platforms),
        }

    return results


def main():
    config = load_config()
    cache_dir = BASE_DIR / config["attack_data"]["cache_dir"]

    # Load parsed ATT&CK data
    attack_cache = cache_dir / "parsed_attack.json"
    if not attack_cache.exists():
        logger.error("Parsed ATT&CK data not found. Run 01_fetch_attack_data.py first.")
        return

    parsed = load_parsed_data(attack_cache)
    techniques = parsed["techniques"]

    # Load LC event mapping
    lc_mapping = load_lc_mapping()
    component_coverage = build_component_coverage(lc_mapping)

    logger.info("LC covers %d ATT&CK data components via %d event types",
                len(component_coverage), len(lc_mapping))

    # Assess coverage
    coverage = assess_technique_coverage(techniques, component_coverage, config)

    # Save results
    output_path = BASE_DIR / "mappings" / "technique_rules.yaml"
    with open(output_path, "w") as f:
        yaml.dump(coverage, f, default_flow_style=False, sort_keys=True)
    logger.info("Saved technique coverage mapping to %s", output_path)

    # Summary
    fully = sum(1 for v in coverage.values() if v["status"] == "fully_covered")
    partial = sum(1 for v in coverage.values() if v["status"] == "partially_covered")
    not_cov = sum(1 for v in coverage.values() if v["status"] == "not_covered")
    total = len(coverage)

    logger.info("--- Phase 2 Summary ---")
    logger.info("Total techniques assessed: %d", total)
    logger.info("Fully covered:    %d (%.1f%%)", fully, 100 * fully / total if total else 0)
    logger.info("Partially covered: %d (%.1f%%)", partial, 100 * partial / total if total else 0)
    logger.info("Not covered:      %d (%.1f%%)", not_cov, 100 * not_cov / total if total else 0)

    # List most impactful missing data components
    missing_impact = {}
    for tid, info in coverage.items():
        for comp in info.get("missing_components", []):
            missing_impact.setdefault(comp, []).append(tid)

    if missing_impact:
        logger.info("\nTop missing data components (by technique count):")
        for comp, tids in sorted(missing_impact.items(), key=lambda x: -len(x[1]))[:15]:
            logger.info("  %s: %d techniques", comp, len(tids))


if __name__ == "__main__":
    main()
