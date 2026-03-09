#!/usr/bin/env python3
"""Phase 1: Download and cache ATT&CK STIX data and Atomic Red Team test definitions."""

import json
import logging
import subprocess
import sys
from pathlib import Path

import requests
import yaml

from lib.attack_parser import parse_stix_bundle, save_parsed_data
from lib.atomic_parser import parse_atomic_directory

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger(__name__)

BASE_DIR = Path(__file__).parent
CONFIG_PATH = BASE_DIR / "config.yaml"


def load_config() -> dict:
    with open(CONFIG_PATH) as f:
        return yaml.safe_load(f)


def download_stix(url: str, dest: Path) -> None:
    """Download the ATT&CK STIX bundle if not already cached."""
    if dest.exists():
        logger.info("STIX bundle already cached at %s", dest)
        return

    logger.info("Downloading ATT&CK STIX bundle from %s", url)
    resp = requests.get(url, timeout=120)
    resp.raise_for_status()
    dest.parent.mkdir(parents=True, exist_ok=True)
    with open(dest, "w") as f:
        f.write(resp.text)
    logger.info("Saved STIX bundle to %s (%.1f MB)", dest, dest.stat().st_size / 1e6)


def clone_atomic_red_team(repo_url: str, dest: Path) -> None:
    """Sparse-checkout the atomics/ directory from Atomic Red Team."""
    if dest.exists() and any(dest.iterdir()):
        logger.info("Atomic Red Team data already present at %s, pulling updates", dest)
        repo_root = dest.parent  # data/ directory contains the .git for sparse checkout
        # Check if it's a git repo
        git_dir = repo_root / "atomic-red-team"
        if git_dir.exists():
            subprocess.run(
                ["git", "-C", str(git_dir), "pull", "--ff-only"],
                check=False,
                capture_output=True,
            )
        return

    logger.info("Cloning Atomic Red Team (sparse checkout of atomics/ only)")
    dest.parent.mkdir(parents=True, exist_ok=True)
    clone_dir = dest.parent / "atomic-red-team"

    subprocess.run(
        [
            "git",
            "clone",
            "--depth=1",
            "--filter=blob:none",
            "--sparse",
            repo_url,
            str(clone_dir),
        ],
        check=True,
    )
    subprocess.run(
        ["git", "-C", str(clone_dir), "sparse-checkout", "set", "atomics"],
        check=True,
    )

    # Symlink atomics/ into data/atomics for convenience (absolute path)
    atomics_src = clone_dir / "atomics"
    if atomics_src.exists():
        if dest.is_dir() and not dest.is_symlink():
            dest.rmdir()  # Remove empty placeholder directory
        if not dest.exists():
            dest.symlink_to(atomics_src.resolve())
            logger.info("Linked %s → %s", dest, atomics_src.resolve())


def main():
    config = load_config()
    cache_dir = BASE_DIR / config["attack_data"]["cache_dir"]
    cache_dir.mkdir(parents=True, exist_ok=True)

    # Step 1: Download STIX bundles (latest + v15.1 for data source mappings)
    stix_path = cache_dir / "enterprise-attack.json"
    download_stix(config["attack_data"]["stix_url"], stix_path)

    # v15.1 has x_mitre_data_sources on techniques and data-component "detects"
    # relationships, which were removed in v16+.
    ds_stix_url = config["attack_data"].get(
        "datasource_stix_url",
        "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack-15.1.json",
    )
    ds_stix_path = cache_dir / "enterprise-attack-15.1.json"
    download_stix(ds_stix_url, ds_stix_path)

    # Step 2: Clone Atomic Red Team
    atomics_path = cache_dir / "atomics"
    clone_atomic_red_team(config["attack_data"]["atomic_repo"], atomics_path)

    # Step 3: Parse STIX data (latest for techniques/groups, v15.1 for data source linkage)
    logger.info("Parsing ATT&CK STIX bundles...")
    parsed_attack = parse_stix_bundle(stix_path, datasource_stix_path=ds_stix_path)
    attack_cache = cache_dir / "parsed_attack.json"
    save_parsed_data(parsed_attack, attack_cache)

    # Step 4: Parse Atomic Red Team data
    logger.info("Parsing Atomic Red Team tests...")
    atomic_tests = parse_atomic_directory(atomics_path)

    # Save atomic data cache
    atomic_cache = cache_dir / "parsed_atomics.json"
    atomic_serializable = {}
    for tid, tests in atomic_tests.items():
        atomic_serializable[tid] = []
        for test in tests:
            t = {
                "technique_id": test.technique_id,
                "test_name": test.test_name,
                "test_number": test.test_number,
                "description": test.description,
                "supported_platforms": test.supported_platforms,
                "executor_name": test.executor_name,
                "elevation_required": test.elevation_required,
                "indicators": [
                    {
                        "type": ind.type,
                        "value": ind.value,
                        "platform": ind.platform,
                        "context": ind.context,
                    }
                    for ind in test.indicators
                ],
            }
            atomic_serializable[tid].append(t)

    with open(atomic_cache, "w") as f:
        json.dump(atomic_serializable, f, indent=2)
    logger.info("Saved parsed atomic data to %s", atomic_cache)

    # Summary
    tech_count = len(parsed_attack["techniques"])
    atomic_count = len(atomic_tests)
    total_tests = sum(len(t) for t in atomic_tests.values())
    total_indicators = sum(
        len(ind)
        for tests in atomic_tests.values()
        for t in tests
        for ind in [t.indicators]
    )

    logger.info("--- Phase 1 Summary ---")
    logger.info("ATT&CK techniques: %d", tech_count)
    logger.info("Techniques with atomic tests: %d", atomic_count)
    logger.info("Total atomic tests: %d", total_tests)
    logger.info("Total extracted indicators: %d", total_indicators)


if __name__ == "__main__":
    main()
