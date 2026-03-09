"""LimaCharlie SDK wrapper for D&R rule deployment via Hive."""

import logging
import os
from dataclasses import dataclass
from typing import Optional

logger = logging.getLogger(__name__)


@dataclass
class DeployResult:
    rule_name: str
    success: bool
    message: str = ""


def get_manager(org_id: Optional[str] = None, api_key: Optional[str] = None):
    """Create a LimaCharlie Manager instance.

    Uses provided credentials, then environment variables (LC_OID, LC_API_KEY),
    then falls back to the LC CLI's stored credentials.
    """
    import limacharlie

    oid = org_id or os.environ.get("LC_OID", "")
    key = api_key or os.environ.get("LC_API_KEY", "")

    if oid and key:
        return limacharlie.Manager(oid=oid, secret_api_key=key)

    # Fall back to SDK's default credential resolution (CLI stored creds)
    try:
        man = limacharlie.Manager()
        logger.info("Using LC CLI stored credentials for org %s", man._oid)
        return man
    except Exception:
        raise ValueError(
            "LimaCharlie credentials required. Set LC_OID and LC_API_KEY "
            "environment variables, store credentials via 'limacharlie login', "
            "or pass org_id and api_key."
        )


def deploy_rule(
    manager,
    rule_name: str,
    detect: dict,
    respond: list,
    tags: list[str],
    comment: str = "",
    enabled: bool = True,
    dry_run: bool = False,
) -> DeployResult:
    """Deploy a single D&R rule to the org via Hive.

    Args:
        manager: LimaCharlie Manager instance
        rule_name: Unique rule name
        detect: Detection logic dict
        respond: Response action list
        tags: Tags to apply
        comment: Rule description
        enabled: Whether rule is active
        dry_run: If True, validate but don't deploy
    """
    if dry_run:
        logger.info("[DRY RUN] Would deploy rule: %s", rule_name)
        return DeployResult(rule_name=rule_name, success=True, message="dry run")

    try:
        from limacharlie.Hive import Hive, HiveRecord

        hive = Hive(manager, "dr-general")
        # HiveRecord expects (recordName, data_dict) where data_dict
        # has 'data' and 'usr_mtd' keys matching the API format.
        record = HiveRecord(
            rule_name,
            {
                "data": {"detect": detect, "respond": respond},
                "usr_mtd": {
                    "enabled": enabled,
                    "tags": tags,
                    "comment": comment,
                },
            },
        )
        hive.set(record)
        logger.info("Deployed rule: %s", rule_name)
        return DeployResult(rule_name=rule_name, success=True, message="deployed")
    except Exception as e:
        logger.error("Failed to deploy rule %s: %s", rule_name, e)
        return DeployResult(rule_name=rule_name, success=False, message=str(e))


def list_rules(manager, tag_filter: Optional[str] = None) -> list[dict]:
    """List existing D&R rules, optionally filtered by tag."""
    try:
        from limacharlie.Hive import Hive

        hive = Hive(manager, "dr-general")
        records = hive.list()  # returns dict: name → HiveRecord
        rules = []
        for name, rec in records.items():
            if tag_filter and tag_filter not in (rec.tags or []):
                continue
            rules.append(
                {
                    "name": rec.name,
                    "tags": rec.tags,
                    "enabled": rec.enabled,
                    "comment": rec.comment,
                }
            )
        return rules
    except Exception as e:
        logger.error("Failed to list rules: %s", e)
        return []


def delete_rules_by_tag(
    manager, tag: str, dry_run: bool = False
) -> list[DeployResult]:
    """Delete all rules matching a specific tag."""
    results = []
    try:
        from limacharlie.Hive import Hive

        hive = Hive(manager, "dr-general")
        records = hive.list()  # returns dict: name → HiveRecord
        for name, rec in records.items():
            if tag in (rec.tags or []):
                if dry_run:
                    logger.info("[DRY RUN] Would delete rule: %s", rec.name)
                    results.append(
                        DeployResult(rec.name, True, "dry run delete")
                    )
                else:
                    try:
                        hive.delete(rec.name)
                        logger.info("Deleted rule: %s", rec.name)
                        results.append(DeployResult(rec.name, True, "deleted"))
                    except Exception as e:
                        logger.error("Failed to delete %s: %s", rec.name, e)
                        results.append(DeployResult(rec.name, False, str(e)))
    except Exception as e:
        logger.error("Failed to list rules for deletion: %s", e)

    return results
