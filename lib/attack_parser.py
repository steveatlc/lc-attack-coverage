"""Parse MITRE ATT&CK STIX bundle into usable structures."""

import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)


@dataclass
class DataComponent:
    id: str
    name: str
    data_source_name: str
    data_source_id: str


@dataclass
class Technique:
    id: str  # e.g. "T1059.001"
    name: str
    description: str
    tactics: list[str] = field(default_factory=list)
    platforms: list[str] = field(default_factory=list)
    data_components: list[str] = field(default_factory=list)
    is_subtechnique: bool = False
    parent_id: Optional[str] = None
    url: str = ""
    threat_group_count: int = 0  # Number of groups using this technique


def parse_stix_bundle(stix_path: Path, datasource_stix_path: Optional[Path] = None) -> dict:
    """Parse ATT&CK STIX bundle(s) and return structured data.

    Args:
        stix_path: Path to the primary (latest) STIX bundle.
        datasource_stix_path: Optional path to an older STIX bundle (e.g. v15.1)
            that contains x_mitre_data_sources on techniques and data-component
            "detects" relationships.  If the primary bundle lacks these, the
            older bundle is used to populate technique → data component mappings.

    Returns dict with keys:
        techniques: dict[str, Technique]
        data_sources: dict[str, dict]
        data_components: dict[str, DataComponent]
    """
    logger.info("Loading STIX bundle from %s", stix_path)
    with open(stix_path, "r") as f:
        bundle = json.load(f)

    objects = bundle.get("objects", [])

    # If a separate data-source bundle is provided, load it too
    ds_objects = []
    if datasource_stix_path and datasource_stix_path.exists():
        logger.info("Loading data-source STIX bundle from %s", datasource_stix_path)
        with open(datasource_stix_path, "r") as f:
            ds_bundle = json.load(f)
        ds_objects = ds_bundle.get("objects", [])

    # Index all objects by ID for relationship resolution
    obj_by_id = {}
    for obj in objects:
        obj_by_id[obj["id"]] = obj

    ds_obj_by_id = {}
    for obj in ds_objects:
        ds_obj_by_id[obj["id"]] = obj

    # Extract data sources (from whichever bundle has them)
    data_sources = {}
    for obj in (objects + ds_objects):
        if obj.get("type") == "x-mitre-data-source" and not obj.get("revoked", False):
            ds_name = obj.get("name", "")
            if ds_name not in data_sources:
                data_sources[ds_name] = {
                    "id": obj["id"],
                    "name": ds_name,
                    "description": obj.get("description", ""),
                }

    # Extract data components and link to data sources
    data_components = {}
    component_id_to_name = {}
    for obj in (objects + ds_objects):
        if obj.get("type") == "x-mitre-data-component" and not obj.get("revoked", False):
            comp_name = obj.get("name", "")
            if comp_name in data_components:
                continue
            ds_ref = obj.get("x_mitre_data_source_ref", "")
            ds_obj = obj_by_id.get(ds_ref) or ds_obj_by_id.get(ds_ref, {})
            dc = DataComponent(
                id=obj["id"],
                name=comp_name,
                data_source_name=ds_obj.get("name", ""),
                data_source_id=ds_ref,
            )
            data_components[comp_name] = dc
            component_id_to_name[obj["id"]] = comp_name

    # Extract relationships from both bundles
    all_rels = [o for o in (objects + ds_objects)
                if o.get("type") == "relationship" and not o.get("revoked", False)]

    tech_to_components = {}  # technique STIX ID → set of component names
    tech_to_group_count = {}  # technique STIX ID → count of groups
    for obj in all_rels:
        rel_type = obj.get("relationship_type", "")
        source = obj.get("source_ref", "")
        target = obj.get("target_ref", "")

        if rel_type == "detects":
            # In ATT&CK ≤v15: source = x-mitre-data-component, target = attack-pattern
            comp_name = component_id_to_name.get(source)
            if comp_name:
                tech_to_components.setdefault(target, set()).add(comp_name)

        if rel_type == "uses":
            # source = intrusion-set (group), target = attack-pattern (technique)
            source_obj = obj_by_id.get(source) or ds_obj_by_id.get(source, {})
            if source_obj.get("type") == "intrusion-set":
                tech_to_group_count[target] = tech_to_group_count.get(target, 0) + 1

    # Extract techniques from the PRIMARY bundle (latest version)
    techniques = {}
    for obj in objects:
        if obj.get("type") != "attack-pattern" or obj.get("revoked", False):
            continue

        external_refs = obj.get("external_references", [])
        technique_id = ""
        url = ""
        for ref in external_refs:
            if ref.get("source_name") == "mitre-attack":
                technique_id = ref.get("external_id", "")
                url = ref.get("url", "")
                break

        if not technique_id:
            continue

        # Extract tactics from kill chain phases
        tactics = []
        for phase in obj.get("kill_chain_phases", []):
            if phase.get("kill_chain_name") == "mitre-attack":
                tactics.append(phase["phase_name"])

        # Normalize platforms to lowercase
        platforms = [p.lower() for p in obj.get("x_mitre_platforms", [])]

        # Get data components — try three sources:
        # 1. x_mitre_data_sources field on the technique (format: "Data Source: Component")
        # 2. Relationship-based mapping from the ds bundle
        # 3. x_mitre_data_sources from the ds bundle's copy of this technique
        stix_id = obj["id"]
        comp_names = set(tech_to_components.get(stix_id, set()))

        # Also try x_mitre_data_sources field (present in ≤v15 bundles)
        inline_ds = obj.get("x_mitre_data_sources", [])
        if not inline_ds and ds_objects:
            # Look up this technique in the ds bundle by external_id
            ds_tech = _find_technique_in_bundle(ds_objects, technique_id)
            if ds_tech:
                inline_ds = ds_tech.get("x_mitre_data_sources", [])
                # Also grab relationship-based components from ds bundle
                ds_stix_id = ds_tech["id"]
                comp_names.update(tech_to_components.get(ds_stix_id, set()))

        # Parse "Data Source: Component" format
        for ds_entry in inline_ds:
            if ": " in ds_entry:
                comp_name = ds_entry.split(": ", 1)[1]
                comp_names.add(comp_name)

        is_sub = obj.get("x_mitre_is_subtechnique", False)
        parent_id = None
        if is_sub and "." in technique_id:
            parent_id = technique_id.split(".")[0]

        tech = Technique(
            id=technique_id,
            name=obj.get("name", ""),
            description=obj.get("description", ""),
            tactics=tactics,
            platforms=platforms,
            data_components=sorted(comp_names),
            is_subtechnique=is_sub,
            parent_id=parent_id,
            url=url,
            threat_group_count=tech_to_group_count.get(stix_id, 0),
        )
        techniques[technique_id] = tech

    with_dc = sum(1 for t in techniques.values() if t.data_components)
    logger.info(
        "Parsed %d techniques (%d with data components), %d data sources, %d data components",
        len(techniques),
        with_dc,
        len(data_sources),
        len(data_components),
    )
    return {
        "techniques": techniques,
        "data_sources": data_sources,
        "data_components": data_components,
    }


# Cache for ds bundle technique lookups
_ds_tech_cache: dict[str, dict] = {}


def _find_technique_in_bundle(objects: list, technique_id: str) -> Optional[dict]:
    """Find a technique object in a STIX object list by its external ID."""
    # Build cache on first call
    if not _ds_tech_cache:
        for obj in objects:
            if obj.get("type") != "attack-pattern":
                continue
            for ref in obj.get("external_references", []):
                if ref.get("source_name") == "mitre-attack":
                    _ds_tech_cache[ref["external_id"]] = obj
                    break
    return _ds_tech_cache.get(technique_id)


def save_parsed_data(parsed: dict, output_path: Path) -> None:
    """Serialize parsed ATT&CK data to JSON cache."""

    def serialize(obj):
        if hasattr(obj, "__dataclass_fields__"):
            return {k: getattr(obj, k) for k in obj.__dataclass_fields__}
        if isinstance(obj, set):
            return list(obj)
        raise TypeError(f"Cannot serialize {type(obj)}")

    with open(output_path, "w") as f:
        json.dump(parsed, f, default=serialize, indent=2)
    logger.info("Saved parsed ATT&CK data to %s", output_path)


def load_parsed_data(cache_path: Path) -> dict:
    """Load cached parsed ATT&CK data and reconstruct dataclasses."""
    with open(cache_path, "r") as f:
        raw = json.load(f)

    techniques = {}
    for tid, tdata in raw.get("techniques", {}).items():
        techniques[tid] = Technique(**tdata)

    data_components = {}
    for cname, cdata in raw.get("data_components", {}).items():
        data_components[cname] = DataComponent(**cdata)

    return {
        "techniques": techniques,
        "data_sources": raw.get("data_sources", {}),
        "data_components": data_components,
    }
