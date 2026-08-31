"""Merges target info and module results into one report object, and
groups observations by category (per the design doc's report structure)
rather than by module, since that reads better as a 'profile'."""

import uuid
from datetime import datetime, timezone

CATEGORY_ORDER = [
    "Domain & Registration",
    "Hosting & Network",
    "DNS Infrastructure",
    "TLS/Certificate Posture",
    "HTTP Surface",
    "Discovered Subdomains",
    "Crawl Surface",
    "Technology Stack",
    "Open Ports",
]

SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3}


def build_report(target: dict, module_results: list, options: dict = None) -> dict:
    all_observations = [f for r in module_results for f in r["findings"]]
    all_observations.sort(key=lambda f: SEVERITY_ORDER.get(f["severity"], 4))

    counts = {"high": 0, "medium": 0, "low": 0, "info": 0}
    for f in all_observations:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1

    grouped = {cat: [] for cat in CATEGORY_ORDER}
    for f in all_observations:
        grouped.setdefault(f.get("category", "Observations"), []).append(f)

    modules_by_name = {r["module"]: r for r in module_results}

    return {
        "scan_id": str(uuid.uuid4()),
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "target": target,
        "options": options or {},
        "observation_counts": counts,
        "observations_by_category": grouped,
        "modules": module_results,
        "modules_by_name": modules_by_name,
    }
