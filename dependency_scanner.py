"""
Autonomous Dependency Scanner
Audits requirements.txt across governed repositories against PyPI and OSV.dev
to detect outdated packages and active CVEs.
Governing Authority: Governing Officer Tarwater
"""

import os
import re
import base64
import logging
import requests

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)

GITHUB_API_URL = "https://api.github.com"
PYPI_API_URL = "https://pypi.org/pypi"
OSV_API_URL = "https://api.osv.dev/v1/query"

REQ_LINE_PATTERN = re.compile(r"^([a-zA-Z0-9_\-\.]+)\s*(?:==|>=|<=|~=|!=|>|<)?\s*([a-zA-Z0-9_\-\.\*]+)?")


def get_github_headers() -> dict:
    token = os.getenv("GH_PAT") or os.getenv("GITHUB_TOKEN")
    if not token:
        raise EnvironmentError("Missing GH_PAT or GITHUB_TOKEN environment variable.")
    return {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28"
    }


def fetch_requirements_file(owner: str, repo: str) -> tuple[str | None, str | None]:
    """Fetches raw requirements.txt content and blob SHA from the target repository."""
    headers = get_github_headers()
    url = f"{GITHUB_API_URL}/repos/{owner}/{repo}/contents/requirements.txt"
    resp = requests.get(url, headers=headers, timeout=15)

    if resp.status_code != 200:
        logging.info(f"No requirements.txt found in {owner}/{repo}.")
        return None, None

    data = resp.json()
    raw_text = base64.b64decode(data.get("content", "")).decode("utf-8", errors="ignore")
    return raw_text, data.get("sha")


def get_latest_pypi_version(package_name: str) -> str | None:
    """Queries PyPI JSON API for the latest stable release of a package."""
    try:
        resp = requests.get(f"{PYPI_API_URL}/{package_name}/json", timeout=10)
        if resp.status_code == 200:
            return resp.json().get("info", {}).get("version")
    except requests.RequestException as e:
        logging.warning(f"PyPI lookup failed for {package_name}: {e}")
    return None


def check_osv_vulnerabilities(package_name: str, version: str | None) -> list[str]:
    """Queries Google's OSV.dev API for known vulnerabilities affecting the package."""
    payload = {"package": {"name": package_name, "ecosystem": "PyPI"}}
    if version and "*" not in version:
        payload["version"] = version

    try:
        resp = requests.post(OSV_API_URL, json=payload, timeout=10)
        if resp.status_code == 200:
            vulns = resp.json().get("vulns", [])
            return [v.get("id", "UNKNOWN-CVE") for v in vulns]
    except requests.RequestException as e:
        logging.warning(f"OSV lookup failed for {package_name}: {e}")
    return []


def audit_repository_dependencies(target_repo: str) -> dict:
    """
    Audits all Python packages in a target repository.
    Returns a report with outdated packages, CVE alerts, and proposed requirements.txt content.
    """
    owner, repo = target_repo.split("/", 1)
    raw_reqs, file_sha = fetch_requirements_file(owner, repo)

    if not raw_reqs:
        return {"has_updates": False}

    updated_lines = []
    upgrades = []
    cve_alerts = []

    for line in raw_reqs.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            updated_lines.append(line)
            continue

        match = REQ_LINE_PATTERN.match(stripped)
        if not match:
            updated_lines.append(line)
            continue

        pkg_name, current_ver = match.group(1), match.group(2)
        latest_ver = get_latest_pypi_version(pkg_name)
        vulns = check_osv_vulnerabilities(pkg_name, current_ver)

        if vulns:
            cve_alerts.append(f"{pkg_name} ({current_ver or 'unpinned'}): {', '.join(vulns)}")

        if latest_ver and current_ver != latest_ver:
            upgrades.append({
                "package": pkg_name,
                "from": current_ver or "unpinned",
                "to": latest_ver,
                "cves": vulns
            })
            updated_lines.append(f"{pkg_name}>={latest_ver}")
        else:
            updated_lines.append(line)

    return {
        "has_updates": len(upgrades) > 0,
        "file_sha": file_sha,
        "upgrades": upgrades,
        "cve_alerts": cve_alerts,
        "updated_content": "\n".join(updated_lines) + "\n"
    }
