"""
Autonomous Dependency Upgrade Dispatcher
Patrols the entire governed repository fleet, verifies constitutional clearance,
and opens automated dependency/CVE upgrade PRs.
Governing Authority: Governing Officer Tarwater
"""

import os
import yaml
import base64
import logging
import argparse
import requests
from datetime import datetime, timezone
from dependency_scanner import audit_repository_dependencies, get_github_headers

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)

GITHUB_API_URL = "https://api.github.com"
CORE_REPO = "Pat333-ux/autonomous-governance-core"

DEFAULT_FLEET = [
    "Pat333-ux/autonomous-governance-core",
    "Pat333-ux/autonomous-agent-swarm",
    "Pat333-ux/autonomous-sandbox-runner",
    "Pat333-ux/autonomous-memory-vault",
    "Pat333-ux/autonomous-command-center",
    "Pat333-ux/autonomous-dependency-warden"
]


def verify_command_clearance() -> dict:
    """Fetches live policy from core and halts immediately if kill switch is active."""
    headers = get_github_headers()
    url = f"{GITHUB_API_URL}/repos/{CORE_REPO}/contents/governance_config.yaml"
    resp = requests.get(url, headers=headers, timeout=15)

    if resp.status_code == 200:
        raw_yaml = base64.b64decode(resp.json().get("content", "")).decode("utf-8")
        policy = yaml.safe_load(raw_yaml)
    else:
        with open("governance_config.yaml", "r", encoding="utf-8") as f:
            policy = yaml.safe_load(f)

    override_cfg = policy.get("communication_and_oversight", {}).get("emergency_override", {})
    env_kill = os.getenv("TARWATER_KILL_SWITCH", "false").lower() == "true"

    if override_cfg.get("global_kill_switch") or env_kill:
        logging.critical("EMERGENCY OVERRIDE ACTIVE: Dependency Warden halted by Governing Officer Tarwater.")
        raise SystemExit(1)

    return policy


def open_dependency_upgrade_pr(target_repo: str, audit_result: dict, policy: dict) -> None:
    """Creates a branch, commits updated requirements.txt, and opens an upgrade PR."""
    headers = get_github_headers()
    owner, repo = target_repo.split("/", 1)
    base_branch = "main"

    ref_resp = requests.get(f"{GITHUB_API_URL}/repos/{owner}/{repo}/git/ref/heads/{base_branch}", headers=headers, timeout=15)
    if ref_resp.status_code != 200:
        base_branch = "master"
        ref_resp = requests.get(f"{GITHUB_API_URL}/repos/{owner}/{repo}/git/ref/heads/{base_branch}", headers=headers, timeout=15)
    if ref_resp.status_code != 200:
        logging.error(f"Could not resolve default branch for {target_repo}")
        return

    base_sha = ref_resp.json()["object"]["sha"]
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    branch_name = f"auto-deps/supply-chain-upgrade-{timestamp}"

    # Create branch
    branch_payload = {"ref": f"refs/heads/{branch_name}", "sha": base_sha}
    requests.post(f"{GITHUB_API_URL}/repos/{owner}/{repo}/git/refs", headers=headers, json=branch_payload, timeout=15).raise_for_status()

    # Commit updated requirements.txt
    commit_payload = {
        "message": "[DEPS-WARDEN] Automated supply-chain & CVE dependency upgrade",
        "content": base64.b64encode(audit_result["updated_content"].encode("utf-8")).decode("utf-8"),
        "sha": audit_result["file_sha"],
        "branch": branch_name
    }
    requests.put(
        f"{GITHUB_API_URL}/repos/{owner}/{repo}/contents/requirements.txt",
        headers=headers,
        json=commit_payload,
        timeout=30
    ).raise_for_status()

    # Build PR summary
    approver = policy.get("operational_mandate", {}).get("require_final_approval_from", "Tarwater")
    upgrade_lines = []
    for u in audit_result["upgrades"]:
        cve_tag = f" **[SECURITY FIX: {', '.join(u['cves'])}]**" if u["cves"] else ""
        upgrade_lines.append(f"- `{u['package']}`: `{u['from']}` -> `{u['to']}`{cve_tag}")

    pr_title = (
        f"[SECURITY-DEPS] CVE Patch & Dependency Upgrade ({len(audit_result['upgrades'])} packages)"
        if audit_result["cve_alerts"]
        else f"[DEPS-WARDEN] Automated Dependency Upgrade ({len(audit_result['upgrades'])} packages)"
    )

    pr_body = (
        f"### 📦 Autonomous Dependency Warden Report\n\n"
        f"The Supply-Chain Warden audited `{target_repo}` and prepared the following updates:\n\n"
        + "\n".join(upgrade_lines) +
        f"\n\n- **Sandbox Verification:** Routed through CI/Sandbox quarantine prior to merge.\n"
        f"- **Executive Sign-Off Required:** Governing Officer {approver}\n\n"
        f"*Generated automatically by `autonomous-dependency-warden`.*"
    )

    pr_payload = {
        "title": pr_title,
        "head": branch_name,
        "base": base_branch,
        "body": pr_body
    }
    pr_resp = requests.post(f"{GITHUB_API_URL}/repos/{owner}/{repo}/pulls", headers=headers, json=pr_payload, timeout=30)
    if pr_resp.status_code == 201:
        logging.info(f"Opened Dependency Upgrade PR on {target_repo}: {pr_resp.json().get('html_url')}")
    else:
        logging.error(f"Failed to open PR on {target_repo}: {pr_resp.text}")


def patrol_fleet(targets: list[str]) -> None:
    """Audits every repository in the target list and dispatches upgrade PRs where needed."""
    policy = verify_command_clearance()

    for repo in targets:
        logging.info(f"Patrolling supply chain for: {repo}")
        result = audit_repository_dependencies(repo)
        if result.get("has_updates"):
            logging.info(f"Found {len(result['upgrades'])} package upgrades for {repo}.")
            open_dependency_upgrade_pr(repo, result, policy)
        else:
            logging.info(f"{repo} dependencies are fully up to date.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Autonomous Dependency Warden")
    parser.add_argument(
        "--target",
        default="all",
        help="Specific owner/repo to audit, or 'all' to patrol the entire fleet"
    )
    args = parser.parse_args()

    fleet = DEFAULT_FLEET if args.target == "all" else [args.target]
    patrol_fleet(fleet)
