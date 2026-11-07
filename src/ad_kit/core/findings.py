"""
Finding definition loader.

This module provides functionality for loading finding definitions from YAML 
files and converting them into Finding objects.

Finding content is maintained separately from detection logic to improve 
maintainability, simplify report updates, and allow reporting content to be 
modified without changing assessment code.

Finding definitions are organised by category within the 'findings' directory. 
Each YAML file contains one or more finding definitions identified by a unique
finding identifier (e.g. LDAP-001, SMB-001).
"""

from pathlib import Path

import yaml

from ad_kit.core.finding import Finding


def load_finding(
    category: str,
    finding_id: str,
) -> Finding:
    """
    Load a finding definition from a YAML file.

    Args:
        category:
            Finding category name (e.g. ldap, smb,
            passwords).

        finding_id:
            Unique finding identifier
            (e.g. LDAP-001, SMB-001).

    Returns:
        A populated Finding instance.

    Raises:
        RuntimeError:
            If the findings file cannot be located or
            the specified finding definition does not
            exist.
    """

    findings_file = (
        Path(__file__).parent.parent
        / "findings"
        / f"{category}.yaml"
    )

    if not findings_file.exists():
        raise RuntimeError(f"Finding category '{category}' not found.")

    data = (yaml.safe_load(findings_file.read_text(encoding="utf-8",)) or {})

    finding = data.get(finding_id)

    if finding is None:
        raise RuntimeError(
            f"Finding '{finding_id}' not found."
        )

    return Finding(
        id=finding["id"],
        title=finding["title"],
        commentary=finding["commentary"],
        remediation=finding["remediation"],
        references=finding.get("references") or [],
    )