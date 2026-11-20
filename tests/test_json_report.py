import json

from ad_kit.core.finding import Finding
from ad_kit.reporting import json as json_report


def test_collect_and_write_all_findings_with_yaml_ids(tmp_path):
    json_report.reset()

    json_report.collect(
        [
            Finding(
                id="SMB-001",
                title="SMB Signing Not Enforced",
                commentary="SMB signing details.",
                remediation="",
            ),
            Finding(
                id="LDAPINFO-001",
                title="Sensitive Information Stored in LDAP Attributes",
                commentary="LDAP information\n details.\n\nAnother paragraph.",
                remediation="",
            ),
        ]
    )

    output = tmp_path / "ad-kit_findings.json"
    json_report.write_findings(output)

    data = json.loads(output.read_text(encoding="utf-8"))

    assert data == {
        "findings": [
            {
                "id": "LDAPINFO-001",
                "description": "LDAP information details.\n\nAnother paragraph.",
            },
            {"id": "SMB-001", "description": "SMB signing details."},
        ]
    }