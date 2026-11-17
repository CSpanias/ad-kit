import json

from ad_kit.core.finding import Finding
from ad_kit.reporting import json as json_report


def test_collect_and_write_mapped_findings(tmp_path):
    json_report.reset()

    json_report.collect(
        [
            Finding(
                id="SMB-001",
                title="SMB Signing Not Enforced",
                commentary="",
                remediation="",
            ),
            Finding(
                id="LDAPINFO-001",
                title="Sensitive Information Stored in LDAP Attributes",
                commentary="",
                remediation="",
            ),
        ]
    )

    output = tmp_path / "findings.json"
    json_report.write_findings(output)

    data = json.loads(output.read_text(encoding="utf-8"))

    assert data == {
        "findings": [
            {
                "id": "smb-signing-not-enforced",
                "description": (
                    "SMB signing is not enforced on one or more hosts, "
                    "permitting SMB relay attacks."
                ),
            }
        ]
    }