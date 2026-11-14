from ad_kit.checks import adcs


def test_adcs_check_only_counts_vulnerabilities_and_deduplicates(monkeypatch):
    output = """Certificate Authorities
  0
    CA Name : MOLLYSEC-ROOT-CA
    [!] Vulnerabilities
      ESC8 : Web enrollment is enabled.
    [*] Remarks
      ESC8 : this is only a remark.
Certificate Templates
  0
    Template Name : ESC1
    [*] Remarks
      ESC1 : the template name alone is not a vulnerability.
  1
    Template Name : VulnerableTemplate
    [!] Vulnerabilities
      ESC1 : Enrollee supplies subject and template allows client authentication.
      ESC1 : repeated ESC1 detail.
      ESC15 : Version 1 template accepts application policies.
      ESC17 : Enrollee supplies subject and template allows server authentication.
    [*] Remarks
      ESC1 : a remark is not a vulnerability.
"""
    loaded_findings = []

    monkeypatch.setattr(adcs, "run_check", lambda *_args: output)

    def fake_load_finding(category, finding_id):
        assert category == "adcs"
        loaded_findings.append(finding_id)
        return adcs.Finding(
            id=finding_id,
            title=finding_id,
            commentary="",
            remediation="",
        )

    monkeypatch.setattr(adcs, "load_finding", fake_load_finding)

    results, findings = adcs.adcs_check(
        "192.0.2.1",
        "example.test",
        "user",
        "password",
    )

    assert results["ESC1"] == ["VulnerableTemplate"]
    assert results["ESC8"] == ["MOLLYSEC-ROOT-CA"]
    assert results["ESC15"] == ["VulnerableTemplate"]
    assert results["ESC17"] == ["VulnerableTemplate"]
    assert [finding.id for finding in findings] == [
        "ADCS-ESC1",
        "ADCS-ESC8",
        "ADCS-ESC15",
    ]
    assert loaded_findings == ["ADCS-ESC1", "ADCS-ESC8", "ADCS-ESC15"]
