from ad_kit.checks import nopac


def test_nopac_check_compares_ticket_sizes_and_finds_vulnerable_dc(monkeypatch):
    outputs = iter(
        [
            "NOPAC TGT with PAC size 1800\n"
            "NOPAC TGT without PAC size 1700\nNOPAC VULNERABLE",
            "NOPAC TGT with PAC size 1800\n"
            "NOPAC TGT without PAC size 1800",
            "NOPAC could not obtain a TGT",
        ]
    )
    commands = []

    def fake_run_check(name, command, sensitive_values, *, kerberos_dc):
        commands.append((name, command, sensitive_values))
        assert kerberos_dc in {"192.0.2.1", "192.0.2.2", "192.0.2.3"}
        return next(outputs)

    monkeypatch.setattr(nopac, "run_check", fake_run_check)

    results, findings = nopac.nopac_check(
        ["192.0.2.1", "192.0.2.2", "192.0.2.3"],
        "poppy",
        "Password123!",
    )

    assert [result["status"] for result in results] == [
        "Vulnerable",
        "Not vulnerable",
        "Unable to assess",
    ]
    assert [finding.id for finding in findings] == ["NOPAC-001"]
    assert findings[0].affected_assets == ["192.0.2.1"]
    assert commands[0][1] == [
        "nxc",
        "smb",
        "192.0.2.1",
        "-u",
        "poppy",
        "-p",
        "Password123!",
        "-M",
        "nopac",
    ]
    assert commands[0][2] == ["Password123!"]
