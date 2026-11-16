from ad_kit.checks import privileged_excessive
from ad_kit.core.privileged import PRIVILEGED_GROUPS


def test_admin_count_uses_its_own_threshold(monkeypatch, tmp_path):
    monkeypatch.setattr(
        privileged_excessive,
        "require_session",
        lambda: {"domain_users_filtered_count": 100},
    )
    monkeypatch.setattr(
        privileged_excessive,
        "get_artefacts_dir",
        lambda: tmp_path,
    )
    monkeypatch.setattr(
        privileged_excessive,
        "get_privileged_group_members",
        lambda *_args: {group: [] for group in PRIVILEGED_GROUPS},
    )
    output = "\n".join(
        f"LDAP 192.0.2.1 389 DC01 account-{index}"
        for index in range(25)
    )

    def fake_run_check(name, command, sensitive_values):
        assert name == "privileged-admin-count"
        assert command[-1] == "--admin-count"
        assert sensitive_values == ["password"]
        return output

    monkeypatch.setattr(privileged_excessive, "run_check", fake_run_check)

    results, findings = privileged_excessive.privileged_excessive_check(
        "192.0.2.1",
        "user",
        "password",
    )

    assert results["admin_count"] == {
        "member_count": 25,
        "percentage": 25.0,
        "members": sorted(f"account-{index}" for index in range(25)),
    }
    assert [finding.id for finding in findings] == ["PRIV-002"]


def test_admin_count_below_threshold_does_not_create_finding(
    monkeypatch,
    tmp_path,
):
    monkeypatch.setattr(
        privileged_excessive,
        "require_session",
        lambda: {"domain_users_filtered_count": 100},
    )
    monkeypatch.setattr(
        privileged_excessive,
        "get_artefacts_dir",
        lambda: tmp_path,
    )
    monkeypatch.setattr(
        privileged_excessive,
        "get_privileged_group_members",
        lambda *_args: {group: [] for group in PRIVILEGED_GROUPS},
    )
    monkeypatch.setattr(
        privileged_excessive,
        "run_check",
        lambda *_args, **_kwargs: "\n".join(
            f"LDAP 192.0.2.1 389 DC01 account-{index}"
            for index in range(24)
        ),
    )

    results, findings = privileged_excessive.privileged_excessive_check(
        "192.0.2.1",
        "user",
        "password",
    )

    assert results["admin_count"]["percentage"] == 24.0
    assert findings == []
