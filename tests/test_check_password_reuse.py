from ad_kit.commands import check


def test_check_all_reuses_smb_password_for_asreproast(monkeypatch):
    asreproast_passwords = []

    monkeypatch.setattr(check, "run_ldap_checks", lambda: None)
    monkeypatch.setattr(
        check,
        "run_smb_checks",
        lambda std_pass=None: "smb-password",
    )

    def fake_asreproast(std_pass=None):
        asreproast_passwords.append(std_pass)
        return std_pass

    monkeypatch.setattr(check, "run_asreproast_checks", fake_asreproast)

    authenticated_checks = (
        "run_local_admin_checks",
        "run_password_policy_checks",
        "run_password_not_required_checks",
        "run_password_never_expires_checks",
        "run_maq_checks",
        "run_dns_checks",
        "run_pre2k_checks",
        "run_nopac_checks",
        "run_scriptpath_checks",
        "run_privileged_group_checks",
        "run_delegation_checks",
        "run_kerberoast_checks",
        "run_adcs_checks",
        "run_ldap_info_checks",
        "run_tombstone_checks",
        "run_coercion_checks",
    )
    for name in authenticated_checks:
        monkeypatch.setattr(check, name, lambda *_args: None)

    check.run_checks()

    assert asreproast_passwords == ["smb-password"]


def test_selected_smb_and_asreproast_reuse_password(monkeypatch):
    asreproast_passwords = []

    monkeypatch.setattr(
        check,
        "run_smb_checks",
        lambda std_pass=None: "smb-password",
    )

    def fake_asreproast(std_pass=None):
        asreproast_passwords.append(std_pass)
        return std_pass

    monkeypatch.setattr(check, "run_asreproast_checks", fake_asreproast)

    check.run_selected_checks(["smb", "asreproast"])

    assert asreproast_passwords == ["smb-password"]
