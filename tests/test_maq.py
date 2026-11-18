from types import SimpleNamespace

from ad_kit.checks import maq


def _seed_secrets(monkeypatch):
    monkeypatch.setattr(
        maq,
        "secrets",
        SimpleNamespace(token_hex=lambda length: "A" * length),
    )


def test_maq_check_creates_and_deletes_machine_over_ldap(monkeypatch):
    outputs = {
        "maq": (
            "LDAP 10.0.0.27 389 ADTDC1 [*] Getting the MachineAccountQuota\n"
            "MAQ 10.0.0.27 389 ADTDC1 MachineAccountQuota: 10\n"
            'MAQ 10.0.0.27 389 ADTDC1 - "Authenticated Users" (S-1-5-11)\n'
        ),
        "maq-create-machine": (
            'ADD-COMP 10.0.0.27 389 ADTDC1 Successfully added "ADKIT-AAAA$" '
            'with password "AAAAAAAA"\n'
        ),
        "maq-auth-machine": (
            "SMB 10.0.0.27 445 ADTDC1 [+] assureddt.uk\\ADKIT-AAAA$:********\n"
        ),
        "maq-delete-machine": (
            'ADD-COMP 10.0.0.27 389 ADTDC1 Insufficient rights to delete '
            '"ADKIT-AAAA$"\n'
        ),
    }
    commands = []

    def fake_run_check(name, command, sensitive_values=None):
        commands.append((name, command))
        return outputs[name]

    monkeypatch.setattr(maq, "run_check", fake_run_check)
    _seed_secrets(monkeypatch)

    results = maq.maq_check(
        "10.0.0.27",
        "csacyber26",
        "pass",
    )

    assert results["machine_account_quota"] == "10"
    assert results["machine_join_group"] == "Authenticated Users"
    assert results["machine_created"] is True
    assert results["machine_authenticated"] is True
    assert results["machine_deleted"] is False
    assert results["cleanup_method"] == "Domain Admin Required"

    assert commands == [
        (
            "maq",
            [
                "nxc", "ldap", "10.0.0.27",
                "-u", "csacyber26",
                "-p", "pass",
                "-M", "maq",
            ],
        ),
        (
            "maq-create-machine",
            [
                "nxc", "ldap", "10.0.0.27",
                "-u", "csacyber26",
                "-p", "pass",
                "-M", "add-computer",
                "-o",
                "NAME=ADKIT-AAAA",
                "PASSWORD=AAAAAAAA",
            ],
        ),
        (
            "maq-auth-machine",
            [
                "nxc", "smb", "10.0.0.27",
                "-u", "ADKIT-AAAA$",
                "-p", "AAAAAAAA",
            ],
        ),
        (
            "maq-delete-machine",
            [
                "nxc", "ldap", "10.0.0.27",
                "-u", "csacyber26",
                "-p", "pass",
                "-M", "add-computer",
                "-o",
                "NAME=ADKIT-AAAA",
                "PASSWORD=AAAAAAAA",
                "DELETE=True",
            ],
        ),
    ]


def test_maq_check_reports_denied_when_creation_fails(monkeypatch):
    outputs = {
        "maq": (
            "LDAP 10.0.0.27 389 ADTDC1 [*] Getting the MachineAccountQuota\n"
            "MAQ 10.0.0.27 389 ADTDC1 MachineAccountQuota: 10\n"
        ),
        "maq-create-machine": (
            "ADD-COMP 10.0.0.27 389 ADTDC1 Unable to add the computer\n"
        ),
    }
    commands = []

    def fake_run_check(name, command, sensitive_values=None):
        commands.append((name, command))
        return outputs[name]

    monkeypatch.setattr(maq, "run_check", fake_run_check)
    _seed_secrets(monkeypatch)

    results = maq.maq_check(
        "10.0.0.27",
        "csacyber26",
        "pass",
    )

    assert results["machine_created"] is False
    assert results["machine_authenticated"] is False
    assert results["machine_deleted"] is False
    assert results["cleanup_method"] == "None"

    assert [name for name, _ in commands] == [
        "maq",
        "maq-create-machine",
    ]


def test_maq_check_cleanup_as_standard_user(monkeypatch):
    outputs = {
        "maq": "MAQ 10.0.0.27 389 ADTDC1 MachineAccountQuota: 10\n",
        "maq-create-machine": "Successfully added the machine account\n",
        "maq-auth-machine": "SMB 10.0.0.27 445 ADTDC1 [+] authenticated\n",
        "maq-delete-machine": (
            'Successfully deleted the "ADKIT-AAAA$" Computer account\n'
        ),
    }

    def fake_run_check(name, command, sensitive_values=None):
        return outputs[name]

    monkeypatch.setattr(maq, "run_check", fake_run_check)
    _seed_secrets(monkeypatch)

    results = maq.maq_check(
        "10.0.0.27",
        "csacyber26",
        "pass",
    )

    assert results["machine_created"] is True
    assert results["machine_deleted"] is True
    assert results["cleanup_method"] == "Standard User"