from ad_kit.core.exceptions import CheckExecutionError, InstallationError


def test_installation_error_includes_tool_and_reason():
    error = InstallationError("certipy", "download failed")

    assert str(error) == "Failed to install 'certipy': download failed"
    assert error.tool_name == "certipy"
    assert error.reason == "download failed"


def test_check_execution_error_uses_stderr_detail():
    error = CheckExecutionError(
        "password-never-expires",
        ["nxc", "ldap", "dc", "--password-never-expires"],
        returncode=2,
        stderr="nxc: error: unrecognized arguments: --password-never-expires",
    )

    assert error.name == "password-never-expires"
    assert error.returncode == 2
    assert "password-never-expires" in str(error)
    assert "unrecognized arguments: --password-never-expires" in str(error)


def test_check_execution_error_without_stderr_uses_returncode():
    error = CheckExecutionError("maq", ["nxc", "ldap", "dc"], returncode=1)

    assert "exit code 1" in str(error)
