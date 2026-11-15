from ad_kit.core.exceptions import InstallationError


def test_installation_error_includes_tool_and_reason():
    error = InstallationError("certipy", "download failed")

    assert str(error) == "Failed to install 'certipy': download failed"
    assert error.tool_name == "certipy"
    assert error.reason == "download failed"
