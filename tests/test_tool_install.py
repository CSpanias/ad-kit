import subprocess
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from typer.testing import CliRunner

from ad_kit import cli
from ad_kit.commands.tools import install as install_commands
from ad_kit.core.exceptions import InstallationError
from ad_kit.installers import github, uv
from ad_kit.models import Tool


def release_tool():
    return Tool(
        name="kerbrute",
        installer="github_release",
        description="Kerberos enumeration",
        repo="CSpanias/kerbrute",
        asset_pattern="linux_amd64",
        binary_name="kerbrute",
        check_command="kerbrute",
    )


@pytest.mark.parametrize("tool", ["kerbrute", "all"])
def test_install_cli_forwards_force(monkeypatch, tool):
    install = Mock()
    monkeypatch.setattr(cli, "install_tool", install)

    result = CliRunner().invoke(cli.app, ["tools", "install", tool, "--force"])

    assert result.exit_code == 0
    install.assert_called_once_with(tool, force=True)


def test_install_all_passes_force_to_each_installer(monkeypatch):
    tool = release_tool()
    installer = Mock()
    monkeypatch.setattr(
        install_commands, "ToolRegistry", lambda: SimpleNamespace(get_all_tools=lambda: [tool])
    )
    monkeypatch.setattr(install_commands, "get_installer", lambda _: installer)

    install_commands.install_tool("all", force=True)

    installer.install.assert_called_once_with(tool, force=True)


def test_unknown_tool_returns_nonzero_and_lists_available_tools():
    result = CliRunner().invoke(cli.app, ["tools", "install", "not-a-tool"])
    assert result.exit_code != 0
    assert "Unknown tool: not-a-tool" in result.output
    assert "Available tools:" in result.output


@pytest.mark.parametrize("tool", ["kerbrute", "all"])
def test_failed_install_returns_nonzero(monkeypatch, tool):
    monkeypatch.setattr(
        install_commands, "get_installer",
        lambda _: SimpleNamespace(install=Mock(side_effect=InstallationError(tool, "failed"))),
    )
    result = CliRunner().invoke(cli.app, ["tools", "install", tool])
    assert result.exit_code != 0
    assert "failed" in result.output.lower()


def test_cli_version_uses_package_metadata():
    from importlib.metadata import version

    result = CliRunner().invoke(cli.app, ["--version"])
    assert result.exit_code == 0
    assert result.output.strip() == f"ad-kit {version('ad-kit')}"


def test_cli_returns_nonzero_when_enumeration_fails(monkeypatch):
    monkeypatch.setattr(cli, "run_enumeration", lambda: False)
    result = CliRunner().invoke(cli.app, ["enum"])
    assert result.exit_code != 0


def test_github_reinstall_replaces_only_managed_path_and_reports_shadowing(
    monkeypatch, tmp_path
):
    managed = tmp_path / "bin"
    managed.mkdir()
    external = tmp_path / "external"
    external.write_bytes(b"old")
    destination = managed / "kerbrute"
    destination.symlink_to(external)
    monkeypatch.setattr(github, "INSTALL_DIR", managed)
    monkeypatch.setattr(github, "which", lambda _: str(external))
    warnings = Mock()
    monkeypatch.setattr(github, "print_warning", warnings)

    installer = github.GitHubReleaseInstaller()
    release = Mock(return_value={
        "assets": [{"name": "kerbrute_linux_amd64", "browser_download_url": "https://example.test"}]
    })
    monkeypatch.setattr(installer, "_get_latest_release", release)

    def download(command, *, check):
        assert check
        Path(command[3]).write_bytes(b"new")

    monkeypatch.setattr(github.subprocess, "run", download)

    installer.install(release_tool())
    release.assert_not_called()
    assert destination.is_symlink()

    installer.install(release_tool(), force=True)
    release.assert_called_once_with("CSpanias/kerbrute")
    assert destination.read_bytes() == b"new"
    assert not destination.is_symlink()
    assert external.read_bytes() == b"old"
    assert str(external) in warnings.call_args.args[0]


def test_github_failed_forced_download_preserves_existing_binary(monkeypatch, tmp_path):
    destination = tmp_path / "kerbrute"
    destination.write_bytes(b"old")
    monkeypatch.setattr(github, "INSTALL_DIR", tmp_path)
    monkeypatch.setattr(github, "which", lambda _: str(destination))
    installer = github.GitHubReleaseInstaller()
    monkeypatch.setattr(installer, "_get_latest_release", lambda _: {
        "assets": [{"name": "kerbrute_linux_amd64", "browser_download_url": "https://example.test"}]
    })
    monkeypatch.setattr(
        github.subprocess, "run", Mock(side_effect=subprocess.CalledProcessError(1, "wget"))
    )

    with pytest.raises(InstallationError):
        installer.install(release_tool(), force=True)

    assert destination.read_bytes() == b"old"


@pytest.mark.parametrize("data", [
    None,
    {},
    {"assets": None},
    {"assets": ["invalid"]},
    {"assets": [{"name": "kerbrute_linux_amd64"}]},
    {"assets": [{"name": "", "browser_download_url": "https://example.test"}]},
    {"assets": [{"name": "kerbrute_linux_amd64", "browser_download_url": None}]},
])
def test_github_invalid_release_metadata_is_reported(monkeypatch, data):
    response = Mock()
    response.json.return_value = data
    monkeypatch.setattr(github.requests, "get", Mock(return_value=response))

    with pytest.raises(ValueError, match="GitHub release.*invalid"):
        github.GitHubReleaseInstaller()._get_latest_release("CSpanias/kerbrute")

    response.raise_for_status.assert_called_once()


def test_github_release_metadata_preserves_asset_details(monkeypatch):
    response = Mock()
    response.json.return_value = {
        "tag_name": "v1.0.4",
        "assets": [{
            "name": "kerbrute_linux_amd64",
            "browser_download_url": "https://example.test/kerbrute",
            "size": 123,
        }],
    }
    monkeypatch.setattr(github.requests, "get", Mock(return_value=response))

    release = github.GitHubReleaseInstaller()._get_latest_release("CSpanias/kerbrute")

    assert release == {"assets": [{
        "name": "kerbrute_linux_amd64",
        "browser_download_url": "https://example.test/kerbrute",
    }]}


def test_uv_missing_source_fails_before_running_command(monkeypatch):
    tool = Tool(name="example", installer="uv", description="Example")
    run = Mock()
    monkeypatch.setattr(uv.subprocess, "run", run)

    with pytest.raises(InstallationError, match="No installation source is configured"):
        uv.UVInstaller().install(tool)

    run.assert_not_called()
