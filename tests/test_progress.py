import pytest

from ad_kit.checks import coercion, ldap_info, nopac
from ad_kit.core import util
from ad_kit.core.exceptions import CheckExecutionError


class FakeProgress:
    instances = []

    def __init__(self, *columns, **kwargs):
        self.total = None
        self.completed = 0
        self.closed = False
        self.instances.append(self)

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.closed = True

    def add_task(self, description, total):
        self.total = total
        return 0

    def advance(self, task):
        self.completed += 1


def test_progress_tracks_completed_items_and_cleans_up(monkeypatch):
    FakeProgress.instances.clear()
    monkeypatch.setattr(util, "Progress", FakeProgress)

    items = util.track_items(["a", "b"], "Targets")
    assert next(items) == "a"
    tracker = FakeProgress.instances[-1]
    assert (tracker.completed, tracker.total) == (0, 2)
    assert next(items) == "b"
    assert tracker.completed == 1
    assert list(items) == []
    assert tracker.completed == 2
    assert tracker.closed


def test_progress_does_not_mark_interrupted_item_complete(monkeypatch):
    FakeProgress.instances.clear()
    monkeypatch.setattr(util, "Progress", FakeProgress)

    items = util.track_items(["a", "b"], "Targets")
    assert next(items) == "a"
    tracker = FakeProgress.instances[-1]
    items.close()
    assert tracker.completed == 0
    assert tracker.closed


def test_progress_skips_empty_sequences(monkeypatch):
    FakeProgress.instances.clear()
    monkeypatch.setattr(util, "Progress", FakeProgress)

    assert list(util.track_items([], "Targets")) == []
    assert not FakeProgress.instances


def test_failed_target_is_counted_as_processed(monkeypatch):
    FakeProgress.instances.clear()
    monkeypatch.setattr(util, "Progress", FakeProgress)
    monkeypatch.setattr(nopac, "record_incomplete", lambda *args: None)

    def run_check(name, command, sensitive_values):
        if command[2] == "dc1":
            raise CheckExecutionError(name, command, returncode=1)
        return "TGT with PAC size 1800\nTGT without PAC size 1800"

    monkeypatch.setattr(nopac, "run_check", run_check)
    results, _ = nopac.nopac_check(["dc1", "dc2"], "user", "password")

    assert [result["status"] for result in results] == ["Unable to assess", "Not vulnerable"]
    tracker = FakeProgress.instances[-1]
    assert (tracker.completed, tracker.total) == (2, 2)


@pytest.mark.parametrize(
    ("module", "names", "modules"),
    [
        (
            ldap_info,
            ["ldap-desc-users", "ldap-info-users", "ldap-user-password", "ldap-unix-password"],
            ["get-desc-users", "get-info-users", "get-userPassword", "get-unixUserPassword"],
        ),
        (
            coercion,
            ["coercion-spooler", "coercion-plus", "coercion-webdav"],
            ["spooler", "coerce_plus", "webdav"],
        ),
    ],
)
def test_query_batches_track_each_command(monkeypatch, tmp_path, module, names, modules):
    FakeProgress.instances.clear()
    monkeypatch.setattr(util, "Progress", FakeProgress)
    calls = []
    monkeypatch.setattr(
        module, "run_check", lambda name, command: calls.append((name, command)) or ""
    )
    if module is coercion:
        monkeypatch.setattr(coercion, "load_dc_hostnames", lambda: [])
        monkeypatch.setattr(coercion, "get_artefacts_dir", lambda: tmp_path)
        coercion.coercion_check("user", "password")
    else:
        ldap_info.ldap_info_check("dc", "user", "password")

    assert [name for name, _ in calls] == names
    assert [command[-1] for _, command in calls] == modules
    tracker = FakeProgress.instances[-1]
    assert (tracker.completed, tracker.total) == (len(names), len(names))
