import json

from pathlib import Path

ARTEFACTS_DIR = Path("ad-kit")


def get_artefacts_dir() -> Path:
    """
    Return the AD-Kit artefacts directory.
    """

    ARTEFACTS_DIR.mkdir(exist_ok=True,)

    return ARTEFACTS_DIR


def get_session_file() -> Path:
    """
    Return the AD-Kit session file.
    """

    return (
        get_artefacts_dir()
        / "session.json"
    )


def load_session() -> dict:
    session_file = get_session_file()

    if not session_file.exists():
        raise RuntimeError("Session metadata not found.")

    return json.loads(session_file.read_text(encoding="utf-8"))