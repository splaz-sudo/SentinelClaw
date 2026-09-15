from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import TextIO


logger = logging.getLogger(
    __name__
)

PRIVATE_DIRECTORY_MODE = 0o700
PRIVATE_FILE_MODE = 0o600


def ensure_private_directory(
    path: Path,
) -> Path:
    """Create ``path`` (and parents) with owner-only permissions.

    Only a directory actually created by this call is chmod-ed to
    ``0o700``; an existing directory is left untouched. ``chmod``
    failures (common on Windows) are logged at debug level and never
    raised, so a scan is never aborted over permissions hardening.
    """
    if path.is_dir():
        return path

    try:
        path.mkdir(
            parents=True,
            mode=PRIVATE_DIRECTORY_MODE,
        )
    except FileExistsError:
        if path.is_dir():
            return path
        raise

    try:
        os.chmod(
            path,
            PRIVATE_DIRECTORY_MODE,
        )
    except OSError as exc:
        logger.debug(
            "Unable to restrict permissions on directory %s: %s",
            path,
            exc,
        )

    return path


def open_private_append(
    path: Path,
) -> TextIO:
    """Open ``path`` for text appending, creating it owner-only (0o600)."""
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_APPEND | os.O_CREAT,
        PRIVATE_FILE_MODE,
    )

    try:
        return os.fdopen(
            descriptor,
            "a",
            encoding="utf-8",
        )
    except BaseException:
        os.close(
            descriptor
        )
        raise


def write_private_text(
    path: Path,
    text: str,
) -> None:
    """Write ``text`` to ``path``, creating it owner-only (0o600).

    An existing file keeps its current permissions; the mode applies
    only when the file is first created.
    """
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_TRUNC,
        PRIVATE_FILE_MODE,
    )

    try:
        file = os.fdopen(
            descriptor,
            "w",
            encoding="utf-8",
        )
    except BaseException:
        os.close(
            descriptor
        )
        raise

    with file:
        file.write(
            text
        )


PACKAGE_DIRECTORY = Path(__file__).resolve().parent.parent
PROJECT_DIRECTORY = PACKAGE_DIRECTORY.parent


def get_rules_directory() -> Path:
    """
    Return SentinelClaw's detection-rule directory.

    SENTINELCLAW_RULES_DIR can override the default location.

    Rules are stored inside the installed Python package so they
    remain available in editable installs, wheel installs, and
    normal site-packages installations.
    """
    override = os.environ.get("SENTINELCLAW_RULES_DIR")

    if override:
        return Path(override).expanduser().resolve()

    return PACKAGE_DIRECTORY / "rules"


def get_yara_rules_directory() -> Path:
    """
    Return SentinelClaw's optional YARA rules directory.

    SENTINELCLAW_YARA_RULES_DIR can override the default location.

    Unlike the detection rules above, YARA rules live only inside the
    package (``sentinelclaw/rules/yara/``); they are not part of the
    twin-copy sync used for the YAML rule trees.
    """
    override = os.environ.get("SENTINELCLAW_YARA_RULES_DIR")

    if override:
        return Path(override).expanduser().resolve()

    return PACKAGE_DIRECTORY / "rules" / "yara"


def get_report_directory() -> Path:
    """
    Return the directory used for generated reports.

    SENTINELCLAW_REPORT_DIR can override the default location.

    Reports are written to a user-writable directory rather than
    inside the installed Python package.
    """
    override = os.environ.get("SENTINELCLAW_REPORT_DIR")

    if override:
        return Path(override).expanduser().resolve()

    return Path.cwd() / "reports"


def get_data_directory() -> Path:
    """
    Return SentinelClaw's data directory.

    SENTINELCLAW_DATA_DIR can override the default location.
    """
    override = os.environ.get("SENTINELCLAW_DATA_DIR")

    if override:
        return Path(override).expanduser().resolve()

    return Path.cwd() / "data"
