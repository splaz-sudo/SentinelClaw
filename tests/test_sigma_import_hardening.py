"""Regression tests for Sigma import hardening.

Covers the zip-slip / decompression-bomb / symlinked-refresh fixes in
``sentinelclaw.sigma.importer`` plus the per-rule ``RecursionError``
isolation, using only stdlib-built zips and ``tmp_path``.
"""

from __future__ import annotations

import logging
import os
import urllib.request
import zipfile
from pathlib import Path

import pytest

from sentinelclaw.sigma import importer
from sentinelclaw.sigma.importer import (
    SigmaImportError,
    convert_directory,
    download_release_zip,
    extract_rules_directory,
    import_into,
)

GOOD_RULE = """\
title: Good rule
id: 11111111-1111-1111-1111-111111111111
level: low
logsource:
    category: process_creation
    product: linux
detection:
    selection:
        Image: /usr/bin/evil
    condition: selection
"""


class _FakeResponse:
    """Minimal context-manager stand-in for a ``urlopen`` response."""

    def __init__(self, payload: bytes) -> None:
        self.payload = payload

    def read(self, size: int = -1) -> bytes:
        if size < 0:
            return self.payload

        return self.payload[:size]

    def __enter__(self) -> _FakeResponse:
        return self

    def __exit__(self, *exc_info: object) -> None:
        return None


def build_zip(
    zip_path: Path,
    members: dict[str, str | bytes],
) -> Path:
    with zipfile.ZipFile(zip_path, "w") as archive:
        for name, payload in members.items():
            archive.writestr(name, payload)

    return zip_path


def build_zip_with_raw_member_name(
    zip_path: Path,
    name: str,
    payload: str | bytes,
) -> Path:
    """Build a one-member zip whose stored name is exactly ``name``.

    ``ZipInfo.__init__`` rewrites ``os.sep`` to "/" (on Windows every
    backslash becomes a forward slash, both when writing and when reading
    a zip's central directory), so the raw name must be assigned *after*
    construction to pin the archive bytes on every platform. On read,
    ``ZipInfo.orig_filename`` always reflects those stored bytes.
    """
    with zipfile.ZipFile(zip_path, "w") as archive:
        info = zipfile.ZipInfo("placeholder.yml")
        info.filename = name
        archive.writestr(info, payload)

    return zip_path


def write_rules_tree(
    root: Path,
    rule_text: str = GOOD_RULE,
) -> Path:
    rules_dir = root / "rules" / "linux"
    rules_dir.mkdir(parents=True)
    (rules_dir / "good.yml").write_text(rule_text, encoding="utf-8")
    return root / "rules"


# ---------------------------------------------------------------------------
# Finding 1: zip-slip (traversal / absolute / backslash / drive letter)
# ---------------------------------------------------------------------------


def test_extract_rejects_traversal_entry(tmp_path: Path) -> None:
    archive_path = build_zip(
        tmp_path / "evil.zip",
        {
            "evil/rules/../../../../pwned.yml": GOOD_RULE,
            "sigma-x/rules/ok.yml": GOOD_RULE,
        },
    )

    work_directory = tmp_path / "a" / "b" / "c" / "work"

    with pytest.raises(SigmaImportError, match="pwned.yml"):
        extract_rules_directory(archive_path, work_directory)

    assert list(tmp_path.rglob("pwned.yml")) == []


def test_extract_rejects_absolute_entry(tmp_path: Path) -> None:
    archive_path = build_zip(
        tmp_path / "absolute.zip",
        {"/rules/absolute.yml": GOOD_RULE},
    )

    with pytest.raises(SigmaImportError, match="absolute"):
        extract_rules_directory(archive_path, tmp_path / "work")

    assert not (tmp_path / "work" / "rules" / "absolute.yml").exists()


def test_member_name_rejection_refuses_nul_byte() -> None:
    # zipfile truncates member names at NUL while parsing, so this guard
    # is pinned at the validator boundary instead of through a real zip.
    assert importer._member_name_rejection("sigma-x/rules/bad\x00.yml") == "NUL character"


def test_extract_rejects_drive_letter_entry(tmp_path: Path) -> None:
    archive_path = build_zip(
        tmp_path / "drive.zip",
        {"C:/rules/pwned.yml": GOOD_RULE},
    )

    with pytest.raises(SigmaImportError, match="drive-letter"):
        extract_rules_directory(archive_path, tmp_path / "work")


def test_extract_contains_raw_backslash_entry(tmp_path: Path) -> None:
    """A member stored with literal backslashes must never escape the root.

    The archive genuinely stores the backslash name on every platform
    (asserted via ``ZipInfo.orig_filename``). Windows' ``zipfile`` then
    re-sanitizes the name while reading the central directory, so there
    the validator sees forward slashes and containment is the guarantee
    that holds; POSIX keeps the raw name and the validator refuses it.
    """
    raw_name = "evil\\rules\\pwned.yml"

    archive_path = build_zip_with_raw_member_name(
        tmp_path / "backslash.zip",
        raw_name,
        GOOD_RULE,
    )

    with zipfile.ZipFile(archive_path) as archive:
        stored = archive.infolist()[0]

        # ``orig_filename`` is never sanitized: the raw stored name is
        # present on every platform.
        assert stored.orig_filename == raw_name

        if os.name == "nt":
            assert stored.filename == "evil/rules/pwned.yml"
        else:
            assert stored.filename == raw_name

    work_directory = tmp_path / "a" / "b" / "c" / "work"

    if os.name == "nt":
        # Windows' zipfile normalizes the separator before the validator
        # runs, so extraction is contained rather than refused.
        rules_root = extract_rules_directory(archive_path, work_directory)
        assert (rules_root / "pwned.yml").is_file()
    else:
        with pytest.raises(SigmaImportError, match="backslash"):
            extract_rules_directory(archive_path, work_directory)

    escaped = [
        path
        for path in tmp_path.rglob("pwned.yml")
        if not path.is_relative_to(work_directory)
    ]

    assert escaped == []


# ---------------------------------------------------------------------------
# Validator units: raw-name checks independent of zipfile's per-platform
# normalization (writer-side on Windows, and again while reading infolist())
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("name", "reason"),
    [
        ("evil/rules/../../../pwned.yml", "'..' traversal component"),
        ("/rules/absolute.yml", "absolute path"),
        ("\\rules\\absolute.yml", "absolute path"),
        ("\\\\server\\share\\rules\\x.yml", "absolute path"),
        ("evil\\rules\\pwned.yml", "backslash path separator"),
        ("C:\\rules\\pwned.yml", "backslash path separator"),
        ("C:/rules/pwned.yml", "Windows drive-letter component"),
        ("c:/rules/pwned.yml", "Windows drive-letter component"),
    ],
)
def test_member_name_rejection_refuses_raw_unsafe_names(
    name: str,
    reason: str,
) -> None:
    assert importer._member_name_rejection(name) == reason


def test_member_name_rejection_allows_normal_release_name() -> None:
    assert importer._member_name_rejection("sigma-x/rules/linux/good.yml") is None


@pytest.mark.parametrize(
    ("name", "reason"),
    [
        ("evil/rules/../../../pwned.yml", "traversal"),
        ("/rules/absolute.yml", "absolute"),
        ("\\rules\\absolute.yml", "absolute"),
        ("evil\\rules\\pwned.yml", "backslash"),
        ("C:/rules/pwned.yml", "drive-letter"),
    ],
)
def test_validated_relative_path_rejects_raw_unsafe_names(
    tmp_path: Path,
    name: str,
    reason: str,
) -> None:
    rules_root = tmp_path / "work" / "rules"

    with pytest.raises(SigmaImportError, match=reason):
        importer._validated_relative_path(
            name,
            rules_root,
            rules_root.resolve(),
            tmp_path / "evil.zip",
        )


def test_validated_relative_path_accepts_rules_member(tmp_path: Path) -> None:
    rules_root = tmp_path / "work" / "rules"

    relative = importer._validated_relative_path(
        "sigma-x/rules/linux/good.yml",
        rules_root,
        rules_root.resolve(),
        tmp_path / "release.zip",
    )

    assert relative == Path("linux/good.yml")


def test_validated_relative_path_ignores_non_rules_member(tmp_path: Path) -> None:
    rules_root = tmp_path / "work" / "rules"

    relative = importer._validated_relative_path(
        "sigma-x/README.md",
        rules_root,
        rules_root.resolve(),
        tmp_path / "release.zip",
    )

    assert relative is None


# ---------------------------------------------------------------------------
# Finding 2: decompression bombs (download / per-file / cumulative caps)
# ---------------------------------------------------------------------------


def test_extract_rejects_oversized_rule_file(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(importer, "MAX_RULE_FILE_BYTES", 1024)

    archive_path = build_zip(
        tmp_path / "bomb.zip",
        {"sigma-x/rules/big.yml": b"a" * 4096},
    )

    with pytest.raises(SigmaImportError, match="per-file"):
        extract_rules_directory(archive_path, tmp_path / "work")


def test_extract_rejects_cumulative_size(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(importer, "MAX_TOTAL_EXTRACTED_BYTES", 1500)

    archive_path = build_zip(
        tmp_path / "many.zip",
        {
            "sigma-x/rules/one.yml": b"a" * 1000,
            "sigma-x/rules/two.yml": b"b" * 1000,
        },
    )

    with pytest.raises(SigmaImportError, match="total extraction cap"):
        extract_rules_directory(archive_path, tmp_path / "work")


def test_download_rejects_oversized_release(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(importer, "MAX_DOWNLOAD_BYTES", 16)
    monkeypatch.setattr(
        urllib.request,
        "urlopen",
        lambda *args, **kwargs: _FakeResponse(b"x" * 64),
    )

    destination = tmp_path / "release.zip"

    with pytest.raises(SigmaImportError, match="download cap"):
        download_release_zip("r-test", destination)

    assert not destination.exists()


# ---------------------------------------------------------------------------
# Finding 3: symlinked sigma destination during refresh
# ---------------------------------------------------------------------------


@pytest.mark.skipif(os.name == "nt", reason="symlink deletion semantics differ on Windows")
def test_refresh_refuses_symlinked_sigma_destination(tmp_path: Path) -> None:
    rules_root = write_rules_tree(tmp_path / "source")

    destination = tmp_path / "dest"
    destination.mkdir()

    outside = tmp_path / "outside"
    outside.mkdir()

    keep = outside / "keep.yaml"
    keep.write_text("rules: []\n", encoding="utf-8")

    (destination / "sigma").symlink_to(outside, target_is_directory=True)

    with pytest.raises(SigmaImportError, match="symlink"):
        import_into(rules_root, [destination])

    assert keep.exists()


# ---------------------------------------------------------------------------
# Finding 4: deeply nested conditions must not abort the import
# ---------------------------------------------------------------------------


def test_deeply_nested_condition_is_skipped(
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
) -> None:
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()

    (rules_dir / "good.yml").write_text(GOOD_RULE, encoding="utf-8")

    deep_condition = "not " * 5000 + "selection"

    (rules_dir / "deep.yml").write_text(
        "title: Deep rule\n"
        "id: 22222222-2222-2222-2222-222222222222\n"
        "level: low\n"
        "logsource:\n"
        "    category: process_creation\n"
        "    product: linux\n"
        "detection:\n"
        "    selection:\n"
        "        Image: /usr/bin/evil\n"
        f"    condition: {deep_condition}\n",
        encoding="utf-8",
    )

    with caplog.at_level(logging.WARNING, logger="sentinelclaw.sigma.importer"):
        summary = convert_directory(rules_dir)

    assert summary.converted_count == 1
    assert summary.skipped.get("recursion-error") == 1
    assert any("deep.yml" in record.getMessage() for record in caplog.records)


# ---------------------------------------------------------------------------
# Happy path: a normal release zip still imports end to end
# ---------------------------------------------------------------------------


def test_normal_release_zip_imports_successfully(tmp_path: Path) -> None:
    archive_path = build_zip(
        tmp_path / "release.zip",
        {
            "sigma-r2026-07-01/rules/linux/good.yml": GOOD_RULE,
            "sigma-r2026-07-01/rules/README.md": "docs",
        },
    )

    rules_root = extract_rules_directory(archive_path, tmp_path / "work")

    extracted = rules_root / "linux" / "good.yml"

    assert extracted.read_text(encoding="utf-8") == GOOD_RULE

    destination = tmp_path / "dest"

    summary = import_into(rules_root, [destination])

    assert summary.converted_count == 1
    assert (destination / "sigma" / "linux" / "good.yaml").exists()
