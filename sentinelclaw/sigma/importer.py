"""
Sigma import pipeline (P2-14).

Turns a SigmaHQ checkout (a directory tree or a release zip) into
converted internal-format rules written under the ``sigma/``
subdirectory of the rule copies.

The import is strictly user-invoked: nothing in this module runs during
scans, and network access happens only when the CLI ``rules import``
command downloads the pinned release. Offline conversions use
``--source <dir-or-zip>`` and are what the test-suite exercises.

Pipeline shape:

1. :func:`collect_sigma_sources` walks a Sigma ``rules/`` directory for
   ``*.yml`` files (recursively).
2. :func:`convert_directory` converts every file through
   ``sigma.reader.convert_sigma_rule``; per-file failures raise
   :class:`~sentinelclaw.sigma.reader.SigmaRuleError` and are tallied
   under their ``reason_code`` instead of aborting the import.
3. :func:`write_converted_directory` clears the destination ``sigma/``
   directory (``refresh``) and mirrors the source layout underneath,
   writing one internal YAML file per converted Sigma file.
4. The CLI writes the identical tree to both rule copies so
   ``scripts/sync_rules.py --check`` stays green.

The default release is a pinned quarterly SigmaHQ snapshot tag
(:data:`SIGMA_RELEASE_TAG`). Override it with ``--release`` on the CLI
or the ``SENTINELCLAW_SIGMA_RELEASE`` environment variable.
"""

from __future__ import annotations

import logging
import os
import urllib.request
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from sentinelclaw.sigma.reader import (
    SigmaRuleError,
    convert_sigma_rule,
)

logger = logging.getLogger(__name__)

#: Pinned SigmaHQ release downloaded by ``sentinelclaw rules import``.
#: SigmaHQ snapshots use immutable ``rYYYY-MM-DD`` tags, so imports stay
#: reproducible.
SIGMA_RELEASE_TAG = "r2026-07-01"

SIGMA_RELEASE_ENV = "SENTINELCLAW_SIGMA_RELEASE"

DEFAULT_NETWORK_TIMEOUT_SECONDS = 120

RELEASE_ZIP_URL = "https://github.com/SigmaHQ/sigma/archive/refs/tags/{tag}.zip"

MAX_SIGMA_FILES = 20_000

#: Hard cap on a downloaded release archive (256 MiB). A larger response
#: is rejected and its partial file removed instead of written to disk.
MAX_DOWNLOAD_BYTES = 256 * 1024 * 1024

#: Hard cap on one extracted ``*.yml`` rule file (8 MiB). Enforced on the
#: bytes actually read, never on the archive's self-reported size.
MAX_RULE_FILE_BYTES = 8 * 1024 * 1024

#: Hard cap on the cumulative bytes extracted from one archive (256 MiB).
MAX_TOTAL_EXTRACTED_BYTES = 256 * 1024 * 1024


class SigmaImportError(Exception):
    """The import as a whole failed (network, extraction, I/O)."""


def release_tag_from_env() -> str:
    """Return the effective release tag (env override or pinned)."""
    return os.environ.get(
        SIGMA_RELEASE_ENV,
        SIGMA_RELEASE_TAG,
    )


def download_release_zip(
    tag: str,
    destination: Path,
    timeout: int = DEFAULT_NETWORK_TIMEOUT_SECONDS,
) -> Path:
    """Download the SigmaHQ release zip for ``tag`` to ``destination``.

    The response is read with a bounded read of
    :data:`MAX_DOWNLOAD_BYTES` plus one byte; anything larger is refused
    (and any partial file removed) rather than materialized. Raises
    :class:`SigmaImportError` on any network failure or when the size cap
    is exceeded.
    """
    url = RELEASE_ZIP_URL.format(tag=tag)

    try:
        with urllib.request.urlopen(
            url,
            timeout=timeout,
        ) as response:
            payload = response.read(MAX_DOWNLOAD_BYTES + 1)
    except OSError as exc:
        raise SigmaImportError(f"Unable to download {url}: {exc}") from exc

    if len(payload) > MAX_DOWNLOAD_BYTES:
        try:
            destination.unlink(missing_ok=True)
        except OSError as exc:
            logger.warning(
                "Unable to remove oversized partial download %s: %s",
                destination,
                exc,
            )

        raise SigmaImportError(
            f"Sigma release {tag} exceeds the {MAX_DOWNLOAD_BYTES}-byte download cap"
        )

    try:
        destination.write_bytes(payload)
    except OSError as exc:
        raise SigmaImportError(f"Unable to write {destination}: {exc}") from exc

    return destination


def _member_name_rejection(
    name: str,
) -> str | None:
    """Return why an archive member name is unsafe, or ``None`` if safe.

    Absolute names, backslash separators, ``..`` traversal components
    and Windows drive letters are never legitimate in a SigmaHQ release
    zip and are refused outright.
    """
    if "\x00" in name:
        return "NUL character"

    if name.startswith("/") or name.startswith("\\"):
        return "absolute path"

    if "\\" in name:
        return "backslash path separator"

    for part in name.split("/"):
        if part == "..":
            return "'..' traversal component"

        if len(part) >= 2 and part[1] == ":" and part[0].isalpha():
            return "Windows drive-letter component"

    return None


def _validated_relative_path(
    name: str,
    rules_root: Path,
    resolved_rules_root: Path,
    zip_path: Path,
) -> Path | None:
    """Validate a ``*.yml`` archive member against the extraction root.

    Returns the member path relative to ``rules/``, or ``None`` when the
    member is not part of a ``rules/`` tree. Raises
    :class:`SigmaImportError` (naming the entry) *before* any directory
    or file is created for absolute, traversing, backslash or
    drive-letter names, or when the resolved destination escapes
    ``resolved_rules_root``.
    """
    rejection = _member_name_rejection(name)

    if rejection is not None:
        raise SigmaImportError(f"Refusing unsafe entry {name!r} in {zip_path}: {rejection}")

    marker = "/rules/"
    marker_index = name.find(marker)

    if marker_index < 0:
        return None

    relative = Path(name[marker_index + len(marker) :])

    if relative.is_absolute() or ".." in relative.parts:
        raise SigmaImportError(
            f"Refusing unsafe entry {name!r} in {zip_path}: path escapes the rules tree"
        )

    destination = rules_root / relative

    if not destination.resolve().is_relative_to(resolved_rules_root):
        raise SigmaImportError(
            f"Refusing entry {name!r} in {zip_path}: destination is outside {resolved_rules_root}"
        )

    return relative


def extract_rules_directory(
    zip_path: Path,
    work_directory: Path,
) -> Path:
    """Extract a release zip's ``rules/**/*.yml`` tree.

    Returns the extracted ``rules/`` directory. Works for GitHub
    ``archive/refs/tags`` zips (which nest under a ``sigma-<tag>/``
    prefix) and for any zip that carries a ``rules/`` tree. Every member
    is containment-checked before extraction, and both per-file and
    cumulative extraction sizes are capped (see the ``MAX_*`` constants);
    violations raise :class:`SigmaImportError` instead of being skipped.
    """
    try:
        archive = zipfile.ZipFile(zip_path)
    except zipfile.BadZipFile as exc:
        raise SigmaImportError(f"Invalid Sigma release zip {zip_path}: {exc}") from exc

    rules_root = work_directory / "rules"
    resolved_rules_root = rules_root.resolve()
    extracted = 0
    total_extracted_bytes = 0

    with archive:
        for info in archive.infolist():
            name = info.filename

            if info.is_dir() or not name.endswith(".yml"):
                continue

            relative = _validated_relative_path(
                name,
                rules_root,
                resolved_rules_root,
                zip_path,
            )

            if relative is None:
                continue

            destination = rules_root / relative

            with archive.open(info) as source:
                payload = source.read(MAX_RULE_FILE_BYTES + 1)

            if len(payload) > MAX_RULE_FILE_BYTES:
                raise SigmaImportError(
                    f"Rule {name!r} in {zip_path} exceeds the "
                    f"{MAX_RULE_FILE_BYTES}-byte per-file extraction cap"
                )

            total_extracted_bytes += len(payload)

            if total_extracted_bytes > MAX_TOTAL_EXTRACTED_BYTES:
                raise SigmaImportError(
                    f"Archive {zip_path} exceeds the "
                    f"{MAX_TOTAL_EXTRACTED_BYTES}-byte total extraction cap"
                )

            destination.parent.mkdir(
                parents=True,
                exist_ok=True,
            )

            destination.write_bytes(payload)

            extracted += 1

            if extracted >= MAX_SIGMA_FILES:
                break

    if extracted == 0:
        raise SigmaImportError(f"No 'rules/**/*.yml' files inside {zip_path}")

    return rules_root


def prepare_source_directory(
    source: Path,
    work_directory: Path,
) -> Path:
    """Return the Sigma ``rules/`` directory for a source path.

    A path to a ``rules`` directory (or the checkout root that contains
    one) is used as-is; a ``.zip`` archive is extracted into
    ``work_directory`` first.
    """
    if source.is_dir():
        candidate = source / "rules" if (source / "rules").is_dir() else source

        if not candidate.is_dir():
            raise SigmaImportError(f"Sigma source directory contains no rules/ tree: {source}")

        return candidate

    if source.is_file() and source.suffix.lower() == ".zip":
        return extract_rules_directory(
            source,
            work_directory,
        )

    raise SigmaImportError(f"Sigma source is neither a directory nor a zip: {source}")


def collect_sigma_sources(
    rules_directory: Path,
) -> list[Path]:
    """Return the sorted ``*.yml`` rule files under a rules directory."""
    if not rules_directory.exists():
        raise SigmaImportError(f"Sigma rules directory does not exist: {rules_directory}")

    sources = sorted(rules_directory.glob("**/*.yml"))

    if not sources:
        raise SigmaImportError(f"No Sigma rule files (*.yml) under {rules_directory}")

    return sources


@dataclass
class ConversionSummary:
    """Outcome tally for one import run."""

    converted: dict[Path, dict[str, Any]] = field(default_factory=dict)
    skipped: dict[str, int] = field(default_factory=dict)
    skip_messages: list[str] = field(default_factory=list)

    @property
    def converted_count(self) -> int:
        return len(self.converted)

    @property
    def skipped_count(self) -> int:
        return sum(self.skipped.values())

    def record_skip(
        self,
        reason_code: str,
        message: str,
    ) -> None:
        self.skipped[reason_code] = self.skipped.get(reason_code, 0) + 1

        if len(self.skip_messages) < 20:
            self.skip_messages.append(message)


def convert_sigma_file(
    file_path: Path,
    summary: ConversionSummary,
) -> dict[str, Any] | None:
    """Convert one Sigma file; tally failures onto ``summary``."""
    try:
        text = file_path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        summary.record_skip(
            "read-error",
            f"{file_path}: {exc}",
        )

        return None

    try:
        return convert_sigma_rule(
            yaml.safe_load(text),
            source=str(file_path),
        )
    except SigmaRuleError as exc:
        summary.record_skip(
            exc.reason_code,
            exc.message,
        )

        return None
    except yaml.YAMLError as exc:
        summary.record_skip(
            "invalid-yaml",
            f"{file_path}: {exc}",
        )

        return None
    except RecursionError:
        logger.warning(
            "Skipping Sigma rule %s: condition nesting exceeds the recursion limit",
            file_path,
        )

        summary.record_skip(
            "recursion-error",
            f"{file_path}: condition nesting exceeds the recursion limit",
        )

        return None


def convert_directory(
    rules_directory: Path,
    summary: ConversionSummary | None = None,
) -> ConversionSummary:
    """Convert every Sigma file under a directory (see module docs)."""
    result = summary if summary is not None else ConversionSummary()

    for source_file in collect_sigma_sources(rules_directory):
        rule = convert_sigma_file(
            source_file,
            result,
        )

        if rule is not None:
            result.converted[source_file] = rule

    return result


def _dump_internal_rules(
    rules: list[dict[str, Any]],
) -> str:
    return yaml.safe_dump(
        {"rules": rules},
        sort_keys=False,
        default_flow_style=False,
        allow_unicode=True,
        width=100,
    )


def _clear_sigma_directory(
    destination: Path,
    rules_root: Path,
) -> None:
    """Remove the destination ``sigma/`` subtree for a refresh import.

    Refuses (raises :class:`SigmaImportError`) when the destination is a
    symlink, when any path component between ``rules_root`` and the
    destination is a symlink, or when the resolved destination lies
    outside the resolved rules root: deleting through a symlink would
    remove files outside the rules tree.
    """
    if destination.is_symlink():
        raise SigmaImportError(f"Refusing to clear symlinked Sigma destination: {destination}")

    current = destination.parent

    while current != rules_root and current.parent != current:
        if current.is_symlink():
            raise SigmaImportError(
                f"Refusing to clear Sigma destination {destination}: {current} is a symlink"
            )

        current = current.parent

    if not destination.resolve().is_relative_to(rules_root.resolve()):
        raise SigmaImportError(
            f"Refusing to clear Sigma destination outside {rules_root}: {destination}"
        )

    if not destination.exists():
        return

    for stale in destination.rglob("*"):
        if stale.is_file():
            stale.unlink()

    for stale in sorted(
        destination.rglob("*"),
        key=lambda path: len(path.parts),
        reverse=True,
    ):
        if stale.is_dir():
            try:
                stale.rmdir()
            except OSError:
                logger.debug(
                    "Unable to remove directory %s",
                    stale,
                )


def write_converted_directory(
    rules_directory: Path,
    destination_root: Path,
    summary: ConversionSummary,
    refresh: bool = False,
) -> list[Path]:
    """Write converted rules under ``destination_root/sigma``.

    Files mirror the source tree relative to ``rules_directory`` and use
    the ``.yaml`` extension (one internal rule file per Sigma file).
    With ``refresh`` the destination ``sigma/`` subtree is replaced.
    """
    destination = destination_root / "sigma"

    if refresh:
        _clear_sigma_directory(destination, destination_root)

    written: list[Path] = []

    for source_file, rule in sorted(summary.converted.items()):
        try:
            relative = source_file.relative_to(rules_directory)
        except ValueError:
            relative = Path(source_file.name)

        target = destination / relative.with_suffix(".yaml")

        target.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        target.write_text(
            _dump_internal_rules([rule]),
            encoding="utf-8",
        )

        written.append(target)

    return written


def import_into(
    sigma_rules_directory: Path,
    destination_roots: list[Path],
    refresh: bool = True,
) -> ConversionSummary:
    """Convert a Sigma source and write identical copies everywhere.

    ``destination_roots`` are rule directories (the packaged runtime
    copy and its repo sibling, usually two entries); each receives an
    identical ``sigma/`` subtree.
    """
    summary = convert_directory(sigma_rules_directory)

    if not summary.converted:
        return summary

    seen: set[Path] = set()

    for root in destination_roots:
        resolved_root = root.resolve()

        if resolved_root in seen:
            continue

        seen.add(resolved_root)

        write_converted_directory(
            rules_directory=sigma_rules_directory,
            destination_root=root,
            summary=summary,
            refresh=refresh,
        )

    return summary


def tally_by_reason(
    skipped: dict[str, int],
) -> list[tuple[str, int]]:
    """Return skip reasons sorted by frequency for the CLI summary."""
    return sorted(
        skipped.items(),
        key=lambda item: (-item[1], item[0]),
    )
