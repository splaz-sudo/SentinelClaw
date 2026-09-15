# SentinelClaw

**SentinelClaw** is a local, defensive cybersecurity analysis CLI for Windows and Linux.

It collects and analyzes security-relevant system data, normalizes detections, correlates related findings into incidents, builds investigation timelines, calculates risk scores, analyzes PCAP files, and generates security assessment reports.

SentinelClaw can optionally use a locally running **Qwen model through Ollama** to explain deterministic scan results.

> SentinelClaw is designed for defensive security, investigation, education, and authorized analysis. Its core detection engine does not depend on AI.

---

## Features

- Local system security scanning
- Running process analysis
- Network connection analysis
- Windows Security Event Log analysis
- Offline EVTX log analysis
- File security analysis
- Text log analysis
- Offline PCAP analysis
- YAML-based detection rules
- SigmaHQ rule import
- Finding normalization and deduplication
- Incident correlation
- Security timeline generation
- Scan-state history and hunting commands
- Risk scoring
- MITRE ATT&CK mappings
- JSON, text, HTML, CSV, and JSONL reports
- Optional local Qwen analysis through Ollama
- Terminal security dashboard
- Plugin API (entry-point based)
- Standalone binary packaging (PyInstaller)
- OpenClaw integration
- No cloud dependency for core detection

---

## Architecture

```text
Security Data
     |
     v
Collectors / File Input
     |
     v
Analyzers
     |
     v
Detectors + YAML Rules
     |
     v
Finding Processor
     |
     v
Correlation Engine
     |
     +--------------------+
     |                    |
     v                    v
Risk Engine          Timeline Engine
     |                    |
     +---------+----------+
               |
               v
        Reports / Console
               |
               v
      Optional Local Qwen
```

The deterministic security pipeline operates independently from the AI layer.

AI is used as an optional investigation assistant rather than as the primary detection mechanism.

---

## Requirements

### Supported Python

Python 3.11 or newer.

### Primary Platforms

- Windows 10
- Windows 11
- Linux

Some functionality is platform-specific.

Windows Security Event Log collection requires Windows and may require an elevated terminal.

---

## Installation

Clone the repository:

```bash
git clone <repository-url>
cd SentinelClaw
```

Create a virtual environment:

### Windows PowerShell

```powershell
python -m venv venv
venv\Scripts\Activate.ps1
```

### Linux

```bash
python3 -m venv venv
source venv/bin/activate
```

Upgrade pip:

```bash
python -m pip install --upgrade pip
```

Install SentinelClaw in editable mode:

```bash
python -m pip install -e .
```

Verify the installation:

```bash
sentinelclaw --help
```

---

## Optional Extras

SentinelClaw ships as a lean core. Optional analysis features are
installed through package extras; a missing extra disables only the
related collectors, never the core pipeline.

### PCAP Support

PCAP analysis uses Scapy.

Install SentinelClaw with PCAP support:

```bash
python -m pip install -e ".[pcap]"
```

Then analyze a capture:

```bash
sentinelclaw pcap path/to/capture.pcap
```

SentinelClaw performs offline PCAP analysis and does not require packet capture privileges for existing capture files.

Depending on the operating system and Scapy configuration, additional packet-capture components may be required for functionality beyond SentinelClaw's offline analysis workflow.

### EVTX Support

Offline Windows Event Log (.evtx) analysis uses python-evtx:

```bash
python -m pip install -e ".[evtx]"
sentinelclaw evtx path/to/file.evtx
```

### YARA Support

YARA rule scanning for the `file` command uses yara-python:

```bash
python -m pip install -e ".[yara]"
```

YARA rules are loaded from the packaged `sentinelclaw/rules/yara/`
directory (overridable with `SENTINELCLAW_YARA_RULES_DIR`).

Extras can be combined, for example:

```bash
python -m pip install -e ".[pcap,evtx,yara]"
```

### Build Extra

`.[build]` installs PyInstaller for producing standalone binaries; see
the [Packaging](#standalone-binaries) section.

---

## Development Installation

Install the development dependencies:

```bash
python -m pip install -e ".[dev]"
```

Run the automated test suite:

```bash
pytest
```

For detailed output:

```bash
pytest -v
```

---

## Quick Start

Run the terminal dashboard:

```bash
sentinelclaw dashboard
```

Show additional evidence:

```bash
sentinelclaw dashboard --verbose
```

Run the complete deterministic scan:

```bash
sentinelclaw scan
```

Display a compact summary:

```bash
sentinelclaw summary
```

Show correlated incidents:

```bash
sentinelclaw incidents
```

Display the investigation timeline:

```bash
sentinelclaw timeline
```

Show loaded detection rules:

```bash
sentinelclaw rules
```

---

## Commands

Command reference (run any command with `--help` for the live
definition; the global `--debug` flag shows Python tracebacks):

| Command | Purpose | Arguments / flags |
| --- | --- | --- |
| `system` | Show system information | |
| `processes` | Show running processes | |
| `network` | Show network connections | |
| `windows-events` | Show monitored Windows Security events (Windows, admin) | |
| `evtx` | Analyze an offline `.evtx` log | `path`, `--json`, `--verbose` |
| `scan` | Run the complete scan, print machine-readable JSON | `--format json\|jsonl`, `--json-raw`, `--since ISO`, `--last` |
| `dashboard` | Run scan, display the security console | `--verbose` |
| `summary` | Run scan, show compact security summary | `--verbose` |
| `watch` | Loop scans, record state, print finding deltas | `--interval N`, `--count N` |
| `report` | Generate report files | `--format json\|text\|html\|csv\|jsonl\|all`, `--json-raw` |
| `rules` | Show loaded detection rules | subcommand `import` |
| `rules import` | Import SigmaHQ rules | `--source`, `--release`, `--dest` |
| `incidents` | Run scan, show correlated incidents | `--verbose` |
| `timeline` | Run scan, show chronological timeline | |
| `history` | List scan-state records | |
| `diff` | Show new/closed findings between records | `[id1 id2]`, `--last` |
| `search` | Search findings/incidents in scan state | `keyword`, `--state ID` |
| `accounts` | Summarize logon activity from scan state | |
| `tree` | Render an incident's process tree | `incident_id` |
| `stats` | Event-ID / finding-count statistics | |
| `investigate` | Run scan, optional local Qwen analysis | `--model NAME` |
| `logs` | Analyze a text log file | `file`, `--json`, `--verbose` |
| `file` | Analyze a file or directory | `path`, `--json`, `--verbose` |
| `pcap` | Analyze a PCAP/PCAPNG capture | `path`, `--json`, `--verbose` |
| `sample-plugin` | Demo of the plugin API | |

### System Information

```bash
sentinelclaw system
```

Collects basic local system information.

### Process Analysis

```bash
sentinelclaw processes
```

Collects information about running processes.

Process detections can identify indicators such as suspicious execution locations, unusual parent-child relationships, suspicious PowerShell arguments, and selected living-off-the-land behavior.

A detection is an indicator for investigation and does not by itself prove malicious activity.

### Network Analysis

```bash
sentinelclaw network
```

Examines current network connections.

SentinelClaw can identify security-relevant network indicators such as connections involving monitored ports.

Network findings should be validated before being treated as malicious.

### Windows Security Events

```bash
sentinelclaw windows-events
```

Analyzes selected Windows Security Event Log records.

Monitored events include security-relevant activity such as:

- Failed logons
- Explicit credential use
- Special privilege assignment
- Process creation
- Service installation
- Account creation
- Group membership changes
- Account lockouts
- Security audit log clearing

Access to the Windows Security log may require Administrator privileges.

If access is denied, launch PowerShell, Windows Terminal, or VS Code as Administrator and run SentinelClaw again.

### Offline EVTX Analysis

```bash
sentinelclaw evtx path/to/file.evtx
```

Analyzes an offline Windows Event Log file without a live event-log
connection. Requires the `evtx` extra.

Machine-readable output:

```bash
sentinelclaw evtx path/to/file.evtx --json
```

### Text Log Analysis

```bash
sentinelclaw logs path/to/file.log
```

Analyzes supported text log input.

```bash
sentinelclaw logs path/to/file.log --json --verbose
```

### File Analysis

```bash
sentinelclaw file path/to/file.exe
```

File analysis can examine indicators including:

- SHA-256
- File metadata
- MIME information
- Entropy
- PE signatures
- Authenticode status
- Executable location
- Suspicious double extensions
- Script file types

Machine-readable output:

```bash
sentinelclaw file path/to/file.exe --json
```

### PCAP Analysis

```bash
sentinelclaw pcap path/to/capture.pcap
```

PCAP analysis includes:

- Protocol statistics
- Source and destination IPs
- Destination ports
- Network flows
- TCP scan indicators
- UDP scan indicators
- Monitored-port detections
- High-volume flow indicators

PCAP findings represent investigation signals rather than automatic proof of compromise.

### Scan State & Hunting Commands

`scan` persists a bounded record of every run (see
[State Store](#state-store)). The hunting commands query those records:

```bash
sentinelclaw history                      # list scan records
sentinelclaw diff --last                  # new/closed findings vs previous scan
sentinelclaw diff <id1> <id2>             # ... between two records
sentinelclaw search powershell            # keyword search across records
sentinelclaw accounts                     # logon activity summary
sentinelclaw stats                        # Event-ID / finding-count statistics
sentinelclaw tree <incident_id>           # process tree for an incident
sentinelclaw watch                        # loop scans, print finding deltas
```

`scan` also reports deltas against an explicit baseline:

```bash
sentinelclaw scan --since 2026-01-01T00:00:00Z
sentinelclaw scan --last                  # delta vs the previous record
sentinelclaw scan --format jsonl          # one JSON object per line
```

`watch` accepts `--interval N` (seconds between scans) and `--count N`
(0 = until interrupted).

---

## Security Dashboard

```bash
sentinelclaw dashboard
```

The dashboard provides a compact SOC-style overview containing information such as:

```text
SENTINELCLAW SECURITY DASHBOARD

RISK
Overall Risk : LOW
Risk Score   : 6/100

SCAN SUMMARY
Processes
Connections
Windows Events
Findings
Incidents

PRIORITIZED FINDINGS
...
```

Use:

```bash
sentinelclaw dashboard --verbose
```

for additional evidence and context.

---

## Detection Rules

SentinelClaw supports external YAML detection rules.

The default rule categories include:

```text
process
file
windows_event
```

Example rule structure:

```yaml
id: PROC-EXAMPLE-001
title: Example Process Detection
category: process
severity: medium
description: Example defensive process rule.

conditions:
  - field: name
    operator: equals
    value: powershell.exe
```

Rules should identify observable security indicators rather than assume malicious intent without supporting evidence.

List the loaded rules:

```bash
sentinelclaw rules
```

### SigmaHQ Import

`rules import` converts SigmaHQ rules into SentinelClaw's internal
format. By default it downloads the pinned SigmaHQ release; pass a
local checkout or release zip with `--source` to convert offline:

```bash
sentinelclaw rules import                                  # downloads pinned release
sentinelclaw rules import --source /path/to/sigma          # offline conversion
sentinelclaw rules import --release r2026-07-01            # pin a release tag
sentinelclaw rules import --dest /path/to/rules            # explicit destination
```

The release tag can also be set with `SENTINELCLAW_SIGMA_RELEASE`.
Imported rules are written into a `sigma/` tree inside the rule
directory and are listed by `sentinelclaw rules`.

---

## Finding Processing

Raw detections are passed through SentinelClaw's finding processor.

The processor handles:

- Severity normalization
- Confidence normalization
- Evidence normalization
- MITRE metadata normalization
- Duplicate detection
- Finding merging
- Deterministic ordering

This reduces repeated alerts before correlation and reporting.

---

## Incident Correlation

SentinelClaw attempts to correlate related security findings into higher-level incidents.

Examples include:

- Multiple suspicious findings involving the same process
- Process and network activity sharing relevant context
- Related MITRE ATT&CK activity

Correlation increases investigative context but does not automatically prove that an intrusion occurred.

---

## Timeline

Run:

```bash
sentinelclaw timeline
```

SentinelClaw builds a chronological investigation timeline from findings and correlated incidents when timestamps are available.

This helps reconstruct the order of security-relevant activity.

---

## Risk Scoring

SentinelClaw uses deterministic severity-based risk scoring.

Findings and correlated incidents contribute to the overall assessment.

Risk levels include:

```text
INFORMATIONAL
LOW
MEDIUM
HIGH
CRITICAL
```

The risk score is intended for prioritization.

It should not be interpreted as a mathematical probability that a system is compromised.

---

## Reports

Generate all report formats:

```bash
sentinelclaw report
```

SentinelClaw supports:

```text
JSON
Text
HTML
CSV
JSONL
```

`report` with no arguments defaults to `--format all`, which writes
JSON, text, and HTML. Generate a specific format:

```bash
sentinelclaw report --format html
```

Other examples:

```bash
sentinelclaw report --format json
sentinelclaw report --format text
sentinelclaw report --format csv
sentinelclaw report --format jsonl
sentinelclaw report --format all
```

`--json-raw` embeds raw collector dumps (processes, network
connections, Windows events) into the JSON report.

Reports include security assessment information such as:

- Overall risk
- Executive assessment
- Scan statistics
- Prioritized observations
- Findings
- Correlated incidents
- Timeline events
- Collector status
- Investigation recommendations
- Methodology and limitations

Generated reports are stored in the configured report directory.

The report directory can be overridden using:

```text
SENTINELCLAW_REPORT_DIR
```

---

## Optional Local AI Investigation

SentinelClaw's core security engine does **not** require AI.

The architecture is:

```text
SentinelClaw
├── Deterministic scan → AI not required
└── AI investigation   → optional Ollama/Qwen
```

The AI layer receives results produced by SentinelClaw's deterministic analysis pipeline and provides an analyst-oriented explanation.

It does not replace the underlying detection engine.

---

## Ollama Setup

Install Ollama separately.

After Ollama is installed, download a compatible Qwen model.

Example:

```bash
ollama pull qwen3:14b
```

Verify it is available:

```bash
ollama list
```

Then run:

```bash
sentinelclaw investigate
```

The default model is:

```text
qwen3:14b
```

A different installed Ollama model can be selected with:

```bash
sentinelclaw investigate --model MODEL_NAME
```

For example:

```bash
sentinelclaw investigate --model qwen3:14b
```

If Ollama is unavailable, the deterministic SentinelClaw scan remains usable.

---

## AI Security Model

SentinelClaw follows a separation-of-responsibility model:

```text
Python detection engine
        |
        | produces evidence
        v
Structured findings
        |
        v
Correlation + risk + timeline
        |
        v
Optional Qwen analysis
```

The deterministic engine identifies observable indicators.

The AI layer is intended to:

- Summarize evidence
- Explain findings
- Assist investigation
- Identify relationships in supplied evidence
- Suggest defensive verification steps

The AI layer should not invent evidence or treat an indicator as confirmed malware without supporting data.

AI output is advisory.

---

## Configuration

SentinelClaw resolves settings with the following precedence (lowest
to highest):

1. Built-in defaults.
2. An optional TOML configuration file.
3. `SENTINELCLAW_*` environment variables (environment wins).

TOML discovery order (first existing file wins):

1. `SENTINELCLAW_CONFIG` environment variable, when set.
2. `./sentinelclaw.toml` in the current working directory.
3. `~/.config/sentinelclaw/config.toml`.

A missing configuration file is not an error; built-in defaults apply.

### Environment Variables

Common path overrides:

```text
SENTINELCLAW_RULES_DIR      detection rules directory
SENTINELCLAW_REPORT_DIR     report output directory
SENTINELCLAW_DATA_DIR       scan-state store and data directory
SENTINELCLAW_YARA_RULES_DIR YARA rules directory
SENTINELCLAW_SIGMA_RELEASE  SigmaHQ release tag for `rules import`
SENTINELCLAW_CONFIG         path to the TOML config file
```

The full settings table (every `SENTINELCLAW_*` variable and its TOML
key) is documented in the module docstring of
`sentinelclaw/config/settings.py` -- that table is the source of truth.

---

## State Store

Each `scan` (and `watch`) appends a bounded record to the local
scan-state store, one JSON object per line in `scans.jsonl` under the
resolved data directory (default `./data`, override with
`SENTINELCLAW_DATA_DIR`). The hunting commands -- `history`, `diff`,
`search`, `accounts`, `tree`, `stats` -- read these records. The store
is purely local and read-only with respect to the target system.

---

## Plugins

External packages can contribute commands through the
`sentinelclaw.detectors` entry-point group. A plugin module exposes
`register(subparsers)`, `handle(args)`, and an optional `COMMANDS`
tuple. Discovery is best-effort: a broken plugin is logged and skipped
without affecting built-in commands.

The built-in `sample-plugin` command demonstrates the API:

```bash
sentinelclaw sample-plugin
```

Example entry point in a plugin's `pyproject.toml`:

```toml
[project.entry-points."sentinelclaw.detectors"]
myplugin = "myplugin"
```

---

## Standalone Binaries

Standalone, OS-native binaries are built with PyInstaller (the
`[build]` extra). See `packaging/README.md` for the full build and
release-signing process:

```bash
# Linux / macOS
scripts/build_binary.sh

# Windows (PowerShell)
.\scripts\build_binary.ps1
```

The CI `build` job builds on `ubuntu-latest` and `windows-latest` and
uploads `dist/sentinelclaw` / `dist/sentinelclaw.exe` as artifacts, so
a Windows binary is available even when developing on Linux. Binary
signing (Authenticode / codesign / GPG) is a release-time step; see
`packaging/README.md`. Versions are bumped with
`scripts/bump_version.py` before tagging a release.

---

## Windows Launcher

The repository includes:

```text
sentinelclaw.bat
```

It can be used from the project directory on Windows.

Example:

```powershell
.\sentinelclaw.bat dashboard
```

The launcher uses the project's `venv` if present, falling back to
`.venv`. If neither exists it prints a clear error instead of falling
back to a possibly-unconfigured system Python.

After package installation, the preferred command is:

```bash
sentinelclaw
```

---

## OpenClaw Integration

SentinelClaw includes an OpenClaw skill definition for local integration.

The integration is intended to expose defensive SentinelClaw analysis through OpenClaw while keeping the underlying security operations read-only.

The skill must not automatically:

- Kill processes
- Delete files
- Modify the registry
- Modify firewall rules
- Perform remediation
- Execute destructive actions

SentinelClaw should provide evidence and investigation context while leaving consequential remediation decisions to the operator.

---

## Project Structure

```text
SentinelClaw/
│
├── .github/            # CI workflows (lint, typecheck, tests, build)
├── sentinelclaw/
│   ├── ai/
│   ├── commands/       # CLI command modules (P6-30)
│   ├── config/
│   ├── detectors/
│   ├── engine/
│   ├── models/
│   ├── plugins/        # entry-point plugin discovery + sample plugin
│   ├── reporting/
│   ├── rules/          # packaged rule trees (yaml, sigma, yara)
│   ├── sigma/          # SigmaHQ importer/reader
│   ├── state/          # scan-state store + hunting commands
│   ├── tools/
│   └── ui/
│
├── rules/              # detection-rule source of truth (synced to package)
├── packaging/          # PyInstaller spec + packaging docs
├── scripts/            # sync_rules, bump_version, build_binary
├── tests/
├── data/               # scan-state store and sample data
├── reports/
├── openclaw/
│
├── pyproject.toml
├── requirements.txt
├── sentinelclaw.bat
└── README.md
```

---

## Testing

SentinelClaw includes automated tests for core components including:

- Risk scoring
- Finding processing
- Correlation
- Timeline generation
- YAML rule execution
- CLI behavior

Run:

```bash
pytest -v
```

A release should not be considered validated unless the automated test suite passes.

---

## Security Philosophy

SentinelClaw is intentionally designed around several principles.

**Deterministic detection first**

Security findings should originate from observable data and deterministic rules whenever possible.

**AI is optional**

Failure or absence of the local AI model must not disable core security analysis.

**Evidence before conclusions**

Suspicious behavior is treated as an investigation indicator rather than automatic proof of compromise.

**Local-first operation**

Core analysis is designed to run locally without requiring cloud services.

**Read-only analysis**

SentinelClaw focuses on collection, detection, correlation, investigation, and reporting rather than automatic remediation.

---

## Limitations

SentinelClaw is not a replacement for an enterprise EDR, SIEM, antivirus product, or professional incident-response platform.

Current limitations may include:

- Detection rules can produce false positives.
- Windows Security Event Log access depends on permissions and auditing configuration.
- Network connections may be legitimate even when they match monitored indicators.
- PCAP scan heuristics do not by themselves prove reconnaissance or compromise.
- Some timestamps may originate from different system or event sources.
- Correlation is heuristic and should be reviewed by an analyst.
- Local AI output can contain incorrect interpretations.
- AI-generated conclusions must be validated against deterministic evidence.
- Platform-specific collectors may not be available on every operating system.
- UI strings are English-only (internationalization is deferred; see `ui/console.py`).

---

## Responsible Use

SentinelClaw is intended for:

- Defensive cybersecurity
- Security education
- SOC training
- Authorized system investigation
- Incident analysis
- Security research on systems and data you are permitted to analyze

Do not use SentinelClaw to access, interfere with, or analyze systems without authorization.

---

## Project Status

SentinelClaw is under active development.

Current major capabilities include:

```text
System collection
Process analysis
Network analysis
Windows Event Log analysis
EVTX analysis
File analysis
YAML detection rules
SigmaHQ rule import
Scan-state history and hunting
Finding normalization
Incident correlation
Timeline reconstruction
Local Qwen integration
PCAP analysis
Terminal dashboard
Report generation
Plugin API
Standalone binaries
Automated testing
OpenClaw integration
```

The project is being prepared for a clean-machine release validation and public repository release.
