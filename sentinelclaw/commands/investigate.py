"""``investigate`` command module (P6-30).

Runs the scan and augments the deterministic results with an optional
local Qwen analysis; AI output is advisory only.
"""

from __future__ import annotations

import argparse

from sentinelclaw.ai.qwen_analyzer import analyze_report_with_qwen

from sentinelclaw.config.settings import get_settings

from sentinelclaw.ui.console import sanitize_terminal_text


COMMANDS = ("investigate",)


def register(
    subparsers: argparse._SubParsersAction[argparse.ArgumentParser],
) -> None:
    investigate_parser = subparsers.add_parser(
        "investigate",
        help=("Run scan and analyze results using optional local Qwen"),
    )

    investigate_parser.add_argument(
        "--model",
        default=None,
        help=("Ollama model to use (default: qwen3:14b or configured model)"),
    )


def handle(
    args: argparse.Namespace,
) -> None:
    from sentinelclaw import main as cli

    report = cli.run_scan(show_progress=True)

    print_ai_investigation(
        report,
        model=(args.model or get_settings().ollama_model),
    )


def print_ai_investigation(
    report: dict,
    model: str,
) -> None:
    print()
    print("Deterministic scan complete.")

    print(f"Findings: {report['summary']['total_findings']}")

    print(f"Incidents: {report['summary']['incidents']}")

    print(f"Risk: {report['risk']['score']}/100 ({report['risk']['level'].upper()})")

    print()
    print(f"Starting optional local AI analysis with {sanitize_terminal_text(model)}...")

    try:
        ai_result = analyze_report_with_qwen(
            report,
            model=model,
        )
    except RuntimeError as exc:
        print()
        print("[AI UNAVAILABLE]")

        print(sanitize_terminal_text(exc))

        print()
        print("The SentinelClaw deterministic security scan completed successfully.")

        print("Start Ollama and ensure the requested model is installed to use AI analysis.")

        return
    except Exception as exc:
        print()
        print(f"[AI ERROR] {sanitize_terminal_text(exc)}")

        print("The deterministic scan results remain valid.")

        return

    print()
    print("=" * 72)
    print("                 SENTINELCLAW AI INVESTIGATION")
    print("=" * 72)
    print()

    print(f"Model: {sanitize_terminal_text(ai_result['model'])}")

    print()
    print(sanitize_terminal_text(ai_result["analysis"]))

    print()
    print("=" * 72)
    print("AI analysis is advisory. Detections come from SentinelClaw's deterministic engine.")
    print("=" * 72)
    print()
