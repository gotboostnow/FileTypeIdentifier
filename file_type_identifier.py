#!/usr/bin/env python3
"""Interactive file-type identifier based on file header signatures."""

from __future__ import annotations

import argparse
import sys

from detector import (
    Analysis,
    AnalysisError,
    analyze_file,
    format_extensions,
    format_hex_preview,
)

BANNER = "---FILE TYPE IDENTIFIER---"
NOTE = (
    "Magic numbers identify content, not intent. Headers can be forged and\n"
    "polyglot files can match multiple formats. Use this as a triage signal,\n"
    "not as proof that a file is safe."
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Identify a file by its magic number, compare the result with its "
            "extension, and flag suspicious mismatches."
        )
    )
    parser.add_argument(
        "path",
        nargs="?",
        help="file to analyze; omit for interactive mode",
    )
    parser.add_argument(
        "--no-file",
        action="store_true",
        help="skip the optional system 'file' cross-check",
    )
    return parser


def render_report(analysis: Analysis) -> None:
    detection = analysis.detection
    assessment = analysis.assessment
    expected = (
        "any text/source extension"
        if detection.category == "text"
        else format_extensions(detection.extensions)
    )
    extension_display = f".{analysis.extension}" if analysis.extension else "(none)"

    print(f"File: {analysis.path}")
    print(f"Size: {analysis.size:,} bytes")
    print()
    print("Magic Number Analysis:")
    print(f"Raw hex: {format_hex_preview(analysis.header)}")
    print(f"Detected: {detection.name} [{detection.confidence} confidence]")
    print(f"MIME type: {detection.mime}")
    if detection.note:
        print(f"Details: {detection.note}")
    print()
    print(f"File extension: {extension_display}")
    print(f"Expected extensions: {expected}")
    print(f"Verdict: {assessment.state}")
    print(f"Risk: {assessment.severity}")
    print(f"Reason: {assessment.message}")
    print()
    print("File command output:")
    print(analysis.file_output)
    print()
    note_lines = NOTE.splitlines()
    print(f"Note: {note_lines[0]}")
    for line in note_lines[1:]:
        print(f"      {line}")
    print()


def analyze_and_report(path: str, *, include_file_output: bool) -> bool:
    try:
        analysis = analyze_file(path, include_file_output=include_file_output)
    except AnalysisError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return False
    render_report(analysis)
    return True


def interactive(include_file_output: bool) -> int:
    print(BANNER)
    print()
    while True:
        try:
            raw_path = input("Enter file path to analyze (or 'q' to quit): ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return 0

        if not raw_path:
            continue
        if raw_path.lower() in {"q", "quit", "exit"}:
            return 0

        analyze_and_report(raw_path, include_file_output=include_file_output)
        try:
            input("Press Enter to Continue...")
        except (EOFError, KeyboardInterrupt):
            print()
            return 0
        print()


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    include_file_output = not args.no_file

    if args.path:
        print(BANNER)
        print()
        ok = analyze_and_report(args.path, include_file_output=include_file_output)
        return 0 if ok else 1

    return interactive(include_file_output)


if __name__ == "__main__":
    raise SystemExit(main())
