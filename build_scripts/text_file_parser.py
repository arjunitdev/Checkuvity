#!/usr/bin/env python3
"""
Text file parser used by the demo server and CLI utilities.
Extracts SHA-256 hashes, signatures, and post-signature hashes from a variety of
manifest formats so uploads succeed even when users supply custom layouts.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional


@dataclass
class ParsedFileData:
    """Container for values extracted from a text manifest."""

    filename: str
    original_hash: Optional[str] = None
    signature: Optional[str] = None
    post_signature_hash: Optional[str] = None
    raw_content: str = ""
    parse_success: bool = False
    parse_errors: List[str] | None = None

    def __post_init__(self) -> None:
        if self.parse_errors is None:
            self.parse_errors = []


def compute_text_hash(text: str) -> str:
    """Return the SHA-256 digest for the provided text."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


class TextFileParser:
    """Flexible parser that recognises several common manifest layouts."""

    # Precompiled regexes for the parser
    PATTERNS: Dict[str, List[str]] = {
        "pre": [
            r"(?:pre[_\-\s]?signature[_\-\s]?hash|original[_\-\s]?hash|hash value)\s*[:=]\s*([A-Fa-f0-9]{64})",
            r"1\.\s*PRE[_\-\s]?SIGNATURE\s+HASH.*?([A-Fa-f0-9]{64})",
            r"(?:^|\n)(?:sha-?256)\s*[:=]\s*([A-Fa-f0-9]{64})",
        ],
        "sig": [
            r"(?:security[_\-\s]?signature|signature hash|signature)\s*[:=]\s*([A-Fa-f0-9]{64})",
            r"2\.\s*SECURITY\s+SIGNATURE.*?([A-Fa-f0-9]{64})",
        ],
        "post": [
            r"(?:post[_\-\s]?signature[_\-\s]?hash|final hash)\s*[:=]\s*([A-Fa-f0-9]{64})",
            r"4\.\s*POST[_\-\s]?SIGNATURE\s+HASH.*?([A-Fa-f0-9]{64})",
        ],
    }

    @staticmethod
    def parse_file(file_path: Path) -> ParsedFileData:
        """Read a path from disk and delegate to `parse_content`."""
        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")
        except Exception as exc:
            return ParsedFileData(
                filename=file_path.name,
                parse_success=False,
                parse_errors=[f"Error reading file: {exc}"],
            )

        return TextFileParser.parse_content(content, filename=file_path.name)

    @staticmethod
    def parse_content(content: str, filename: str = "unknown") -> ParsedFileData:
        """Parse already-loaded manifest text."""
        parsed = ParsedFileData(filename=filename, raw_content=content, parse_success=False)

        parsed.original_hash = TextFileParser._extract_first(content, TextFileParser.PATTERNS["pre"])
        parsed.signature = TextFileParser._extract_first(content, TextFileParser.PATTERNS["sig"])
        parsed.post_signature_hash = TextFileParser._extract_first(content, TextFileParser.PATTERNS["post"])

        if not parsed.original_hash and not parsed.signature and not parsed.post_signature_hash:
            hashes = TextFileParser._extract_all_hashes(content)
            if hashes:
                parsed.original_hash = hashes[0]
            if len(hashes) > 1:
                parsed.signature = hashes[1]
            if len(hashes) > 2:
                parsed.post_signature_hash = hashes[2]

        if not parsed.original_hash and content:
            parsed.original_hash = compute_text_hash(content)
            parsed.parse_errors.append("Pre-signature hash missing; computed hash of entire file.")

        parsed.parse_success = parsed.original_hash is not None
        if not parsed.parse_success and not parsed.parse_errors:
            parsed.parse_errors.append("No SHA-256 hashes found in manifest.")

        return parsed

    @staticmethod
    def _extract_first(content: str, patterns: List[str]) -> Optional[str]:
        for pattern in patterns:
            match = re.search(pattern, content, flags=re.IGNORECASE | re.DOTALL)
            if match:
                return match.group(1).lower()
        return None

    @staticmethod
    def _extract_all_hashes(content: str) -> List[str]:
        matches = re.findall(r"\b([A-Fa-f0-9]{64})\b", content)
        unique: List[str] = []
        seen = set()
        for item in matches:
            lower = item.lower()
            if lower not in seen:
                seen.add(lower)
                unique.append(lower)
        return unique


def parse_text_files(file_paths: List[Path]) -> Dict[str, ParsedFileData]:
    """Convenience helper for CLI usage."""
    parser = TextFileParser()
    results: Dict[str, ParsedFileData] = {}

    for path in file_paths:
        if not path.exists():
            continue
        results[path.name] = parser.parse_file(path)

    return results


def main() -> None:
    import sys

    if len(sys.argv) < 2:
        print("Usage: python text_file_parser.py <text_file1> [text_file2] ...")
        raise SystemExit(1)

    paths = [Path(arg) for arg in sys.argv[1:]]
    results = parse_text_files(paths)

    for name, parsed in results.items():
        print("\n" + "=" * 60)
        print(f"File: {name}")
        print("=" * 60)
        print(f"Parse Success: {parsed.parse_success}")
        print(f"Original Hash: {parsed.original_hash}")
        print(f"Signature: {parsed.signature}")
        print(f"Post-Signature Hash: {parsed.post_signature_hash}")
        if parsed.parse_errors:
            print(f"Errors: {parsed.parse_errors}")


if __name__ == "__main__":
    main()








