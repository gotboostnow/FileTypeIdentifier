"""Tests for the file-type detector using harmless generated fixtures."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from detector import (  # noqa: E402
    AnalysisError,
    analyze_file,
    format_hex_preview,
)


PNG_HEADER = b"\x89PNG\r\n\x1a\n"
SHELL_SCRIPT = b"#!/usr/bin/env bash\necho 'harmless test fixture'\n"


def make_elf_header() -> bytes:
    header = bytearray(64)
    header[0:4] = b"\x7fELF"
    header[4] = 2  # 64-bit
    header[5] = 1  # little-endian
    header[6] = 1  # ELF version
    header[16:18] = (2).to_bytes(2, "little")  # executable
    header[18:20] = (62).to_bytes(2, "little")  # x86-64
    return bytes(header)


def make_pie_elf_header() -> bytes:
    header = bytearray(make_elf_header())
    header.extend(b"\x00" * 56)
    header[16:18] = (3).to_bytes(2, "little")  # ET_DYN
    header[32:40] = (64).to_bytes(8, "little")  # program header offset
    header[54:56] = (56).to_bytes(2, "little")  # program header size
    header[56:58] = (1).to_bytes(2, "little")  # program header count
    header[64:68] = (3).to_bytes(4, "little")  # PT_INTERP
    return bytes(header)


def make_macho_header() -> bytes:
    return (
        b"\xcf\xfa\xed\xfe"  # 64-bit little-endian
        + (0x0100000C).to_bytes(4, "little")  # ARM64
        + (0).to_bytes(4, "little")
        + (6).to_bytes(4, "little")  # MH_DYLIB
        + b"\x00" * 16
    )


def make_pe_header() -> bytes:
    header = bytearray(256)
    header[0:2] = b"MZ"
    header[0x3C:0x40] = (0x40).to_bytes(4, "little")
    header[0x40:0x44] = b"PE\x00\x00"
    header[0x44:0x46] = (0x8664).to_bytes(2, "little")  # x86-64
    return bytes(header)


def make_bmp_header() -> bytes:
    header = bytearray(54)
    header[0:2] = b"BM"
    header[10:14] = (54).to_bytes(4, "little")
    header[14:18] = (40).to_bytes(4, "little")
    return bytes(header)


class DetectorTests(unittest.TestCase):
    def setUp(self) -> None:
        self._temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self._temporary_directory.cleanup)
        self.root = Path(self._temporary_directory.name)

    def write_file(self, name: str, data: bytes) -> Path:
        path = self.root / name
        path.write_bytes(data)
        return path

    def analyze(self, name: str, data: bytes):
        path = self.write_file(name, data)
        return analyze_file(path, include_file_output=False)

    def test_png_with_matching_extension(self) -> None:
        analysis = self.analyze("photo.png", PNG_HEADER)
        self.assertEqual(analysis.detection.name, "PNG image")
        self.assertEqual(analysis.extension, "png")
        self.assertEqual(analysis.assessment.state, "MATCH")
        self.assertEqual(analysis.assessment.severity, "NONE")

    def test_extension_matching_is_case_insensitive(self) -> None:
        analysis = self.analyze("photo.PNG", PNG_HEADER)
        self.assertEqual(analysis.assessment.state, "MATCH")

    def test_elf_disguised_as_image(self) -> None:
        analysis = self.analyze("invoice.jpg", make_elf_header())
        self.assertEqual(
            analysis.detection.name, "ELF 64-bit LSB executable (x86-64)"
        )
        self.assertEqual(analysis.detection.category, "executable")
        self.assertEqual(analysis.assessment.state, "MISMATCH")
        self.assertEqual(analysis.assessment.severity, "HIGH")

    def test_pie_elf_is_distinguished_from_shared_object(self) -> None:
        analysis = self.analyze("program", make_pie_elf_header())
        self.assertEqual(
            analysis.detection.name,
            "ELF 64-bit LSB PIE executable (x86-64)",
        )

    def test_macho_header_is_refined(self) -> None:
        analysis = self.analyze("library.dylib", make_macho_header())
        self.assertEqual(
            analysis.detection.name,
            "Mach-O 64-bit dynamic library (ARM64)",
        )
        self.assertEqual(analysis.assessment.state, "MATCH")

    def test_pe_disguised_as_document(self) -> None:
        analysis = self.analyze("invoice.pdf", make_pe_header())
        self.assertEqual(
            analysis.detection.name, "Windows PE executable (x86-64)"
        )
        self.assertEqual(analysis.assessment.state, "MISMATCH")
        self.assertEqual(analysis.assessment.severity, "HIGH")

    def test_shell_script_disguised_as_image(self) -> None:
        analysis = self.analyze("holiday.png", SHELL_SCRIPT)
        self.assertEqual(analysis.detection.name, "Bash script")
        self.assertEqual(analysis.detection.category, "script")
        self.assertEqual(analysis.assessment.state, "MISMATCH")
        self.assertEqual(analysis.assessment.severity, "HIGH")

    def test_shell_script_with_matching_extension(self) -> None:
        analysis = self.analyze("multitool.sh", SHELL_SCRIPT)
        self.assertEqual(analysis.detection.category, "script")
        self.assertEqual(analysis.assessment.state, "MATCH")

    def test_plain_text_with_text_extension(self) -> None:
        analysis = self.analyze("notes.txt", b"Just a harmless note.\n")
        self.assertEqual(analysis.detection.category, "text")
        self.assertEqual(analysis.assessment.state, "MATCH")

    def test_plain_text_disguised_as_image(self) -> None:
        analysis = self.analyze("notes.jpg", b"Just a harmless note.\n")
        self.assertEqual(analysis.detection.category, "text")
        self.assertEqual(analysis.assessment.state, "MISMATCH")
        self.assertEqual(analysis.assessment.severity, "MEDIUM")

    def test_unknown_binary_is_inconclusive(self) -> None:
        analysis = self.analyze("mystery.jpg", b"\x00\x01\x02\x03\xff" * 20)
        self.assertEqual(analysis.detection.kind, "unknown")
        self.assertEqual(analysis.assessment.state, "INCONCLUSIVE")
        self.assertEqual(analysis.assessment.severity, "NONE")

    def test_empty_file_is_inconclusive(self) -> None:
        analysis = self.analyze("empty.jpg", b"")
        self.assertEqual(analysis.detection.name, "Empty file")
        self.assertEqual(analysis.assessment.state, "INCONCLUSIVE")

    def test_file_without_extension_is_not_flagged(self) -> None:
        analysis = self.analyze("image", PNG_HEADER)
        self.assertEqual(analysis.detection.name, "PNG image")
        self.assertEqual(analysis.assessment.state, "INCONCLUSIVE")
        self.assertIn("no extension", analysis.assessment.message)

    def test_bmp_structure_is_validated(self) -> None:
        text = b"BMW is a car, not a bitmap file at all.\n"
        analysis = self.analyze("notes.txt", text)
        self.assertEqual(analysis.detection.category, "text")
        self.assertNotEqual(analysis.detection.name, "BMP image")

    def test_valid_bmp_header(self) -> None:
        analysis = self.analyze("image.bmp", make_bmp_header())
        self.assertEqual(analysis.detection.name, "BMP image")
        self.assertEqual(analysis.assessment.state, "MATCH")

    def test_text_starting_with_mz_is_not_an_executable(self) -> None:
        text = b"MZ stands for the first two bytes here, but this is text.\n"
        analysis = self.analyze("notes.txt", text)
        self.assertEqual(analysis.detection.category, "text")

    def test_text_starting_with_id3_is_not_mp3(self) -> None:
        text = b"ID3 tags are metadata; this is not an audio file.\n"
        analysis = self.analyze("notes.txt", text)
        self.assertEqual(analysis.detection.category, "text")

    def test_text_with_com_extension_is_flagged(self) -> None:
        # EICAR-style test files are plain text despite the executable .com
        # extension. DOS COM files have no magic header to match.
        analysis = self.analyze(
            "eicar.com",
            b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$TEST-PAYLOAD!$H+H*",
        )
        self.assertEqual(analysis.detection.category, "text")
        self.assertEqual(analysis.extension, "com")
        self.assertEqual(analysis.assessment.state, "MISMATCH")
        self.assertEqual(analysis.assessment.severity, "MEDIUM")

    def test_text_with_txt_extension_is_not_flagged(self) -> None:
        analysis = self.analyze("eicar.txt", b"harmless text fixture\n")
        self.assertEqual(analysis.assessment.state, "MATCH")

    def test_docx_container_is_identified(self) -> None:
        path = self.root / "report.docx"
        with zipfile.ZipFile(path, "w") as archive:
            archive.writestr("[Content_Types].xml", "<Types/>")
            archive.writestr("word/document.xml", "<w:document/>")
        analysis = analyze_file(path, include_file_output=False)
        self.assertEqual(analysis.detection.name, "Microsoft Word document (DOCX)")
        self.assertEqual(analysis.assessment.state, "MATCH")

    def test_macro_enabled_word_document(self) -> None:
        path = self.root / "invoice.docm"
        with zipfile.ZipFile(path, "w") as archive:
            archive.writestr("word/document.xml", "<w:document/>")
            archive.writestr("word/vbaProject.bin", b"harmless placeholder")
        analysis = analyze_file(path, include_file_output=False)
        self.assertEqual(
            analysis.detection.name,
            "Microsoft Word macro-enabled document (DOCM)",
        )
        self.assertEqual(analysis.assessment.state, "MATCH")

    def test_versioned_shared_library_suffix(self) -> None:
        analysis = self.analyze("libdemo.so.1.2", make_elf_header())
        self.assertEqual(analysis.extension, "2")
        self.assertEqual(analysis.assessment.state, "MATCH")
        self.assertIn("Versioned shared-library", analysis.assessment.message)

    def test_generic_zip_falls_back_to_zip_archive(self) -> None:
        path = self.root / "bundle.zip"
        with zipfile.ZipFile(path, "w") as archive:
            archive.writestr("readme.txt", "harmless")
        analysis = analyze_file(path, include_file_output=False)
        self.assertEqual(analysis.detection.name, "ZIP archive")
        self.assertEqual(analysis.assessment.state, "MATCH")

    def test_java_class_is_identified(self) -> None:
        data = b"\xca\xfe\xba\xbe" + b"\x00\x00" + (61).to_bytes(2, "big")
        analysis = self.analyze("Example.class", data)
        self.assertEqual(analysis.detection.name, "Java class (major version 61)")
        self.assertEqual(analysis.assessment.state, "MATCH")

    def test_tar_signature_at_offset_257(self) -> None:
        archive = bytearray(1024)
        archive[257:262] = b"ustar"
        analysis = self.analyze("backup.tar", bytes(archive))
        self.assertEqual(analysis.detection.name, "TAR archive")
        self.assertEqual(analysis.assessment.state, "MATCH")

    def test_missing_file_raises_analysis_error(self) -> None:
        with self.assertRaises(AnalysisError):
            analyze_file(self.root / "missing.bin", include_file_output=False)

    def test_directory_raises_analysis_error(self) -> None:
        with self.assertRaises(AnalysisError):
            analyze_file(self.root, include_file_output=False)

    @unittest.skipUnless(os.name == "posix", "permission test requires POSIX")
    def test_unreadable_file_raises_analysis_error(self) -> None:
        if hasattr(os, "geteuid") and os.geteuid() == 0:
            self.skipTest("root can read mode-000 files")
        path = self.write_file("locked.bin", b"secret")
        path.chmod(0)
        self.addCleanup(path.chmod, 0o600)
        with self.assertRaises(AnalysisError):
            analyze_file(path, include_file_output=False)

    def test_hex_preview_is_truncated(self) -> None:
        preview = format_hex_preview(bytes(range(40)))
        self.assertEqual(preview, bytes(range(32)).hex() + "...")

    @unittest.skipUnless(shutil.which("file"), "system file command is unavailable")
    def test_file_command_is_used_as_secondary_check(self) -> None:
        path = self.write_file("notes.txt", b"plain text fixture\n")
        analysis = analyze_file(path, include_file_output=True)
        self.assertNotIn("not available", analysis.file_output)
        self.assertNotIn("could not run", analysis.file_output)
        self.assertIn("text", analysis.file_output.lower())


class CliTests(unittest.TestCase):
    def setUp(self) -> None:
        self._temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self._temporary_directory.cleanup)
        self.root = Path(self._temporary_directory.name)

    def test_one_shot_output_contains_verdict(self) -> None:
        path = self.root / "invoice.jpg"
        path.write_bytes(make_elf_header())
        result = subprocess.run(
            [
                sys.executable,
                str(PROJECT_ROOT / "file_type_identifier.py"),
                str(path),
                "--no-file",
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("---FILE TYPE IDENTIFIER---", result.stdout)
        self.assertIn("Raw hex:", result.stdout)
        self.assertIn("Verdict: MISMATCH", result.stdout)
        self.assertIn("Risk: HIGH", result.stdout)

    def test_one_shot_missing_file_returns_error(self) -> None:
        result = subprocess.run(
            [
                sys.executable,
                str(PROJECT_ROOT / "file_type_identifier.py"),
                str(self.root / "missing.bin"),
                "--no-file",
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 1)
        self.assertIn("Error: File does not exist", result.stderr)


if __name__ == "__main__":
    unittest.main()
