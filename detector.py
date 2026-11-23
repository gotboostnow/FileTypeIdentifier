"""Content detection, extension checking, and secondary `file` integration."""

from __future__ import annotations

import codecs
import shutil
import subprocess
import zipfile
from dataclasses import dataclass
from pathlib import Path

from magic_signatures import (
    BINARY_EXTENSIONS,
    SIGNATURES,
    TEXT_EXTENSIONS,
    ZIP_CONTAINER_FORMATS,
    Signature,
    ZipContainerFormat,
)

HEADER_BYTES = 64 * 1024
HEX_PREVIEW_BYTES = 32
EXECUTABLE_CATEGORIES = frozenset({"executable", "script"})


class AnalysisError(Exception):
    """Raised when a file cannot be analyzed safely."""


@dataclass(frozen=True, slots=True)
class Detection:
    """The content type inferred from the file's header."""

    name: str
    mime: str
    category: str
    extensions: frozenset[str]
    confidence: str
    kind: str
    note: str = ""

    @property
    def is_executable(self) -> bool:
        return self.category in EXECUTABLE_CATEGORIES


@dataclass(frozen=True, slots=True)
class ExtensionAssessment:
    """How the filename extension relates to the detected content."""

    state: str
    severity: str
    message: str


@dataclass(frozen=True, slots=True)
class Analysis:
    """All results needed to render a report."""

    path: Path
    size: int
    header: bytes
    detection: Detection
    extension: str
    assessment: ExtensionAssessment
    file_output: str


_ELF_MACHINES = {
    3: "x86",
    8: "MIPS",
    20: "PowerPC",
    21: "PowerPC64",
    40: "ARM",
    62: "x86-64",
    183: "ARM64",
    243: "RISC-V",
}

_ELF_TYPES = {
    0: "file",
    1: "relocatable object",
    2: "executable",
    3: "shared object",
    4: "core dump",
}

_PE_MACHINES = {
    0x014C: "x86",
    0x01C0: "ARM",
    0x0200: "IA-64",
    0x8664: "x86-64",
    0xAA64: "ARM64",
}

_MACHO_CPUS = {
    7: "x86",
    12: "ARM",
    18: "PowerPC",
    0x01000007: "x86-64",
    0x0100000C: "ARM64",
    0x01000012: "PowerPC64",
}

_MACHO_FILETYPES = {
    1: "object file",
    2: "executable",
    6: "dynamic library",
    7: "dynamic linker",
    8: "bundle",
    9: "dynamic library stub",
    10: "debug symbols",
    11: "kernel extension",
}

_SHELL_EXTENSIONS = frozenset(
    {"sh", "bash", "zsh", "ksh", "dash", "ash", "fish", "bats"}
)

# command name -> (display name, MIME type, compatible extensions)
_SHEBANG_FORMATS: dict[str, tuple[str, str, frozenset[str]]] = {
    "sh": ("POSIX shell script", "text/x-shellscript", _SHELL_EXTENSIONS),
    "bash": ("Bash script", "text/x-shellscript", _SHELL_EXTENSIONS),
    "zsh": ("Zsh script", "text/x-shellscript", _SHELL_EXTENSIONS),
    "ksh": ("Korn shell script", "text/x-shellscript", _SHELL_EXTENSIONS),
    "dash": ("Dash script", "text/x-shellscript", _SHELL_EXTENSIONS),
    "ash": ("Ash script", "text/x-shellscript", _SHELL_EXTENSIONS),
    "fish": ("Fish script", "text/x-shellscript", _SHELL_EXTENSIONS),
    "python": ("Python script", "text/x-python", frozenset({"py", "pyw"})),
    "perl": ("Perl script", "text/x-perl", frozenset({"pl", "pm", "t"})),
    "ruby": ("Ruby script", "text/x-ruby", frozenset({"rb"})),
    "node": ("JavaScript / Node.js script", "text/javascript", frozenset({"js", "mjs", "cjs"})),
    "php": ("PHP script", "application/x-httpd-php", frozenset({"php", "phtml"})),
    "lua": ("Lua script", "text/x-lua", frozenset({"lua"})),
    "pwsh": ("PowerShell script", "text/x-powershell", frozenset({"ps1", "psm1", "psd1"})),
    "powershell": (
        "PowerShell script",
        "text/x-powershell",
        frozenset({"ps1", "psm1", "psd1"}),
    ),
    "tclsh": ("Tcl script", "text/x-tcl", frozenset({"tcl"})),
    "awk": ("AWK script", "text/x-awk", frozenset({"awk"})),
    "rscript": ("R script", "text/x-r", frozenset({"r"})),
}

_ALL_SCRIPT_EXTENSIONS = frozenset(
    extension
    for _, _, extensions in _SHEBANG_FORMATS.values()
    for extension in extensions
)


def analyze_file(
    path: str | Path,
    *,
    include_file_output: bool = True,
) -> Analysis:
    """Analyze one regular file without executing it.

    Only the first ``HEADER_BYTES`` are read for classification. The optional
    ``file`` command is used as a secondary cross-check, never as the primary
    detector.
    """
    file_path = Path(path).expanduser()
    if not file_path.exists():
        raise AnalysisError(f"File does not exist: {file_path}")
    if not file_path.is_file():
        raise AnalysisError(f"Path is not a regular file: {file_path}")

    try:
        with file_path.open("rb") as handle:
            header = handle.read(HEADER_BYTES)
            size = handle.seek(0, 2)
    except PermissionError as exc:
        raise AnalysisError(f"Permission denied: {file_path}") from exc
    except OSError as exc:
        raise AnalysisError(f"Could not read {file_path}: {exc}") from exc

    detection = detect_content(file_path, header)
    extension = file_path.suffix.lower().lstrip(".")
    assessment = assess_extension(extension, detection, filename=file_path.name)
    file_output = (
        run_file_command(file_path)
        if include_file_output
        else "Skipped (file command disabled)."
    )

    return Analysis(
        path=file_path,
        size=size,
        header=header,
        detection=detection,
        extension=extension,
        assessment=assessment,
        file_output=file_output,
    )


def detect_content(path: Path, header: bytes) -> Detection:
    """Identify content from the header bytes."""
    if not header:
        return Detection(
            name="Empty file",
            mime="application/x-empty",
            category="empty",
            extensions=frozenset(),
            confidence="high",
            kind="empty",
        )

    matches = [
        signature
        for signature in SIGNATURES
        if signature.matches(header)
        and (
            signature.validator is None
            or _validate_structure(signature.validator, header)
        )
    ]
    if matches:
        matched = max(
            matches,
            key=lambda item: sum(len(pattern) for _, pattern in item.patterns),
        )
        return _refine_signature(path, header, matched)

    decoded = _decode_text(header)
    if decoded is not None:
        return _classify_text(decoded)

    return Detection(
        name="Unknown binary",
        mime="application/octet-stream",
        category="unknown",
        extensions=frozenset(),
        confidence="low",
        kind="unknown",
    )


def _validate_structure(validator: str, header: bytes) -> bool:
    if validator == "bmp":
        return _looks_like_bmp(header)
    if validator == "ico":
        return _looks_like_ico(header)
    if validator == "mz":
        return _looks_like_mz(header)
    if validator == "id3":
        return _looks_like_id3(header)
    return True


def _looks_like_bmp(header: bytes) -> bool:
    if len(header) < 26 or header[:2] != b"BM":
        return False
    dib_size = int.from_bytes(header[14:18], "little")
    if dib_size not in {12, 16, 40, 52, 56, 64, 108, 124}:
        return False
    pixel_offset = int.from_bytes(header[10:14], "little")
    return pixel_offset >= 14 + dib_size


def _looks_like_ico(header: bytes) -> bool:
    if len(header) < 22 or header[:4] != b"\x00\x00\x01\x00":
        return False
    count = int.from_bytes(header[4:6], "little")
    return 1 <= count <= 256 and len(header) >= 6 + count * 16


def _looks_like_mz(header: bytes) -> bool:
    """Reject plain text that happens to begin with the two-byte MZ marker."""
    if len(header) < 64 or b"\x00" not in header[:64]:
        return False
    pe_offset = int.from_bytes(header[0x3C:0x40], "little")
    return pe_offset == 0 or pe_offset >= 0x40


def _looks_like_id3(header: bytes) -> bool:
    """Validate the ID3 header fields to avoid matching the text 'ID3'."""
    if len(header) < 10 or header[:3] != b"ID3":
        return False
    valid_flag_bits = {2: 0xC0, 3: 0xE0, 4: 0xF0}
    flags_mask = valid_flag_bits.get(header[3])
    if flags_mask is None or header[5] & ~flags_mask:
        return False
    return all(byte < 0x80 for byte in header[6:10])


def _refine_signature(path: Path, header: bytes, signature: Signature) -> Detection:
    if signature.key.startswith("zip_"):
        return _detect_zip(path, signature)
    if signature.key == "elf":
        return _detect_elf(header, signature)
    if signature.key == "mz":
        return _detect_pe(header, signature)
    if signature.key.startswith("macho"):
        return _detect_macho(header, signature)
    if signature.key == "cafebabe":
        return _detect_cafebabe(header, signature)
    if signature.key == "ole":
        return Detection(
            name=signature.name,
            mime=signature.mime,
            category=signature.category,
            extensions=signature.extensions,
            confidence=signature.confidence,
            kind="signature",
            note="The precise Office subtype requires deeper parsing.",
        )
    return Detection(
        name=signature.name,
        mime=signature.mime,
        category=signature.category,
        extensions=signature.extensions,
        confidence=signature.confidence,
        kind="signature",
    )


def _detect_elf(header: bytes, signature: Signature) -> Detection:
    name = "ELF executable"
    if len(header) >= 20:
        bitness = {1: "32-bit", 2: "64-bit"}.get(header[4], "unknown-width")
        byte_order = {1: "LSB", 2: "MSB"}.get(header[5])
        endian = "little" if byte_order == "LSB" else "big"
        elf_type = int.from_bytes(header[16:18], endian)
        machine_id = int.from_bytes(header[18:20], endian)
        type_label = _ELF_TYPES.get(elf_type, "binary")
        if elf_type == 3 and _elf_has_interpreter(header, endian, header[4] == 2):
            type_label = "PIE executable"
        machine = _ELF_MACHINES.get(machine_id)
        name = f"ELF {bitness} {byte_order or ''} {type_label}"
        name = name.replace("  ", " ").strip()
        if machine:
            name += f" ({machine})"
    return Detection(
        name=name,
        mime=signature.mime,
        category=signature.category,
        extensions=signature.extensions,
        confidence=signature.confidence,
        kind="signature",
    )


def _elf_has_interpreter(header: bytes, endian: str, is_64_bit: bool) -> bool:
    """Return True when a PT_INTERP program header marks ET_DYN as a PIE."""
    if is_64_bit:
        ph_offset = int.from_bytes(header[32:40], endian)
        entry_size = int.from_bytes(header[54:56], endian)
        entry_count = int.from_bytes(header[56:58], endian)
        minimum_entry_size = 56
    else:
        ph_offset = int.from_bytes(header[28:32], endian)
        entry_size = int.from_bytes(header[42:44], endian)
        entry_count = int.from_bytes(header[44:46], endian)
        minimum_entry_size = 32

    if entry_size < minimum_entry_size or entry_count > 1024:
        return False
    for index in range(entry_count):
        start = ph_offset + index * entry_size
        if start + 4 > len(header):
            break
        if int.from_bytes(header[start : start + 4], endian) == 3:  # PT_INTERP
            return True
    return False


def _detect_pe(header: bytes, signature: Signature) -> Detection:
    if len(header) >= 0x40:
        pe_offset = int.from_bytes(header[0x3C:0x40], "little")
        has_pe_header = (
            0 < pe_offset <= len(header) - 24
            and header[pe_offset : pe_offset + 4] == b"PE\x00\x00"
        )
        if has_pe_header:
            machine_id = int.from_bytes(header[pe_offset + 4 : pe_offset + 6], "little")
            characteristics = int.from_bytes(
                header[pe_offset + 22 : pe_offset + 24], "little"
            )
            kind = "DLL" if characteristics & 0x2000 else "executable"
            machine = _PE_MACHINES.get(machine_id, "unknown architecture")
            return Detection(
                name=f"Windows PE {kind} ({machine})",
                mime="application/vnd.microsoft.portable-executable",
                category=signature.category,
                extensions=signature.extensions,
                confidence="high",
                kind="signature",
            )
    return Detection(
        name="DOS MZ executable",
        mime=signature.mime,
        category=signature.category,
        extensions=signature.extensions,
        confidence="high",
        kind="signature",
        note="No valid PE header was found; this may be a DOS executable.",
    )


def _detect_macho(header: bytes, signature: Signature) -> Detection:
    little_endian = signature.key.endswith("_le")
    magic = header[:4]
    bitness = "64-bit" if magic in {b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe"} else "32-bit"
    cpu = None
    filetype = "executable"
    if len(header) >= 16:
        endian = "little" if little_endian else "big"
        cpu_id = int.from_bytes(header[4:8], endian)
        cpu = _MACHO_CPUS.get(cpu_id)
        filetype = _MACHO_FILETYPES.get(
            int.from_bytes(header[12:16], endian),
            "binary",
        )
    name = f"Mach-O {bitness} {filetype}"
    if cpu:
        name += f" ({cpu})"
    return Detection(
        name=name,
        mime=signature.mime,
        category=signature.category,
        extensions=signature.extensions,
        confidence="high",
        kind="signature",
    )


def _detect_cafebabe(header: bytes, signature: Signature) -> Detection:
    if len(header) >= 8:
        major = int.from_bytes(header[6:8], "big")
        if 45 <= major <= 100:
            return Detection(
                name=f"Java class (major version {major})",
                mime="application/java-vm",
                category="executable",
                extensions=frozenset({"class"}),
                confidence="high",
                kind="signature",
            )
        architecture_count = int.from_bytes(header[4:8], "big")
        if 1 <= architecture_count <= 32:
            return Detection(
                name="Mach-O universal binary",
                mime="application/x-mach-binary",
                category="executable",
                extensions=signature.extensions - frozenset({"class"}),
                confidence="high",
                kind="signature",
            )
    return Detection(
        name=signature.name,
        mime=signature.mime,
        category=signature.category,
        extensions=signature.extensions,
        confidence=signature.confidence,
        kind="signature",
        note="CAFEBABE is shared by Java class files and Mach-O universal binaries.",
    )


def _detect_zip(path: Path, signature: Signature) -> Detection:
    try:
        with zipfile.ZipFile(path) as archive:
            entries = {
                name.replace("\\", "/").lstrip("/")
                for name in archive.namelist()
            }
    except (
        OSError,
        ValueError,
        RuntimeError,
        NotImplementedError,
        zipfile.BadZipFile,
        zipfile.LargeZipFile,
    ):
        return _detection_from_zip_format(
            signature,
            note="ZIP header found, but archive entries could not be inspected.",
        )

    for container in ZIP_CONTAINER_FORMATS:
        if container.required_entries <= entries:
            return _detection_from_container(container)

    return _detection_from_zip_format(signature)


def _detection_from_container(container: ZipContainerFormat) -> Detection:
    return Detection(
        name=container.name,
        mime=container.mime,
        category=container.category,
        extensions=container.extensions,
        confidence="high",
        kind="signature",
    )


def _detection_from_zip_format(signature: Signature, note: str = "") -> Detection:
    return Detection(
        name=signature.name,
        mime=signature.mime,
        category=signature.category,
        extensions=signature.extensions,
        confidence=signature.confidence,
        kind="signature",
        note=note,
    )


def _decode_text(header: bytes) -> str | None:
    """Return decoded text when the sample looks textual, otherwise None."""
    if header.startswith(codecs.BOM_UTF8):
        text = _decode_sample(header[len(codecs.BOM_UTF8) :], "utf-8")
    elif header.startswith(codecs.BOM_UTF16_LE):
        text = _decode_sample(header[len(codecs.BOM_UTF16_LE) :], "utf-16-le")
    elif header.startswith(codecs.BOM_UTF16_BE):
        text = _decode_sample(header[len(codecs.BOM_UTF16_BE) :], "utf-16-be")
    elif b"\x00" in header:
        return None
    else:
        text = _decode_sample(header, "utf-8")
        if text is None:
            text = _decode_sample(header, "cp1252")

    if text is None or not text:
        return None
    printable = sum(
        1
        for char in text
        if char.isprintable() or char in "\n\r\t\f\b"
    )
    if printable / len(text) < 0.90:
        return None
    return text


def _decode_sample(data: bytes, encoding: str) -> str | None:
    """Decode a possibly truncated sample without rejecting a split character."""
    if not data:
        return ""
    try:
        decoder = codecs.getincrementaldecoder(encoding)("strict")
        return decoder.decode(data, final=False)
    except (UnicodeDecodeError, LookupError):
        return None


def _classify_text(text: str) -> Detection:
    if text.startswith("#!"):
        first_line = text.splitlines()[0]
        command = _shebang_command(first_line)
        if command:
            format_info = _lookup_shebang(command)
            if format_info:
                name, mime, extensions = format_info
                return Detection(
                    name=name,
                    mime=mime,
                    category="script",
                    extensions=extensions,
                    confidence="high",
                    kind="text",
                    note=f"Shebang interpreter: {command}",
                )
            return Detection(
                name=f"Script with shebang ({command})",
                mime="text/plain",
                category="script",
                extensions=_ALL_SCRIPT_EXTENSIONS,
                confidence="medium",
                kind="text",
                note=f"Unrecognized shebang interpreter: {command}",
            )

    return Detection(
        name="Text file (no magic signature)",
        mime="text/plain",
        category="text",
        extensions=TEXT_EXTENSIONS,
        confidence="medium",
        kind="text",
        note="No magic signature matched; this classification uses text heuristics.",
    )


def _shebang_command(first_line: str) -> str | None:
    parts = first_line[2:].strip().split()
    if not parts:
        return None
    command = parts[0].rsplit("/", 1)[-1]
    if command == "env":
        args = parts[1:]
        while args and (args[0].startswith("-") or "=" in args[0]):
            args.pop(0)
        if not args:
            return None
        command = args[0].rsplit("/", 1)[-1]
    return command


def _lookup_shebang(command: str) -> tuple[str, str, frozenset[str]] | None:
    normalized = command.lower()
    if normalized.startswith("python") or normalized.startswith("pypy"):
        return _SHEBANG_FORMATS["python"]
    if normalized.startswith("perl"):
        return _SHEBANG_FORMATS["perl"]
    if normalized.startswith("ruby"):
        return _SHEBANG_FORMATS["ruby"]
    if normalized.startswith("node"):
        return _SHEBANG_FORMATS["node"]
    if normalized.startswith("php"):
        return _SHEBANG_FORMATS["php"]
    return _SHEBANG_FORMATS.get(normalized)


def assess_extension(
    extension: str,
    detection: Detection,
    *,
    filename: str = "",
) -> ExtensionAssessment:
    """Compare a normalized extension with the detected content."""
    extension = extension.lower().lstrip(".")
    if detection.kind == "empty":
        return ExtensionAssessment(
            state="INCONCLUSIVE",
            severity="NONE",
            message="The file is empty, so there is no content signature to compare.",
        )

    if detection.kind == "unknown":
        return ExtensionAssessment(
            state="INCONCLUSIVE",
            severity="NONE",
            message="No known signature matched, so the extension cannot be verified.",
        )

    if not extension:
        return ExtensionAssessment(
            state="INCONCLUSIVE",
            severity="NONE",
            message="The file has no extension to compare.",
        )

    versioned_so = _is_versioned_shared_object(filename)
    match_extension = "so" if versioned_so else extension

    if detection.category == "text":
        if match_extension in BINARY_EXTENSIONS:
            reason = (
                f"Text content is not consistent with the shared-library "
                f"name {filename}."
                if versioned_so
                else f"Text content is not consistent with a .{extension} extension."
            )
            return ExtensionAssessment(
                state="MISMATCH",
                severity="MEDIUM",
                message=reason,
            )
        return ExtensionAssessment(
            state="MATCH",
            severity="NONE",
            message=f"Text content is compatible with a .{extension} extension.",
        )

    if match_extension in detection.extensions:
        if versioned_so:
            message = (
                f"Versioned shared-library name {filename} is consistent "
                f"with {detection.name}."
            )
        else:
            message = f".{extension} is a standard extension for {detection.name}."
        return ExtensionAssessment(
            state="MATCH",
            severity="NONE",
            message=message,
        )

    if detection.is_executable:
        return ExtensionAssessment(
            state="MISMATCH",
            severity="HIGH",
            message=(
                f"Executable or script content is hidden behind a .{extension} "
                "extension."
            ),
        )

    return ExtensionAssessment(
        state="MISMATCH",
        severity="MEDIUM",
        message=f".{extension} is not a standard extension for {detection.name}.",
    )


def _is_versioned_shared_object(filename: str) -> bool:
    """Match names such as libcrypto.so.3 or libfoo.so.1.2.0."""
    lower_name = filename.lower()
    marker = ".so."
    marker_index = lower_name.rfind(marker)
    if marker_index < 0:
        return False
    version_parts = lower_name[marker_index + len(marker) :].split(".")
    return bool(version_parts) and all(part.isdigit() for part in version_parts)


def run_file_command(path: str | Path, timeout: float = 5.0) -> str:
    """Run the system `file` utility safely, if it is available."""
    file_binary = shutil.which("file")
    if not file_binary:
        return "file command not available on this system."
    try:
        result = subprocess.run(
            [file_binary, "--", str(path)],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return f"file command timed out after {timeout:g} seconds."
    except OSError as exc:
        return f"file command could not run: {exc}"

    output = result.stdout.strip()
    if output:
        return output
    error = result.stderr.strip()
    return error or "file command returned no output."


def format_hex_preview(header: bytes, limit: int = HEX_PREVIEW_BYTES) -> str:
    """Return a compact lowercase hex preview of the file header."""
    if not header:
        return "(empty)"
    preview = header[:limit].hex()
    if len(header) > limit:
        preview += "..."
    return preview


def format_extensions(extensions: frozenset[str]) -> str:
    """Format an extension set for terminal output."""
    if not extensions:
        return "(none)"
    return ", ".join(f".{extension}" for extension in sorted(extensions))
