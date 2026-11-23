"""Known file signatures used for content-based file identification.

A signature is one or more byte patterns at fixed offsets. Most formats place
their magic number at offset 0, but formats such as TAR, MP4, and RIFF use
other offsets. Keeping this information in one typed table makes the detector
easy to audit and extend.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class Signature:
    """A byte-level signature and the metadata for the matching format."""

    key: str
    name: str
    mime: str
    category: str
    extensions: frozenset[str]
    patterns: tuple[tuple[int, bytes], ...]
    confidence: str = "high"
    minimum_size: int = 0
    # Structural checks that need more than a fixed byte pattern.
    validator: str | None = None

    def matches(self, header: bytes) -> bool:
        """Return True when every required pattern is present."""
        if len(header) < self.minimum_size:
            return False
        return all(
            header[offset : offset + len(pattern)] == pattern
            for offset, pattern in self.patterns
        )


@dataclass(frozen=True, slots=True)
class ZipContainerFormat:
    """A ZIP-based format identified by entries in the archive directory."""

    name: str
    mime: str
    category: str
    extensions: frozenset[str]
    required_entries: frozenset[str]


def _extensions(*values: str) -> frozenset[str]:
    return frozenset(values)


JPEG_EXTENSIONS = _extensions("jpg", "jpeg", "jpe", "jfif")
PNG_EXTENSIONS = _extensions("png")
GIF_EXTENSIONS = _extensions("gif")
BMP_EXTENSIONS = _extensions("bmp", "dib")
TIFF_EXTENSIONS = _extensions("tif", "tiff")
WEBP_EXTENSIONS = _extensions("webp")
ICO_EXTENSIONS = _extensions("ico")
PDF_EXTENSIONS = _extensions("pdf")
OLE_EXTENSIONS = _extensions(
    "doc", "dot", "xls", "xlt", "ppt", "pot", "pps", "msi", "msg", "vsd"
)

ELF_EXTENSIONS = _extensions("elf", "so", "o", "bin", "ko")
PE_EXTENSIONS = _extensions("exe", "dll", "sys", "scr", "cpl", "ocx", "efi")
MACHO_EXTENSIONS = _extensions("macho", "dylib", "bundle", "o", "bin")
JAVA_CLASS_EXTENSIONS = _extensions("class")

# All of these are ZIP containers. A more specific subtype is selected when
# the archive directory contains the expected entries.
ZIP_EXTENSIONS = _extensions(
    "zip",
    "zipx",
    "jar",
    "apk",
    "docx",
    "xlsx",
    "pptx",
    "odt",
    "ods",
    "odp",
    "odg",
    "epub",
    "whl",
    "xpi",
    "docm",
    "xlsm",
    "pptm",
)


def _sig(
    key: str,
    name: str,
    mime: str,
    category: str,
    extensions: frozenset[str],
    *patterns: tuple[int, bytes],
    confidence: str = "high",
    minimum_size: int = 0,
    validator: str | None = None,
) -> Signature:
    return Signature(
        key=key,
        name=name,
        mime=mime,
        category=category,
        extensions=extensions,
        patterns=tuple(patterns),
        confidence=confidence,
        minimum_size=minimum_size,
        validator=validator,
    )


SIGNATURES: tuple[Signature, ...] = (
    _sig("jpeg", "JPEG image", "image/jpeg", "image", JPEG_EXTENSIONS, (0, b"\xff\xd8\xff")),
    _sig("png", "PNG image", "image/png", "image", PNG_EXTENSIONS, (0, b"\x89PNG\r\n\x1a\n")),
    _sig("gif87a", "GIF image", "image/gif", "image", GIF_EXTENSIONS, (0, b"GIF87a")),
    _sig("gif89a", "GIF image", "image/gif", "image", GIF_EXTENSIONS, (0, b"GIF89a")),
    _sig(
        "bmp",
        "BMP image",
        "image/bmp",
        "image",
        BMP_EXTENSIONS,
        (0, b"BM"),
        confidence="medium",
        minimum_size=26,
        validator="bmp",
    ),
    _sig("tiff_le", "TIFF image", "image/tiff", "image", TIFF_EXTENSIONS, (0, b"II*\x00")),
    _sig("tiff_be", "TIFF image", "image/tiff", "image", TIFF_EXTENSIONS, (0, b"MM\x00*")),
    _sig(
        "webp",
        "WebP image",
        "image/webp",
        "image",
        WEBP_EXTENSIONS,
        (0, b"RIFF"),
        (8, b"WEBP"),
        minimum_size=12,
    ),
    _sig(
        "ico",
        "ICO icon",
        "image/x-icon",
        "image",
        ICO_EXTENSIONS,
        (0, b"\x00\x00\x01\x00"),
        confidence="medium",
        minimum_size=22,
        validator="ico",
    ),
    _sig("pdf", "PDF document", "application/pdf", "document", PDF_EXTENSIONS, (0, b"%PDF-")),
    _sig(
        "ole",
        "OLE compound document (legacy Microsoft Office)",
        "application/x-ole-storage",
        "document",
        OLE_EXTENSIONS,
        (0, b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"),
    ),
    _sig(
        "zip_local",
        "ZIP archive",
        "application/zip",
        "archive",
        ZIP_EXTENSIONS,
        (0, b"PK\x03\x04"),
    ),
    _sig(
        "zip_empty",
        "ZIP archive",
        "application/zip",
        "archive",
        ZIP_EXTENSIONS,
        (0, b"PK\x05\x06"),
    ),
    _sig(
        "zip_spanned",
        "ZIP archive",
        "application/zip",
        "archive",
        ZIP_EXTENSIONS,
        (0, b"PK\x07\x08"),
    ),
    _sig(
        "rar4",
        "RAR archive",
        "application/vnd.rar",
        "archive",
        _extensions("rar"),
        (0, b"Rar!\x1a\x07\x00"),
        minimum_size=8,
    ),
    _sig(
        "rar5",
        "RAR archive",
        "application/vnd.rar",
        "archive",
        _extensions("rar"),
        (0, b"Rar!\x1a\x07\x01\x00"),
        minimum_size=8,
    ),
    _sig(
        "seven_zip",
        "7-Zip archive",
        "application/x-7z-compressed",
        "archive",
        _extensions("7z"),
        (0, b"7z\xbc\xaf\x27\x1c"),
        minimum_size=6,
    ),
    _sig(
        "gzip",
        "gzip compressed data",
        "application/gzip",
        "archive",
        _extensions("gz", "tgz", "gzip"),
        (0, b"\x1f\x8b\x08"),
        minimum_size=3,
    ),
    _sig(
        "bzip2",
        "bzip2 compressed data",
        "application/x-bzip2",
        "archive",
        _extensions("bz2", "tbz", "tbz2"),
        (0, b"BZh"),
        (4, b"\x31\x41\x59\x26\x53\x59"),
        minimum_size=10,
    ),
    _sig(
        "xz",
        "XZ compressed data",
        "application/x-xz",
        "archive",
        _extensions("xz", "txz"),
        (0, b"\xfd7zXZ\x00"),
        minimum_size=6,
    ),
    _sig(
        "tar",
        "TAR archive",
        "application/x-tar",
        "archive",
        _extensions("tar"),
        (257, b"ustar"),
        minimum_size=262,
    ),
    _sig(
        "elf",
        "ELF executable",
        "application/x-elf",
        "executable",
        ELF_EXTENSIONS,
        (0, b"\x7fELF"),
        minimum_size=16,
    ),
    _sig(
        "mz",
        "DOS/Windows executable",
        "application/x-dosexec",
        "executable",
        PE_EXTENSIONS,
        (0, b"MZ"),
        minimum_size=64,
        validator="mz",
    ),
    _sig(
        "macho32_be",
        "Mach-O 32-bit binary",
        "application/x-mach-binary",
        "executable",
        MACHO_EXTENSIONS,
        (0, b"\xfe\xed\xfa\xce"),
        minimum_size=8,
    ),
    _sig(
        "macho32_le",
        "Mach-O 32-bit binary",
        "application/x-mach-binary",
        "executable",
        MACHO_EXTENSIONS,
        (0, b"\xce\xfa\xed\xfe"),
        minimum_size=8,
    ),
    _sig(
        "macho64_be",
        "Mach-O 64-bit binary",
        "application/x-mach-binary",
        "executable",
        MACHO_EXTENSIONS,
        (0, b"\xfe\xed\xfa\xcf"),
        minimum_size=8,
    ),
    _sig(
        "macho64_le",
        "Mach-O 64-bit binary",
        "application/x-mach-binary",
        "executable",
        MACHO_EXTENSIONS,
        (0, b"\xcf\xfa\xed\xfe"),
        minimum_size=8,
    ),
    _sig(
        "cafebabe",
        "Java class or Mach-O universal binary",
        "application/java-vm",
        "executable",
        JAVA_CLASS_EXTENSIONS | MACHO_EXTENSIONS,
        (0, b"\xca\xfe\xba\xbe"),
        confidence="medium",
        minimum_size=8,
    ),
    _sig(
        "wasm",
        "WebAssembly binary",
        "application/wasm",
        "executable",
        _extensions("wasm"),
        (0, b"\x00asm"),
        minimum_size=8,
    ),
    _sig(
        "sqlite",
        "SQLite database",
        "application/vnd.sqlite3",
        "data",
        _extensions("sqlite", "sqlite3", "db", "db3"),
        (0, b"SQLite format 3\x00"),
        minimum_size=16,
    ),
    _sig(
        "mp3_id3",
        "MP3 audio (ID3 tag)",
        "audio/mpeg",
        "media",
        _extensions("mp3"),
        (0, b"ID3"),
        confidence="medium",
        minimum_size=10,
        validator="id3",
    ),
    _sig(
        "mp4",
        "ISO media / MP4",
        "video/mp4",
        "media",
        _extensions("mp4", "m4v", "m4a", "mov"),
        (4, b"ftyp"),
        confidence="medium",
        minimum_size=12,
    ),
    _sig(
        "ogg",
        "Ogg media",
        "application/ogg",
        "media",
        _extensions("ogg", "oga", "ogv", "opus"),
        (0, b"OggS"),
        minimum_size=4,
    ),
    _sig(
        "flac",
        "FLAC audio",
        "audio/flac",
        "media",
        _extensions("flac"),
        (0, b"fLaC"),
        minimum_size=4,
    ),
    _sig(
        "wav",
        "WAV audio",
        "audio/wav",
        "media",
        _extensions("wav"),
        (0, b"RIFF"),
        (8, b"WAVE"),
        minimum_size=12,
    ),
    _sig(
        "avi",
        "AVI video",
        "video/x-msvideo",
        "media",
        _extensions("avi"),
        (0, b"RIFF"),
        (8, b"AVI "),
        minimum_size=12,
    ),
    _sig(
        "rtf",
        "RTF document",
        "application/rtf",
        "document",
        _extensions("rtf"),
        (0, b"{\\rtf"),
        minimum_size=5,
    ),
)

ZIP_CONTAINER_FORMATS: tuple[ZipContainerFormat, ...] = (
    ZipContainerFormat(
        name="Android package (APK)",
        mime="application/vnd.android.package-archive",
        category="executable",
        extensions=_extensions("apk"),
        required_entries=frozenset({"AndroidManifest.xml", "classes.dex"}),
    ),
    ZipContainerFormat(
        name="Microsoft Word macro-enabled document (DOCM)",
        mime="application/vnd.ms-word.document.macroEnabled.12",
        category="document",
        extensions=_extensions("docm"),
        required_entries=frozenset({"word/document.xml", "word/vbaProject.bin"}),
    ),
    ZipContainerFormat(
        name="Microsoft Word document (DOCX)",
        mime="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        category="document",
        extensions=_extensions("docx"),
        required_entries=frozenset({"word/document.xml"}),
    ),
    ZipContainerFormat(
        name="Microsoft Excel macro-enabled workbook (XLSM)",
        mime="application/vnd.ms-excel.sheet.macroEnabled.12",
        category="document",
        extensions=_extensions("xlsm"),
        required_entries=frozenset({"xl/workbook.xml", "xl/vbaProject.bin"}),
    ),
    ZipContainerFormat(
        name="Microsoft Excel workbook (XLSX)",
        mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        category="document",
        extensions=_extensions("xlsx"),
        required_entries=frozenset({"xl/workbook.xml"}),
    ),
    ZipContainerFormat(
        name="Microsoft PowerPoint macro-enabled presentation (PPTM)",
        mime="application/vnd.ms-powerpoint.presentation.macroEnabled.12",
        category="document",
        extensions=_extensions("pptm"),
        required_entries=frozenset({"ppt/presentation.xml", "ppt/vbaProject.bin"}),
    ),
    ZipContainerFormat(
        name="Microsoft PowerPoint presentation (PPTX)",
        mime="application/vnd.openxmlformats-officedocument.presentationml.presentation",
        category="document",
        extensions=_extensions("pptx"),
        required_entries=frozenset({"ppt/presentation.xml"}),
    ),
    ZipContainerFormat(
        name="EPUB e-book",
        mime="application/epub+zip",
        category="document",
        extensions=_extensions("epub"),
        required_entries=frozenset({"META-INF/container.xml", "mimetype"}),
    ),
    ZipContainerFormat(
        name="OpenDocument file (ODF)",
        mime="application/vnd.oasis.opendocument",
        category="document",
        extensions=_extensions("odt", "ods", "odp", "odg", "odf"),
        required_entries=frozenset({"META-INF/manifest.xml", "content.xml"}),
    ),
    ZipContainerFormat(
        name="Java archive (JAR)",
        mime="application/java-archive",
        category="executable",
        extensions=_extensions("jar"),
        required_entries=frozenset({"META-INF/MANIFEST.MF"}),
    ),
)

TEXT_EXTENSIONS = _extensions(
    "txt",
    "text",
    "md",
    "markdown",
    "rst",
    "log",
    "csv",
    "tsv",
    "ini",
    "cfg",
    "conf",
    "config",
    "toml",
    "yaml",
    "yml",
    "json",
    "jsonl",
    "xml",
    "html",
    "htm",
    "xhtml",
    "svg",
    "sql",
    "sh",
    "bash",
    "zsh",
    "ksh",
    "dash",
    "fish",
    "py",
    "pyw",
    "pl",
    "pm",
    "rb",
    "js",
    "mjs",
    "cjs",
    "ts",
    "tsx",
    "jsx",
    "php",
    "lua",
    "ps1",
    "psm1",
    "psd1",
    "bat",
    "cmd",
    "awk",
    "tcl",
    "r",
    "rtf",
    "properties",
    "tex",
)

_binary_extensions: set[str] = set()
for _signature in SIGNATURES:
    _binary_extensions.update(_signature.extensions)
for _container in ZIP_CONTAINER_FORMATS:
    _binary_extensions.update(_container.extensions)

# DOS COM executables have no magic header, so they cannot be identified from
# their content alone. The extension is still executable-only, which lets the
# verdict logic flag text (including the EICAR test string) saved as .com.
_binary_extensions.update({"com"})

# Extensions that are clearly meant for non-text content. A plain-text file
# carrying one of these extensions is a meaningful mismatch.
BINARY_EXTENSIONS = frozenset(_binary_extensions - TEXT_EXTENSIONS)

assert len({signature.key for signature in SIGNATURES}) == len(SIGNATURES)

