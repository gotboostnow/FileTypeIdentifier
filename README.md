# File Type Identifier

A defensive command-line tool that identifies a file from its **magic number
(header bytes)** rather than trusting its extension. It highlights cases where
the content and extension disagree, such as an ELF executable renamed to
`invoice.jpg` or a shell script renamed to `photo.png`.

This is a malware-analysis triage exercise, not an antivirus. It never executes
the file it examines.

## Features

- Reads at most the first 64 KiB of a regular file for signature matching.
- Shows the raw header bytes and detected type.
- Matches direct, offset-based, and structured signatures.
- Distinguishes ZIP-based formats such as DOCX, XLSX, PPTX, macro-enabled
  Office files, APK, JAR, EPUB, and ODF.
- Detects text files and shebang scripts (shell, Python, Perl, Ruby, Node.js,
  PHP, PowerShell, and more).
- Refines ELF (including PIE), PE, Mach-O, and Java class headers.
- Accepts versioned shared-library names such as `libcrypto.so.3`.
- Reports `MATCH`, `MISMATCH`, or `INCONCLUSIVE`, with `HIGH`/`MEDIUM`/`NONE` risk.
- Uses the system `file` command only as a secondary cross-check.
- Standard library only.

## Requirements

- Python 3.10 or newer.
- The system `file` command is optional. The tool still works without it.

The project was developed and tested with Python 3.14.6 and GNU file 5.48 on
Linux.

## Usage

Interactive mode:

```bash
python3 file_type_identifier.py
```

Analyze one file directly:

```bash
python3 file_type_identifier.py suspicious.jpg
```

Skip the system `file` cross-check:

```bash
python3 file_type_identifier.py suspicious.jpg --no-file
```

Make the script executable if desired:

```bash
chmod +x file_type_identifier.py
./file_type_identifier.py
```

Type `q` at the interactive path prompt to quit.

## Example output

```text
---FILE TYPE IDENTIFIER---

File: invoice.jpg
Size: 15,352 bytes

Magic Number Analysis:
Raw hex: 7f454c46020101000000000000000000...
Detected: ELF 64-bit LSB PIE executable (x86-64) [high confidence]
MIME type: application/x-elf

File extension: .jpg
Expected extensions: .bin, .elf, .ko, .o, .so
Verdict: MISMATCH
Risk: HIGH
Reason: Executable or script content is hidden behind a .jpg extension.

File command output:
invoice.jpg: ELF 64-bit LSB pie executable, x86-64, dynamically linked, ...

Note: Magic numbers identify content, not intent. Headers can be forged and
      polyglot files can match multiple formats. Use this as a triage signal,
      not as proof that a file is safe.
```

## Supported content

The signature table in `magic_signatures.py` covers:

| Category | Examples |
| --- | --- |
| Images | JPEG, PNG, GIF, BMP, TIFF, WebP, ICO |
| Documents | PDF, OLE/legacy Office, DOCX/DOCM, XLSX/XLSM, PPTX/PPTM, EPUB, ODF, RTF |
| Archives | ZIP, RAR, 7-Zip, gzip, bzip2, XZ, TAR |
| Executables | ELF, Windows PE/MZ, Mach-O, Java class, WebAssembly |
| Scripts | shebang-based shell, Python, Perl, Ruby, JavaScript, PHP, PowerShell |
| Media/data | SQLite, MP3 (ID3), MP4, Ogg, FLAC, WAV, AVI |

ZIP-derived formats are identified from the archive's central directory
without extracting any member files. The optional `file` utility may read more
of the file than this tool's 64 KiB signature sample.

## How it works

1. The path is validated and the file is opened in binary read-only mode.
2. Up to 64 KiB is read as the header sample.
3. The detector compares bytes against magic signatures, including signatures
   at non-zero offsets (for example, `ustar` at offset 257 in TAR files).
4. ZIP files are inspected for known internal entry names to identify their
   subtype.
5. If no binary signature matches, text heuristics check for printable content,
   BOMs, and shebang interpreters.
6. The detected content is compared with the filename extension.
7. The optional `file` command provides independent corroboration.

Magic signatures are evidence, not proof. An attacker can forge a header, and a
polyglot file can be valid in more than one format. Treat mismatches as a signal
to continue analysis in a sandbox.

## Extension verdicts

| Verdict | Meaning |
| --- | --- |
| `MATCH` | The extension is consistent with the detected content. |
| `MISMATCH` | Known content conflicts with the extension. |
| `INCONCLUSIVE` | Unknown content, an empty file, or no extension to compare. |

`HIGH` risk is reserved for executable or script content hidden behind an
inconsistent extension. Other known mismatches are `MEDIUM`. Unknown binary
content is not accused of being mismatched, because it may belong to a format
outside this signature table.

Text content carrying an executable or binary-only extension is flagged. This
includes `.com`: classic DOS COM executables have no magic header, but the
extension is still executable-only. An EICAR test string saved as `eicar.com`
is therefore detected as text with a `MISMATCH` result, while the `file`
cross-check identifies it as an EICAR test file.

## Tests

```bash
python3 -m unittest discover -v
```

The tests create harmless temporary fixtures, including a synthetic ELF header
renamed to `.jpg`, a PE header renamed to `.pdf`, a shebang script renamed to
`.png`, a valid PNG, DOCX and macro-enabled DOCM containers, unknown binary
data, versioned shared-library names, and invalid input.

## Limitations

- The signature table is intentionally limited and is not a complete file-format
  database.
- DOS `.com` files have no magic number, so their content type cannot be
  confirmed from the header. Only the extension conflict can be reported.
- EICAR is not detected as a distinct file format because it is plain ASCII and
  has no magic number. The optional `file` command may still identify it.
- Compressed or encrypted content is not decompressed or inspected recursively.
- Text detection is heuristic and can be fooled by non-UTF-8 encodings or
  crafted byte distributions.
- No entropy analysis, hashing, YARA rules, sandbox execution, or reputation
  lookup is performed.
- A matching magic number does not establish that a file is safe.
- The tool should be used on files you are authorized to inspect.

## Project layout

```text
.
├── file_type_identifier.py   # CLI and report formatting
├── detector.py               # Header matching, text detection, verdicts
├── magic_signatures.py       # Typed signature and ZIP-container tables
├── tests/
│   ├── __init__.py
│   └── test_detector.py
└── README.md
```
