# steganography flag detector

A small CTF helper that scans challenge files and prints likely hidden flags/text.

## Supported inputs

- `.png` (metadata chunks + trailing data + embedded printable strings)
- `.tar` (including compressed tar variants readable by Python `tarfile`)
- `.wav` / audio byte streams (printable strings + basic LSB decode for WAV)
- `.rar` (raw string scan + optional archive extraction when `unrar`/`7z`/`bsdtar` exists)
- Other binary files (printable string extraction)

## Usage

```bash
python detector.py /path/to/challenge.png
python detector.py /path/to/challenge.rar --instructions /path/to/instructions.txt
```

If flags are found, the tool prints candidate values like `FLAG{...}` or `CTF{...}`.

The optional instructions file helps by adding custom format hints, for example:

- `flag format: picoCTF{...}`
- `prefix is HTB`
