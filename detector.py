#!/usr/bin/env python3
"""CTF steganography flag detector for common challenge files."""

from __future__ import annotations

import argparse
import io
import os
import re
import shutil
import string
import struct
import subprocess
import tarfile
import tempfile
import wave
from pathlib import Path
from typing import Iterable

PRINTABLE = set(bytes(string.printable, "ascii"))
DEFAULT_FLAG_PATTERNS = [
    re.compile(r"(?i)flag\{[^\r\n\}]{1,200}\}"),
    re.compile(r"(?i)ctf\{[^\r\n\}]{1,200}\}"),
    re.compile(r"(?i)[a-z0-9_\-]{2,32}\{[^\r\n\}]{1,200}\}"),
]


class Detector:
    def __init__(self, min_string_len: int = 4) -> None:
        self.min_string_len = min_string_len

    def detect(self, target_path: Path, instruction_path: Path | None = None) -> list[str]:
        instruction_text = ""
        if instruction_path:
            instruction_text = instruction_path.read_text(encoding="utf-8", errors="ignore")

        all_text = []
        all_text.extend(self._scan_path(target_path))
        all_text.extend(self._scan_bytes(target_path.read_bytes(), source=target_path.name))
        if instruction_text:
            all_text.append(instruction_text)

        return self._extract_candidates(all_text, instruction_text)

    def _scan_path(self, path: Path) -> list[str]:
        suffix = path.suffix.lower()

        if suffix in {".tar", ".tgz", ".gz", ".bz2", ".xz"} or path.name.endswith((".tar.gz", ".tar.bz2", ".tar.xz")):
            return self._scan_tar(path)
        if suffix == ".png":
            return self._scan_png(path)
        if suffix in {".wav"}:
            return self._scan_wav(path)
        if suffix == ".rar":
            return self._scan_rar(path)

        return []

    def _scan_tar(self, path: Path) -> list[str]:
        out: list[str] = []
        try:
            with tarfile.open(path, mode="r:*") as tf:
                for member in tf.getmembers():
                    if not member.isfile():
                        continue
                    file_obj = tf.extractfile(member)
                    if not file_obj:
                        continue
                    payload = file_obj.read()
                    out.extend(self._scan_bytes(payload, source=member.name))
                    out.extend(self._scan_bytes_for_format(member.name, payload))
        except (tarfile.TarError, OSError):
            pass
        return out

    def _scan_png(self, path: Path) -> list[str]:
        data = path.read_bytes()
        out: list[str] = []
        png_sig = b"\x89PNG\r\n\x1a\n"
        if not data.startswith(png_sig):
            return out

        cursor = len(png_sig)
        last_end = cursor
        while cursor + 12 <= len(data):
            length = struct.unpack(">I", data[cursor : cursor + 4])[0]
            ctype = data[cursor + 4 : cursor + 8]
            chunk_start = cursor + 8
            chunk_end = chunk_start + length
            crc_end = chunk_end + 4
            if crc_end > len(data):
                break
            chunk_data = data[chunk_start:chunk_end]

            if ctype in {b"tEXt", b"iTXt", b"zTXt"}:
                out.append(chunk_data.decode("utf-8", errors="ignore"))
            else:
                out.extend(self._scan_bytes(chunk_data, source=f"png:{ctype.decode('ascii', errors='ignore')}"))

            cursor = crc_end
            last_end = crc_end
            if ctype == b"IEND":
                break

        if last_end < len(data):
            out.extend(self._scan_bytes(data[last_end:], source="png_trailing_bytes"))
        return out

    def _scan_wav(self, path: Path) -> list[str]:
        out: list[str] = []
        try:
            with wave.open(str(path), "rb") as wav:
                frames = wav.readframes(wav.getnframes())
            out.extend(self._scan_bytes(frames, source="wav_frames"))
            out.extend(self._decode_lsb_stream(frames))
        except (wave.Error, OSError):
            pass
        return out

    def _scan_rar(self, path: Path) -> list[str]:
        out: list[str] = []
        out.extend(self._scan_bytes(path.read_bytes(), source="rar_raw"))

        tool_cmds = [["unrar", "x", "-inul", str(path)], ["7z", "x", "-y", str(path)], ["bsdtar", "-xf", str(path)]]
        for cmd in tool_cmds:
            if not shutil.which(cmd[0]):
                continue
            try:
                with tempfile.TemporaryDirectory() as tmpdir:
                    proc = subprocess.run(
                        cmd,
                        cwd=tmpdir,
                        check=False,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        timeout=10,
                    )
                    if proc.returncode != 0:
                        continue
                    for root, _, files in os.walk(tmpdir):
                        for f in files:
                            fp = Path(root) / f
                            payload = fp.read_bytes()
                            out.extend(self._scan_bytes(payload, source=f"rar:{f}"))
                            out.extend(self._scan_bytes_for_format(f, payload))
                    return out
            except (OSError, subprocess.SubprocessError):
                continue
        return out

    def _decode_lsb_stream(self, payload: bytes) -> list[str]:
        bits = [b & 1 for b in payload]
        out = bytearray()
        for i in range(0, len(bits) - 7, 8):
            byte = 0
            for bit in bits[i : i + 8]:
                byte = (byte << 1) | bit
            out.append(byte)
        decoded = bytes(out).split(b"\x00")[0]
        if not decoded:
            return []
        text = decoded.decode("utf-8", errors="ignore")
        return [text] if text else []

    def _scan_bytes_for_format(self, name: str, payload: bytes) -> list[str]:
        lower = name.lower()
        if lower.endswith(".png"):
            with tempfile.NamedTemporaryFile(suffix=".png") as tmp:
                tmp.write(payload)
                tmp.flush()
                return self._scan_png(Path(tmp.name))
        if lower.endswith(".wav"):
            with tempfile.NamedTemporaryFile(suffix=".wav") as tmp:
                tmp.write(payload)
                tmp.flush()
                return self._scan_wav(Path(tmp.name))
        return []

    def _scan_bytes(self, payload: bytes, source: str = "") -> list[str]:
        del source
        out: list[str] = []
        current = bytearray()
        for b in payload:
            if b in PRINTABLE and b not in {0x0b, 0x0c}:
                current.append(b)
            else:
                if len(current) >= self.min_string_len:
                    out.append(current.decode("utf-8", errors="ignore"))
                current = bytearray()
        if len(current) >= self.min_string_len:
            out.append(current.decode("utf-8", errors="ignore"))
        return out

    def _extract_candidates(self, chunks: Iterable[str], instruction_text: str = "") -> list[str]:
        patterns = list(DEFAULT_FLAG_PATTERNS)

        custom = self._extract_custom_patterns(instruction_text)
        patterns.extend(custom)

        found: set[str] = set()
        for chunk in chunks:
            for pattern in patterns:
                for match in pattern.findall(chunk):
                    value = match.strip()
                    if len(value) >= 4:
                        found.add(value)
        return sorted(found)

    def _extract_custom_patterns(self, instruction_text: str) -> list[re.Pattern[str]]:
        patterns: list[re.Pattern[str]] = []
        lowered = instruction_text.lower()

        # Example: "flag format: xyz{...}"
        format_match = re.search(r"flag\s*format\s*[:=]\s*([a-z0-9_\-]+)\{", lowered)
        if format_match:
            prefix = re.escape(format_match.group(1))
            patterns.append(re.compile(rf"(?i){prefix}\{{[^\r\n\}}]{{1,200}}\}}"))

        # Prefix hints like "prefix is CTF"
        prefix_match = re.search(r"prefix\s+(?:is|:)\s*([a-z0-9_\-]{2,32})", lowered)
        if prefix_match:
            prefix = re.escape(prefix_match.group(1))
            patterns.append(re.compile(rf"(?i){prefix}\{{[^\r\n\}}]{{1,200}}\}}"))

        return patterns


def main() -> int:
    parser = argparse.ArgumentParser(description="CTF steganography flag detector")
    parser.add_argument("target", type=Path, help="Challenge file (.png, .tar, .wav/audio, .rar, or other binary)")
    parser.add_argument(
        "-i",
        "--instructions",
        type=Path,
        help="Optional challenge instruction file to improve flag pattern detection",
    )
    args = parser.parse_args()

    if not args.target.exists():
        raise SystemExit(f"Target file not found: {args.target}")
    if args.instructions and not args.instructions.exists():
        raise SystemExit(f"Instruction file not found: {args.instructions}")

    detector = Detector()
    candidates = detector.detect(args.target, args.instructions)

    if not candidates:
        print("No obvious flag candidates found.")
        return 1

    print("Possible hidden text / flag candidates:")
    for c in candidates:
        print(f"- {c}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
