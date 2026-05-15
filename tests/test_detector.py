import io
import struct
import tarfile
import tempfile
import unittest
import wave
import zlib
import base64
from pathlib import Path

from detector import Detector


def _png_chunk(chunk_type: bytes, data: bytes) -> bytes:
    crc = zlib.crc32(chunk_type + data) & 0xFFFFFFFF
    return struct.pack(">I", len(data)) + chunk_type + data + struct.pack(">I", crc)


def _build_png_with_text(text: str) -> bytes:
    sig = b"\x89PNG\r\n\x1a\n"
    ihdr = _png_chunk(b"IHDR", struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0))
    txt = _png_chunk(b"tEXt", f"comment\x00{text}".encode())
    iend = _png_chunk(b"IEND", b"")
    return sig + ihdr + txt + iend


def _wav_lsb_payload(text: str, length: int = 2000) -> bytes:
    bits = []
    for b in text.encode() + b"\x00":
        bits.extend([(b >> shift) & 1 for shift in range(7, -1, -1)])
    frames = bytearray(length)
    for i, bit in enumerate(bits):
        frames[i] = (frames[i] & 0xFE) | bit
    return bytes(frames)


class DetectorTests(unittest.TestCase):
    def test_detects_flag_in_png_text_chunk(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "challenge.png"
            path.write_bytes(_build_png_with_text("FLAG{PNG_HIDDEN}"))
            flags = Detector().detect(path)
            self.assertIn("FLAG{PNG_HIDDEN}", flags)

    def test_detects_flag_inside_tar_member(self):
        with tempfile.TemporaryDirectory() as tmp:
            tar_path = Path(tmp) / "challenge.tar"
            with tarfile.open(tar_path, mode="w") as tf:
                data = b"hello CTF{TAR_SECRET} world"
                info = tarfile.TarInfo(name="note.txt")
                info.size = len(data)
                tf.addfile(info, io.BytesIO(data))

            flags = Detector().detect(tar_path)
            self.assertIn("CTF{TAR_SECRET}", flags)

    def test_detects_flag_from_wav_lsb(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "challenge.wav"
            frames = _wav_lsb_payload("FLAG{WAV_LSB}")
            with wave.open(str(path), "wb") as wav:
                wav.setnchannels(1)
                wav.setsampwidth(1)
                wav.setframerate(8000)
                wav.writeframes(frames)

            flags = Detector().detect(path)
            self.assertIn("FLAG{WAV_LSB}", flags)

    def test_detects_base64_encoded_flag_in_binary(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "challenge.bin"
            encoded = base64.b64encode(b"FLAG{B64_HIDDEN}")
            path.write_bytes(b"noise " + encoded + b" more-noise")

            flags = Detector().detect(path)
            self.assertIn("FLAG{B64_HIDDEN}", flags)

    def test_detects_hex_encoded_flag_in_binary(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "challenge.bin"
            encoded = b"4354467b4845585f5345435245547d"  # CTF{HEX_SECRET}
            path.write_bytes(b"xx " + encoded + b" yy")

            flags = Detector().detect(path)
            self.assertIn("CTF{HEX_SECRET}", flags)

    def test_detects_utf16le_flag_in_binary(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "challenge.bin"
            path.write_bytes("xxFLAG{UTF16_SECRET}yy".encode("utf-16le"))

            flags = Detector().detect(path)
            self.assertIn("FLAG{UTF16_SECRET}", flags)

    def test_ignores_odd_length_hex_tokens(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "challenge.bin"
            # Odd-length hex token should be ignored.
            path.write_bytes(b"xx 4354467b4845585f5345435245547 yy")

            flags = Detector().detect(path)
            self.assertNotIn("CTF{HEX_SECRET}", flags)


if __name__ == "__main__":
    unittest.main()
