"""ChaCha20 config-structure parser for the SYNTHETIC blob schema in ANALYSIS.md section 3.3.

*** This tool is for synthetic test blobs only. ***
It must never be pointed at a real sample, and it is built so that it will not read one:
  * it accepts only a blob that starts with the test-only magic below, and
  * the real Lumma magic is unknown to this repository [U], so it cannot match a real file.
CI runs it only on blobs that the tests generate in memory, with a key made inside the test run.

Schema (ours, analyst-derived [A]; only the SIZES of magic, key and nonce are published [V: eSentire
TRU, 2025-01-23]. Order, the length field and the magic value are our own choices):

    offset  size  field
    0       16    magic       (test-only value, TEST_MAGIC)
    16      32    key         (KEY_LEN)
    48      8     nonce       (NONCE_LEN)
    56      4     length of the ciphertext, little-endian
    60      n     ChaCha20 ciphertext

ChaCha20 here is the original construction: a 64-bit counter starting at 0 and an 8-byte nonce
(the library's 16-byte nonce is the 8-byte counter followed by the 8-byte nonce). eSentire says the
8-byte nonce "is padded with four null bytes"; where the padding sits is not published [U], and this
layout is one consistent reading of it [A].

Proving that a parser round-trips this schema proves the parser matches this schema. It says nothing
about the layout of real Lumma configs.
"""
import json
import struct
import sys

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms

TEST_MAGIC = b"SYNTHETIC-MAGIC!"  # 16 bytes, test-only, not a real Lumma value
MAGIC_LEN = 16
KEY_LEN = 32
NONCE_LEN = 8
LENGTH_LEN = 4
HEADER_LEN = MAGIC_LEN + KEY_LEN + NONCE_LEN + LENGTH_LEN
MAX_CIPHERTEXT = 1 << 20  # 1 MiB cap, so a bad length field cannot ask for gigabytes


class ConfigBlobError(ValueError):
    """The blob is not a well-formed synthetic test blob."""


def chacha20_xor(key, nonce8, data):
    """ChaCha20 (64-bit counter at 0, 8-byte nonce). Encryption and decryption are the same operation."""
    if len(key) != KEY_LEN:
        raise ConfigBlobError(f"key must be {KEY_LEN} bytes, got {len(key)}")
    if len(nonce8) != NONCE_LEN:
        raise ConfigBlobError(f"nonce must be {NONCE_LEN} bytes, got {len(nonce8)}")
    full_nonce = (0).to_bytes(8, "little") + nonce8
    return Cipher(algorithms.ChaCha20(key, full_nonce), mode=None).encryptor().update(data)


def parse_blob(blob, expected_magic=TEST_MAGIC):
    """Split a blob into (key, nonce, ciphertext). Raises ConfigBlobError on any structural problem."""
    if len(blob) < HEADER_LEN:
        raise ConfigBlobError(f"blob is {len(blob)} bytes, shorter than the {HEADER_LEN}-byte header")
    if blob[:MAGIC_LEN] != expected_magic:
        raise ConfigBlobError("magic mismatch: refusing to parse a blob that is not a synthetic test blob")
    key = blob[MAGIC_LEN:MAGIC_LEN + KEY_LEN]
    nonce = blob[MAGIC_LEN + KEY_LEN:MAGIC_LEN + KEY_LEN + NONCE_LEN]
    (length,) = struct.unpack("<I", blob[HEADER_LEN - LENGTH_LEN:HEADER_LEN])
    if length > MAX_CIPHERTEXT:
        raise ConfigBlobError(f"ciphertext length {length} exceeds the {MAX_CIPHERTEXT}-byte cap")
    ciphertext = blob[HEADER_LEN:HEADER_LEN + length]
    if len(ciphertext) != length:
        raise ConfigBlobError(f"length field says {length} bytes but {len(ciphertext)} are present")
    return key, nonce, ciphertext


def decrypt_config(blob, expected_magic=TEST_MAGIC):
    """Return the decrypted config bytes of a synthetic blob."""
    key, nonce, ciphertext = parse_blob(blob, expected_magic)
    return chacha20_xor(key, nonce, ciphertext)


def extract_config_json(blob, expected_magic=TEST_MAGIC):
    """Decrypt and parse the config as JSON."""
    return json.loads(decrypt_config(blob, expected_magic).decode("utf-8"))


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if len(argv) != 1:
        print("usage: config_extract.py <synthetic-blob-file>\nSynthetic test blobs only.", file=sys.stderr)
        return 2
    with open(argv[0], "rb") as fh:
        blob = fh.read(HEADER_LEN + MAX_CIPHERTEXT + 1)
    try:
        print(json.dumps(extract_config_json(blob), indent=2))
    except ConfigBlobError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
