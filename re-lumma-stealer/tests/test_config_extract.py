"""Tests for tools/config_extract.py.

The extractor runs ONLY on synthetic blobs generated here, in memory, from a seeded test key and a
synthetic plaintext. No real key, config or sample is used or stored.

A passing round trip shows the parser matches the schema in ANALYSIS.md section 3.3 (our own layout).
It does not show anything about real Lumma blobs.
"""
import json
import struct

import pytest

import config_extract as cx
import gen_artifacts as ga

# Known-answer test: ChaCha20 with an all-zero key and nonce, first 64 keystream bytes.
# Source: the widely published ChaCha20 test vector for a zero key/IV (draft-strombergson-chacha-test-vectors,
# TC1, 256-bit key). Used to check the cipher call, not the schema.
ZERO_KEY_KEYSTREAM_HEX = (
    "76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc8b770dc7"
    "da41597c5157488d7724e03fb8d84a376a43b8f41518a11cc387b669b2ee6586"
)


def test_cipher_known_answer_zero_key():
    keystream = cx.chacha20_xor(bytes(32), bytes(8), bytes(64))
    assert keystream.hex() == ZERO_KEY_KEYSTREAM_HEX


def test_round_trip_recovers_synthetic_config():
    blob = ga.build_blob()
    assert cx.extract_config_json(blob) == ga.PLAINTEXT_CONFIG


def test_blob_layout_matches_documented_offsets():
    blob = ga.build_blob()
    key, nonce = ga.synthetic_key_nonce()
    assert blob[:16] == cx.TEST_MAGIC
    assert blob[16:48] == key and len(key) == 32
    assert blob[48:56] == nonce and len(nonce) == 8
    (length,) = struct.unpack("<I", blob[56:60])
    assert length == len(blob) - 60
    assert cx.HEADER_LEN == 60


def test_ciphertext_does_not_contain_plaintext():
    blob = ga.build_blob()
    assert b"c2-placeholder.example" not in blob


def test_blob_is_deterministic_and_seed_changes_it():
    assert ga.build_blob() == ga.build_blob()
    assert ga.build_blob(seed=1) != ga.build_blob(seed=2)


def test_parse_returns_the_parts():
    key, nonce, ciphertext = cx.parse_blob(ga.build_blob())
    assert (key, nonce) == ga.synthetic_key_nonce()
    assert cx.chacha20_xor(key, nonce, ciphertext) == json.dumps(ga.PLAINTEXT_CONFIG, sort_keys=True).encode()


@pytest.mark.parametrize("size", [0, 1, 59])
def test_short_blob_rejected(size):
    with pytest.raises(cx.ConfigBlobError, match="shorter than"):
        cx.parse_blob(bytes(size))


def test_wrong_magic_rejected():
    blob = bytearray(ga.build_blob())
    blob[0] ^= 0xFF
    with pytest.raises(cx.ConfigBlobError, match="magic mismatch"):
        cx.parse_blob(bytes(blob))


def test_real_looking_file_is_refused():
    """A file that is not a synthetic test blob (here, an MZ-header stand-in made of filler) is refused."""
    not_a_blob = b"MZ" + bytes(200)
    with pytest.raises(cx.ConfigBlobError, match="magic mismatch"):
        cx.parse_blob(not_a_blob)


def test_truncated_ciphertext_rejected():
    blob = ga.build_blob()
    with pytest.raises(cx.ConfigBlobError, match="present"):
        cx.parse_blob(blob[:-5])


def test_oversized_length_field_rejected():
    blob = bytearray(ga.build_blob())
    blob[56:60] = struct.pack("<I", cx.MAX_CIPHERTEXT + 1)
    with pytest.raises(cx.ConfigBlobError, match="exceeds"):
        cx.parse_blob(bytes(blob))


def test_bad_key_or_nonce_length_rejected():
    with pytest.raises(cx.ConfigBlobError, match="key must be"):
        cx.chacha20_xor(bytes(31), bytes(8), b"x")
    with pytest.raises(cx.ConfigBlobError, match="nonce must be"):
        cx.chacha20_xor(bytes(32), bytes(7), b"x")


def test_wrong_key_does_not_recover_config():
    key, nonce, ciphertext = cx.parse_blob(ga.build_blob())
    wrong = bytes(b ^ 1 for b in key)
    assert cx.chacha20_xor(wrong, nonce, ciphertext) != json.dumps(ga.PLAINTEXT_CONFIG, sort_keys=True).encode()


def test_cli_refuses_non_synthetic_file(tmp_path, capsys):
    path = tmp_path / "not_a_blob.bin"
    path.write_bytes(b"MZ" + bytes(200))
    assert cx.main([str(path)]) == 1
    assert "magic mismatch" in capsys.readouterr().err


def test_cli_decrypts_synthetic_blob(tmp_path, capsys):
    path = tmp_path / "synthetic.bin"
    path.write_bytes(ga.build_blob())
    assert cx.main([str(path)]) == 0
    assert json.loads(capsys.readouterr().out) == ga.PLAINTEXT_CONFIG
