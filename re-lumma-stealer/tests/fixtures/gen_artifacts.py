"""Synthetic byte fixtures for the YARA rules and the config extractor.

Safety rules (BLUEPRINT.md section 3):
  * Fixtures are NON-EXECUTABLE. They are filler bytes with a rule's own indicator strings placed in them.
    No fixture has a PE or other executable header.
  * Nothing here comes from a sample. The indicator strings are the ones the rules themselves contain.
  * Blobs and keys are generated at TEST TIME from a fixed seed and a synthetic plaintext. No real key
    or config is stored in the repo. Test keys are not reused outside the tests.
"""
import json
import random
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools"))
import config_extract as cx  # noqa: E402

SEED = 20261122
FILLER_LEN = 2048

# Indicator strings of re_lumma_config_strings.yar (see that file for the basis).
CONFIG_CMD = [b"receive_message", b"send_message", b"get_message"]
CONFIG_VER = b"ver=4.0"
CONFIG_PARAMS = [b"hwid=", b"lid=", b"uid="]
# Indicator strings of re_lumma_chacha_setup.yar.
SETUP_CONST = b"expand 32-byte k"
SETUP_DLL = b"winhttp.dll"
SETUP_OPEN = b"WinHttpOpen"


def _filler(rng, n=FILLER_LEN):
    """Printable-ASCII filler with no MZ header. Letters and digits only, so it holds no indicator by chance."""
    alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    return bytes(rng.choice(alphabet) for _ in range(n))


def _embed(rng, strings):
    """Filler with each string dropped in at a seeded position, separated by filler."""
    parts = []
    for s in strings:
        parts.append(_filler(rng, rng.randint(16, 64)))
        parts.append(s)
    parts.append(_filler(rng, 64))
    return b"".join(parts)


def config_strings_fixtures():
    """name -> (bytes, expected_match) for re_lumma_config_strings.yar."""
    rng = random.Random(SEED)
    full = CONFIG_CMD + [CONFIG_VER, CONFIG_PARAMS[0]]
    return {
        "cfg_positive_all": (_embed(rng, full), True),
        "cfg_positive_uid_variant": (_embed(rng, CONFIG_CMD + [CONFIG_VER, CONFIG_PARAMS[2]]), True),
        "cfg_positive_lid_variant": (_embed(rng, CONFIG_CMD + [CONFIG_VER, CONFIG_PARAMS[1]]), True),
        "cfg_negative_two_commands": (_embed(rng, CONFIG_CMD[:2] + [CONFIG_VER, CONFIG_PARAMS[0]]), False),
        "cfg_negative_no_version": (_embed(rng, CONFIG_CMD + [CONFIG_PARAMS[0]]), False),
        "cfg_negative_no_param": (_embed(rng, CONFIG_CMD + [CONFIG_VER]), False),
        "cfg_negative_filler": (_filler(rng), False),
    }


def setup_fixtures():
    """name -> (bytes, expected_match) for re_lumma_chacha_setup.yar."""
    rng = random.Random(SEED + 1)
    wide_dll = SETUP_DLL.decode().encode("utf-16-le")
    return {
        "setup_positive_all": (_embed(rng, [SETUP_CONST, SETUP_DLL, SETUP_OPEN]), True),
        "setup_positive_wide_dll": (_embed(rng, [SETUP_CONST, wide_dll, SETUP_OPEN]), True),
        "setup_negative_constant_only": (_embed(rng, [SETUP_CONST]), False),
        "setup_negative_winhttp_only": (_embed(rng, [SETUP_DLL, SETUP_OPEN]), False),
        "setup_negative_constant_and_dll": (_embed(rng, [SETUP_CONST, SETUP_DLL]), False),
        "setup_negative_filler": (_filler(rng), False),
    }


# --- synthetic config blobs for the extractor ---------------------------------------------------

PLAINTEXT_CONFIG = {
    "c2": ["https://c2-placeholder.example/api", "203.0.113.10"],
    "build_id": "SYNTH-0001",
    "note": "synthetic test config, not real",
}


def synthetic_key_nonce(seed=SEED):
    """A test-only key and nonce from a seeded RNG. Never a real key."""
    rng = random.Random(seed)
    return rng.randbytes(cx.KEY_LEN), rng.randbytes(cx.NONCE_LEN)


def build_blob(plaintext=None, seed=SEED, magic=cx.TEST_MAGIC, key=None, nonce=None):
    """Build a synthetic blob in the schema from ANALYSIS.md section 3.3, encrypting with ChaCha20."""
    plaintext = json.dumps(PLAINTEXT_CONFIG, sort_keys=True).encode() if plaintext is None else plaintext
    k, n = synthetic_key_nonce(seed)
    key = k if key is None else key
    nonce = n if nonce is None else nonce
    ciphertext = cx.chacha20_xor(key, nonce, plaintext)
    return magic + key + nonce + struct.pack("<I", len(ciphertext)) + ciphertext
