"""Ed25519 signing for sandbox deliverables.

Key resolution order:
1. ``A2A_SIGNING_SEED`` env var (64 hex chars = 32 bytes) -> deterministic
   keypair. Set this in production so redeploys keep the same signing
   identity even on ephemeral disks.
2. Existing ``data/keys/ed25519.pem`` on disk.
3. Freshly generated keypair, persisted to ``data/keys/``.

The public key is published in the catalog.
"""

from __future__ import annotations

import hashlib
import os
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

SEED_ENV_VAR = "A2A_SIGNING_SEED"


def _private_from_seed(seed_hex: str) -> Ed25519PrivateKey:
    seed = bytes.fromhex(seed_hex.strip())
    if len(seed) != 32:
        raise ValueError(
            f"{SEED_ENV_VAR} must be 64 hex characters (32 bytes), "
            f"got {len(seed)} bytes"
        )
    return Ed25519PrivateKey.from_private_bytes(seed)


class Signer:
    def __init__(self, keys_dir: Path) -> None:
        keys_dir.mkdir(parents=True, exist_ok=True)
        priv_path = keys_dir / "ed25519.pem"
        seed_hex = os.environ.get(SEED_ENV_VAR)
        if seed_hex:
            # Deterministic identity: stable across redeploys and ephemeral
            # disks. Fail fast on a malformed seed rather than silently
            # serving a key that mismatches the published catalog.
            self._private = _private_from_seed(seed_hex)
        elif priv_path.exists():
            self._private = serialization.load_pem_private_key(
                priv_path.read_bytes(), password=None
            )
            assert isinstance(self._private, Ed25519PrivateKey)
        else:
            self._private = Ed25519PrivateKey.generate()
            priv_path.write_bytes(
                self._private.private_bytes(
                    serialization.Encoding.PEM,
                    serialization.PrivateFormat.PKCS8,
                    serialization.NoEncryption(),
                )
            )
        self._public: Ed25519PublicKey = self._private.public_key()
        raw = self._public.public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        self.key_id = "sandbox-ed25519-" + hashlib.sha256(raw).hexdigest()[:12]
        self._raw = raw

    def sign(self, data: bytes) -> str:
        return self._private.sign(data).hex()

    def verify(self, data: bytes, signature_hex: str) -> bool:
        try:
            self._public.verify(bytes.fromhex(signature_hex), data)
            return True
        except Exception:
            return False

    def public_key_hex(self) -> str:
        return self._raw.hex()
