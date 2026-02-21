#!/usr/bin/env python3
"""Sign a message with a test Ed25519 key and output ABI-encoded (bytes32 r, bytes32 s).

Usage: python3 sign_ed25519.py <hex_message>
Output: ABI-encoded (bytes32 r, bytes32 s) as hex, suitable for abi.decode.
"""
import sys
from nacl.signing import SigningKey

SK_HEX = "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7"

msg_hex = sys.argv[1]
msg = bytes.fromhex(msg_hex)

sk = SigningKey(bytes.fromhex(SK_HEX))
sig = sk.sign(msg).signature  # 64 bytes: r (32) + s (32)

# Output as ABI-encoded bytes32, bytes32 (just the raw 64 bytes as hex)
# The "0x" prefix makes forge FFI return it as raw bytes
sys.stdout.write("0x" + sig.hex())
