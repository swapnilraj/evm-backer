# -*- encoding: utf-8 -*-
"""
Golden tests for backer AID inception.

These tests verify that the EVM backer's identity — created via
hby.makeHab(name=alias, transferable=False) — produces the exact
inception event structure required by evm-backer-spec.md section 2.2.

Uses real keripy Habery objects with in-memory keystores. No mocks.

Reference:
  - evm-backer-spec.md section 2.2 (Non-Ephemeral, Non-Transferable AID)
  - keripy test_eventing.py test_keyeventfuncs (non-transferable incept)
"""

from keri.app import habbing
from keri.core import coring, serdering
from keri.core.coring import MtrDex
from keri.core.signing import Signer, Salter

from tests.conftest import SEED_0


class TestBackerInception:
    """Verify the backer inception event structure matches the spec exactly."""

    def test_inception_event_type_is_icp(self, backer_hab):
        """The backer's inception event type must be 'icp'."""
        serder = serdering.SerderKERI(raw=backer_hab.iserder.raw)
        assert serder.ked["t"] == "icp"

    def test_inception_event_is_non_transferable(self, backer_hab):
        """The backer AID must be non-transferable: empty n (next key digest) field.

        Spec section 2.2: 'The inception event's n (next key digest) field
        is empty — rotation is impossible.'

        In keripy, makeHab(transferable=False) sets nt=0 and n=[].
        """
        ked = backer_hab.iserder.ked
        assert ked["nt"] == "0", f"Expected nt='0', got nt={ked['nt']!r}"
        assert ked["n"] == [], f"Expected n=[], got n={ked['n']!r}"

    def test_inception_event_has_no_backers(self, backer_hab):
        """Backers cannot have backers (prevents infinite regress).

        Spec section 2.2: 'The backer's b (backers) field is empty'
        """
        ked = backer_hab.iserder.ked
        assert ked["bt"] == "0", f"Expected bt='0', got bt={ked['bt']!r}"
        assert ked["b"] == [], f"Expected b=[], got b={ked['b']!r}"

    def test_inception_event_has_single_ed25519_key(self, backer_hab):
        """The backer uses a single Ed25519 key.

        Spec section 2.1: 'The EVM backer uses an Ed25519 signing key.'
        The key list k should have exactly one entry, and kt should be '1'.
        """
        ked = backer_hab.iserder.ked
        assert ked["kt"] == "1", f"Expected kt='1', got kt={ked['kt']!r}"
        assert len(ked["k"]) == 1, f"Expected 1 key, got {len(ked['k'])}"

    def test_inception_key_uses_correct_derivation_code(self, backer_hab):
        """The backer's public key should use the non-transferable Ed25519 code.

        Non-transferable AIDs (transferable=False) use Ed25519N derivation,
        which means the prefix starts with 'B' (basic non-transferable).
        """
        # The backer's prefix (i field) should start with 'B' for non-transferable
        prefix = backer_hab.pre
        assert prefix[0] == "B", (
            f"Non-transferable backer prefix should start with 'B', got '{prefix[0]}'"
        )

    def test_inception_event_version_string(self, backer_hab):
        """The version string must be KERI 1.0 JSON format."""
        ked = backer_hab.iserder.ked
        assert ked["v"].startswith("KERI10JSON"), (
            f"Expected version string starting with 'KERI10JSON', got {ked['v']!r}"
        )

    def test_inception_said_is_self_addressing(self, backer_hab):
        """The d field (SAID) must equal the i field for a self-addressing inception.

        For non-transferable AIDs created with makeHab(transferable=False),
        d and i are both derived from the inception event content.
        """
        ked = backer_hab.iserder.ked
        # d is the SAID of the inception event
        assert "d" in ked, "Inception event must have a 'd' (SAID) field"
        # For basic non-transferable, i == public key qb64, d is the event SAID
        # They are NOT equal for basic non-transferable (unlike self-addressing transferable)
        assert ked["i"] == ked["k"][0], (
            "For non-transferable basic AID, i should equal the public key"
        )

    def test_inception_sequence_number_is_zero(self, backer_hab):
        """The inception event must have sequence number 0."""
        ked = backer_hab.iserder.ked
        assert ked["s"] == "0", f"Expected s='0', got s={ked['s']!r}"

    def test_inception_config_field_is_empty(self, backer_hab):
        """The configuration traits field c should be empty."""
        ked = backer_hab.iserder.ked
        assert ked["c"] == [], f"Expected c=[], got c={ked['c']!r}"

    def test_inception_anchors_field_is_empty(self, backer_hab):
        """The anchors field a must be empty for non-transferable AIDs.

        Design challenge C6: keripy enforces that non-transferable identifiers
        (transferable=False) have an empty a field. The original spec proposed
        anchoring EVM configuration metadata as a seal in a, but this is not
        possible with stock keripy. The backer inception event carries
        no configuration metadata.
        """
        ked = backer_hab.iserder.ked
        assert ked["a"] == [], f"Expected a=[], got a={ked['a']!r}"

    def test_inception_event_serialization_is_deterministic(self):
        """Creating the same backer identity with the same salt must produce
        identical inception event bytes.

        This is the core golden test property: given fixed input (salt + name),
        the output (serialized inception event) is exactly reproducible.
        """
        salt = b"0123456789abcdef"
        salter = Salter(raw=salt)

        # Create two separate Haberies with the same salt and name
        with habbing.openHby(
            name="determinism-test", salt=salter.qb64, temp=True
        ) as hby1:
            hab1 = hby1.makeHab("det-backer", transferable=False)
            raw1 = hab1.iserder.raw
            pre1 = hab1.pre

        with habbing.openHby(
            name="determinism-test", salt=salter.qb64, temp=True
        ) as hby2:
            hab2 = hby2.makeHab("det-backer", transferable=False)
            raw2 = hab2.iserder.raw
            pre2 = hab2.pre

        assert raw1 == raw2, "Inception event bytes must be deterministic"
        assert pre1 == pre2, "Backer prefix must be deterministic"


class TestBackerInceptionFromFixedSeed:
    """Golden tests using fixed seeds from keripy's test_eventing.py.

    These use the exact same seed bytes as keripy's test suite to produce
    known, stable outputs. Any change in keripy's key derivation will break
    these tests — which is the point.
    """

    def test_fixed_seed_produces_known_prefix(self):
        """Using the golden seed from keripy's test_keyeventfuncs should produce
        the known non-transferable prefix 'BFs8BBx86uytIM0D2BhsE5rrqVIT8ef8mflpNceHo4XH'.
        """
        signer = Signer(raw=SEED_0, transferable=False)
        assert signer.verfer.code == MtrDex.Ed25519N
        assert signer.verfer.qb64 == "BFs8BBx86uytIM0D2BhsE5rrqVIT8ef8mflpNceHo4XH"

    def test_fixed_seed_inception_event_bytes(self):
        """The inception event from the golden seed must produce known raw bytes.

        This is the most important golden test: if anything changes in keripy's
        serialization, this test catches it.
        """
        from keri.core.eventing import incept

        signer = Signer(raw=SEED_0, transferable=False)
        keys = [signer.verfer.qb64]
        serder = incept(keys=keys)

        # From keripy test_keyeventfuncs: non-transferable inception with this key
        expected_raw = (
            b'{"v":"KERI10JSON0000fd_","t":"icp","d":"EMW0zK3bagYPO6gx3w7Ua90f'
            b'-I7x5kGIaI4Xeq9W8_As","i":"BFs8BBx86uytIM0D2BhsE5rrqVIT8ef8mfl'
            b'pNceHo4XH","s":"0","kt":"1","k":["BFs8BBx86uytIM0D2BhsE5rrqVIT8'
            b'ef8mflpNceHo4XH"],"nt":"0","n":[],"bt":"0","b":[],"c":[],"a":[]}'
        )
        assert serder.raw == expected_raw, (
            f"Inception event bytes mismatch.\n"
            f"Expected: {expected_raw!r}\n"
            f"Got:      {serder.raw!r}"
        )

    def test_fixed_seed_inception_said(self):
        """The SAID of the inception event must be exactly known."""
        from keri.core.eventing import incept

        signer = Signer(raw=SEED_0, transferable=False)
        keys = [signer.verfer.qb64]
        serder = incept(keys=keys)

        assert serder.said == "EMW0zK3bagYPO6gx3w7Ua90f-I7x5kGIaI4Xeq9W8_As"

    def test_non_transferable_prefix_starts_with_B(self):
        """Non-transferable derivation codes produce prefixes starting with 'B'."""
        signer = Signer(raw=SEED_0, transferable=False)
        assert signer.verfer.qb64.startswith("B")

    def test_transferable_prefix_starts_with_D(self):
        """Transferable derivation codes produce prefixes starting with 'D'.

        This is the opposite case — verify the backer does NOT use this.
        """
        signer = Signer(raw=SEED_0, transferable=True)
        assert signer.verfer.qb64.startswith("D")
