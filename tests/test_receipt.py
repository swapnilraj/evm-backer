# -*- encoding: utf-8 -*-
"""
Golden tests for receipt message format.

These tests verify the receipt (rct) message structure the backer sends back
to the controller. Per the spec-validator/devil's-advocate findings:

  1. The backer signs a standard KERI rct using NonTransReceiptCouples
     (signature from the backer's KERI key). This is IDENTICAL to how
     witness backers sign receipts.
  2. The receipt is returned IMMEDIATELY after validation -- before
     on-chain anchoring (receipt-first model).
  3. The EVM on-chain anchor is a separate, asynchronous concern.
     It is NOT part of the KERI receipt.

No mocks -- uses real keripy objects to create and verify receipts.

Spec-validator confirmed (C1/C2 resolution):
  - C1: The backer uses Ed25519 via makeHab(transferable=False), producing
    a B-prefixed AID with Ed25519N derivation code.
  - C2: The backer signs standard NonTransReceiptCouples with Ed25519.
    No custom EVM attestation. The on-chain anchor is separate.

Reference:
  - docs/06-design-challenges.md C2 (receipt must be standard KERI)
  - docs/06-design-challenges.md C5 (receipt-first model)
  - keripy test_witness.py (canonical processCues receipt flow)
  - keripy test_eventing.py (receipt function)
  - keripy test_witness.py (hab.receipt(serder) pattern)
"""

from keri.app import habbing
from keri.core import parsing
from keri.core.coring import MtrDex, Diger
from keri.core.signing import Signer
from keri.core.eventing import incept, rotate, interact, receipt, Kevery
from keri.kering import Ilks

from tests.conftest import SEED_0


class TestReceiptMessageFormat:
    """Test the KERI rct message structure per spec section 6.1."""

    def test_receipt_event_type(self):
        """The receipt message type must be 'rct'."""
        signer = Signer(raw=SEED_0, transferable=True)
        keys = [signer.verfer.qb64]
        signer1_raw = (
            b'\x83B~\x04\x94\xe3\xceUQy\x11f\x0c\x93]\x1e\xbf'
            b'\xacQ\xb5\xd6Y^\xa2E\xfa\x015\x98Y\xdd\xe8'
        )
        signer1 = Signer(raw=signer1_raw, transferable=True)
        nxt = [Diger(ser=signer1.verfer.qb64b).qb64]

        serder_icp = incept(keys=keys, ndigs=nxt, code=MtrDex.Blake3_256)
        pre = serder_icp.ked["i"]

        serder_rct = receipt(pre=pre, sn=0, said=serder_icp.said)

        assert serder_rct.ked["t"] == Ilks.rct

    def test_receipt_references_controller_prefix(self):
        """The receipt's i field must contain the controller's AID prefix."""
        signer = Signer(raw=SEED_0, transferable=True)
        keys = [signer.verfer.qb64]
        signer1_raw = (
            b'\x83B~\x04\x94\xe3\xceUQy\x11f\x0c\x93]\x1e\xbf'
            b'\xacQ\xb5\xd6Y^\xa2E\xfa\x015\x98Y\xdd\xe8'
        )
        signer1 = Signer(raw=signer1_raw, transferable=True)
        nxt = [Diger(ser=signer1.verfer.qb64b).qb64]

        serder_icp = incept(keys=keys, ndigs=nxt, code=MtrDex.Blake3_256)
        pre = serder_icp.ked["i"]

        serder_rct = receipt(pre=pre, sn=0, said=serder_icp.said)

        assert serder_rct.ked["i"] == pre

    def test_receipt_references_correct_sequence_number(self):
        """The receipt's s field must contain the sequence number of the receipted event."""
        signer = Signer(raw=SEED_0, transferable=True)
        keys = [signer.verfer.qb64]
        signer1_raw = (
            b'\x83B~\x04\x94\xe3\xceUQy\x11f\x0c\x93]\x1e\xbf'
            b'\xacQ\xb5\xd6Y^\xa2E\xfa\x015\x98Y\xdd\xe8'
        )
        signer1 = Signer(raw=signer1_raw, transferable=True)
        nxt = [Diger(ser=signer1.verfer.qb64b).qb64]

        serder_icp = incept(keys=keys, ndigs=nxt, code=MtrDex.Blake3_256)
        pre = serder_icp.ked["i"]

        # Receipt for inception (sn=0)
        rct_0 = receipt(pre=pre, sn=0, said=serder_icp.said)
        assert rct_0.ked["s"] == "0"

        # Receipt for a later event (sn=5)
        rct_5 = receipt(pre=pre, sn=5, said="EFakeDigestForTestingPurposesOnly12345678901234")
        assert rct_5.ked["s"] == "5"

    def test_receipt_d_field_contains_receipted_event_said(self):
        """The receipt's d field (SAID) must reference the receipted event's SAID.

        Spec section 6.1: 'p: SAID of receipted event'
        Note: keripy's receipt function puts the receipted event's SAID in d.
        """
        signer = Signer(raw=SEED_0, transferable=True)
        keys = [signer.verfer.qb64]
        signer1_raw = (
            b'\x83B~\x04\x94\xe3\xceUQy\x11f\x0c\x93]\x1e\xbf'
            b'\xacQ\xb5\xd6Y^\xa2E\xfa\x015\x98Y\xdd\xe8'
        )
        signer1 = Signer(raw=signer1_raw, transferable=True)
        nxt = [Diger(ser=signer1.verfer.qb64b).qb64]

        serder_icp = incept(keys=keys, ndigs=nxt, code=MtrDex.Blake3_256)
        pre = serder_icp.ked["i"]

        serder_rct = receipt(pre=pre, sn=0, said=serder_icp.said)

        # The d field of the receipt contains the SAID of the receipted event
        assert serder_rct.ked["d"] == serder_icp.said

    def test_receipt_version_string(self):
        """The receipt version string must be KERI 1.0 JSON."""
        signer = Signer(raw=SEED_0, transferable=True)
        keys = [signer.verfer.qb64]
        signer1_raw = (
            b'\x83B~\x04\x94\xe3\xceUQy\x11f\x0c\x93]\x1e\xbf'
            b'\xacQ\xb5\xd6Y^\xa2E\xfa\x015\x98Y\xdd\xe8'
        )
        signer1 = Signer(raw=signer1_raw, transferable=True)
        nxt = [Diger(ser=signer1.verfer.qb64b).qb64]

        serder_icp = incept(keys=keys, ndigs=nxt, code=MtrDex.Blake3_256)
        pre = serder_icp.ked["i"]

        serder_rct = receipt(pre=pre, sn=0, said=serder_icp.said)

        assert serder_rct.ked["v"].startswith("KERI10JSON")


class TestGoldenReceiptBytes:
    """Golden test: exact receipt bytes from known inputs."""

    def test_golden_receipt_for_inception(self):
        """Create a receipt for the golden inception event and verify exact fields.

        Input: inception from SEED_0 (non-transferable)
        Output: rct with known i, s, d values
        """
        signer = Signer(raw=SEED_0, transferable=False)
        keys = [signer.verfer.qb64]
        serder_icp = incept(keys=keys)

        pre = serder_icp.ked["i"]
        said = serder_icp.said

        serder_rct = receipt(pre=pre, sn=0, said=said)

        # These values are deterministic from the golden seed
        assert serder_rct.ked["t"] == "rct"
        assert serder_rct.ked["i"] == "BFs8BBx86uytIM0D2BhsE5rrqVIT8ef8mflpNceHo4XH"
        assert serder_rct.ked["s"] == "0"
        assert serder_rct.ked["d"] == "EMW0zK3bagYPO6gx3w7Ua90f-I7x5kGIaI4Xeq9W8_As"

    def test_golden_receipt_serialization_is_deterministic(self):
        """The same inputs must always produce the same receipt bytes."""
        signer = Signer(raw=SEED_0, transferable=False)
        keys = [signer.verfer.qb64]
        serder_icp = incept(keys=keys)

        pre = serder_icp.ked["i"]
        said = serder_icp.said

        rct1 = receipt(pre=pre, sn=0, said=said)
        rct2 = receipt(pre=pre, sn=0, said=said)

        assert rct1.raw == rct2.raw, "Receipt serialization must be deterministic"


class TestNonTransReceiptCouples:
    """Test that the backer produces standard NonTransReceiptCouples.

    C2 fix: The backer MUST sign a standard KERI receipt using its KERI
    signing key and attach it as NonTransReceiptCouples. This is identical
    to how witness backers sign receipts. keripy's controller Kevery
    already knows how to process this format -- no protocol changes needed.

    hab.receipt(serder) produces a NonTransReceiptCouples attachment
    that keripy processes natively.

    NOTE: These tests use real keripy Habery objects. The backer's hab.receipt()
    call is the production code path.
    """

    def test_backer_hab_can_produce_receipt(self):
        """A non-transferable backer Hab must be able to produce a receipt
        for a controller's event using hab.receipt().

        The backer calls hab.receipt(serder) which produces NonTransReceiptCouples
        containing the backer's signature.
        """
        with habbing.openHby(name="rct-couple-test", temp=True) as hby:
            backer = hby.makeHab("backer", transferable=False)
            ctrl = hby.makeHab(
                "controller", transferable=True,
                wits=[backer.pre], toad=1,
            )

            # Get the controller's inception event
            serder = ctrl.kever.serder

            # The backer produces a receipt -- this is the real production call
            rct_msg = backer.receipt(serder)

            # rct_msg should be non-empty bytes containing the receipt
            assert rct_msg is not None
            assert len(rct_msg) > 0

    def test_receipt_contains_backer_signature(self):
        """The receipt message must contain a signature from the backer's key.

        NonTransReceiptCouples format: (prefix, cigar) pairs where the cigar
        is the backer's signature over the event.
        """
        with habbing.openHby(name="rct-sig-test", temp=True) as hby:
            backer = hby.makeHab("backer", transferable=False)
            ctrl = hby.makeHab(
                "controller", transferable=True,
                wits=[backer.pre], toad=1,
            )

            serder = ctrl.kever.serder
            rct_msg = backer.receipt(serder)

            # The receipt message should contain the backer's prefix
            # (as part of the NonTransReceiptCouples attachment)
            assert backer.pre.encode() in rct_msg, (
                "Receipt must contain the backer's prefix in the attachment"
            )

    def test_receipt_is_returned_before_anchoring(self):
        """C5 fix: The receipt is generated immediately upon validation,
        before any on-chain anchoring occurs.

        This test verifies that hab.receipt() works without any Ethereum
        connection or contract interaction. The receipt is a pure KERI
        operation -- the on-chain anchor happens asynchronously later.
        """
        with habbing.openHby(name="rct-immediate-test", temp=True) as hby:
            backer = hby.makeHab("backer", transferable=False)
            ctrl = hby.makeHab(
                "controller", transferable=True,
                wits=[backer.pre], toad=1,
            )

            serder = ctrl.kever.serder

            # No Ethereum connection, no contract, no web3.
            # The receipt must still be producible.
            rct_msg = backer.receipt(serder)
            assert rct_msg is not None
            assert len(rct_msg) > 0

    def test_receipt_for_rotation_event(self):
        """The backer must be able to receipt a rotation event too."""
        with habbing.openHby(name="rct-rot-test", temp=True) as hby:
            backer = hby.makeHab("backer", transferable=False)
            ctrl = hby.makeHab(
                "controller", transferable=True,
                wits=[backer.pre], toad=1,
            )

            ctrl.rotate()
            rot_serder = ctrl.kever.serder
            assert rot_serder.ked["t"] == "rot"

            rct_msg = backer.receipt(rot_serder)
            assert rct_msg is not None
            assert len(rct_msg) > 0

    def test_receipt_for_interaction_event(self):
        """The backer must be able to receipt an interaction event."""
        with habbing.openHby(name="rct-ixn-test", temp=True) as hby:
            backer = hby.makeHab("backer", transferable=False)
            ctrl = hby.makeHab(
                "controller", transferable=True,
                wits=[backer.pre], toad=1,
            )

            ctrl.interact()
            ixn_serder = ctrl.kever.serder
            assert ixn_serder.ked["t"] == "ixn"

            rct_msg = backer.receipt(ixn_serder)
            assert rct_msg is not None
            assert len(rct_msg) > 0


class TestReceiptForMultipleEventTypes:
    """Test that receipts can be generated for various event types."""

    def test_receipt_for_interaction_event(self):
        """A receipt for an ixn event must reference the correct sn and SAID."""
        signer = Signer(raw=SEED_0, transferable=True)
        keys = [signer.verfer.qb64]
        signer1_raw = (
            b'\x83B~\x04\x94\xe3\xceUQy\x11f\x0c\x93]\x1e\xbf'
            b'\xacQ\xb5\xd6Y^\xa2E\xfa\x015\x98Y\xdd\xe8'
        )
        signer1 = Signer(raw=signer1_raw, transferable=True)
        nxt = [Diger(ser=signer1.verfer.qb64b).qb64]

        serder_icp = incept(keys=keys, ndigs=nxt, code=MtrDex.Blake3_256)
        pre = serder_icp.ked["i"]

        # Create interaction event
        serder_ixn = interact(pre=pre, dig=serder_icp.said, sn=1)

        # Generate receipt for the ixn
        serder_rct = receipt(pre=pre, sn=1, said=serder_ixn.said)

        assert serder_rct.ked["t"] == "rct"
        assert serder_rct.ked["i"] == pre
        assert serder_rct.ked["s"] == "1"
        assert serder_rct.ked["d"] == serder_ixn.said

    def test_receipt_for_rotation_event(self):
        """A receipt for a rot event must reference sn=1 and the rotation SAID."""
        signer0 = Signer(raw=SEED_0, transferable=True)
        signer1_raw = (
            b'\x83B~\x04\x94\xe3\xceUQy\x11f\x0c\x93]\x1e\xbf'
            b'\xacQ\xb5\xd6Y^\xa2E\xfa\x015\x98Y\xdd\xe8'
        )
        signer1 = Signer(raw=signer1_raw, transferable=True)
        signer2_raw = (
            b'\xbe\x96\x02\xa9\x88\xce\xf9O\x1e\x0fo\xc0\xff\x98\xb6\xfa'
            b'\x1e\xa2y\xf2e\xf9AL\x1aeK\xafj\xa1pB'
        )
        signer2 = Signer(raw=signer2_raw, transferable=True)

        keys0 = [signer0.verfer.qb64]
        keys1 = [signer1.verfer.qb64]
        nxt1 = [Diger(ser=signer1.verfer.qb64b).qb64]
        nxt2 = [Diger(ser=signer2.verfer.qb64b).qb64]

        serder_icp = incept(keys=keys0, ndigs=nxt1, code=MtrDex.Blake3_256)
        pre = serder_icp.ked["i"]

        serder_rot = rotate(
            pre=pre, keys=keys1, dig=serder_icp.said, ndigs=nxt2, sn=1
        )

        serder_rct = receipt(pre=pre, sn=1, said=serder_rot.said)

        assert serder_rct.ked["t"] == "rct"
        assert serder_rct.ked["i"] == pre
        assert serder_rct.ked["s"] == "1"
        assert serder_rct.ked["d"] == serder_rot.said


class TestProcessCuesReceiptFlow:
    """Test the canonical witness/backer receipt flow via processCues.

    This is the real production flow from keripy's test_witness.py:
      1. Controller creates event -> serializes as CESR message
      2. Backer's Kevery processes the event (validates signatures, chaining)
      3. Kevery produces cues (receipt requests)
      4. Backer calls hab.processCues(kvy.cues) to generate receipt messages
      5. Receipt messages are returned to the controller

    This is different from hab.receipt(serder) which directly creates a receipt.
    processCues is the real path used by witness/backer HTTP handlers.
    """

    def test_process_cues_produces_receipt_for_inception(self):
        """Processing a controller's inception through Kevery should produce
        receipt cues that hab.processCues() turns into receipt messages.

        Uses a controller with no witnesses (toad=0) so the inception is
        committed immediately and receipt cues are generated. Witness
        designation behavior is tested in test_event_validation.py.
        In keri 1.3.4, with toad>0, events are escrowed until witnessed.
        """
        with habbing.openHby(name="cues-icp-backer", temp=True) as backer_hby:
            backer_hab = backer_hby.makeHab("backer", transferable=False)

            with habbing.openHby(name="cues-icp-ctrl", temp=True) as ctrl_hby:
                ctrl_hab = ctrl_hby.makeHab("controller", transferable=True)

                # Controller creates inception message
                icp_msg = ctrl_hab.makeOwnInception()

                # Backer processes through its Kevery (non-local, lax)
                backer_kvy = Kevery(
                    db=backer_hby.db, lax=True, local=False,
                )
                parsing.Parser().parse(
                    ims=bytearray(icp_msg), kvy=backer_kvy,
                )

                # Verify the backer's Kevery accepted the event
                assert ctrl_hab.pre in backer_kvy.kevers

                # Process cues to generate receipt
                rct_msg = backer_hab.processCues(backer_kvy.cues)

                assert rct_msg is not None
                assert len(rct_msg) > 0

    def test_process_cues_produces_receipt_for_interaction(self):
        """processCues must produce receipts for ixn events too.

        Uses a controller with no witnesses (toad=0) so events are committed
        immediately. With toad>0, ixn would be escrowed pending inception
        witnessing (a prerequisite in keri 1.3.4).
        """
        with habbing.openHby(name="cues-ixn-backer", temp=True) as backer_hby:
            backer_hab = backer_hby.makeHab("backer", transferable=False)

            with habbing.openHby(name="cues-ixn-ctrl", temp=True) as ctrl_hby:
                ctrl_hab = ctrl_hby.makeHab("controller", transferable=True)

                # Process inception first
                icp_msg = ctrl_hab.makeOwnInception()
                backer_kvy = Kevery(
                    db=backer_hby.db, lax=True, local=False,
                )
                parsing.Parser().parse(
                    ims=bytearray(icp_msg), kvy=backer_kvy,
                )
                backer_hab.processCues(backer_kvy.cues)

                # Now do an interaction
                ctrl_hab.interact()
                ixn_msg = ctrl_hab.makeOwnEvent(sn=1)
                parsing.Parser().parse(
                    ims=bytearray(ixn_msg), kvy=backer_kvy,
                )

                rct_msg = backer_hab.processCues(backer_kvy.cues)
                assert rct_msg is not None
                assert len(rct_msg) > 0


class TestReceiptRoundTrip:
    """Test that the controller's Kevery can process the backer's receipt.

    This is the full round-trip: controller creates event -> backer receipts
    it -> controller processes the receipt -> controller's database has the
    receipt stored. If this works, the receipt format is correct end-to-end.
    """

    def test_controller_accepts_backer_receipt(self):
        """The controller's Kevery must accept the backer's receipt and store it.

        This proves the NonTransReceiptCouples format is correct: keripy's
        controller-side Kevery can parse and validate the backer's signature.
        """
        with habbing.openHby(name="rt-backer", temp=True) as backer_hby:
            backer_hab = backer_hby.makeHab("backer", transferable=False)

            with habbing.openHby(name="rt-ctrl", temp=True) as ctrl_hby:
                ctrl_hab = ctrl_hby.makeHab(
                    "controller", transferable=True,
                    wits=[backer_hab.pre], toad=1,
                )

                # Backer receives and processes the controller's inception
                icp_msg = ctrl_hab.makeOwnInception()
                backer_kvy = Kevery(
                    db=backer_hby.db, lax=True, local=False,
                )
                parsing.Parser().parse(
                    ims=bytearray(icp_msg), kvy=backer_kvy,
                )

                # Backer generates receipt
                rct_msg = backer_hab.receipt(ctrl_hab.kever.serder)

                # Controller processes the backer's receipt
                ctrl_kvy = Kevery(
                    db=ctrl_hby.db, lax=False, local=False,
                )
                parsing.Parser().parse(
                    ims=bytearray(rct_msg), kvy=ctrl_kvy,
                )

                # The receipt should be stored in the controller's database.
                # Verify receipt was processed without error (no exception raised).
                # The receipt is stored as a witness receipt (wig) in the db.
                from keri.db import dbing
                dgkey = dbing.dgKey(
                    pre=ctrl_hab.pre,
                    dig=ctrl_hab.kever.serder.saidb,
                )
                wigs = ctrl_hby.db.getWigs(dgkey)
                assert len(wigs) > 0, (
                    "Controller's database must have at least one witness receipt "
                    "after processing the backer's receipt"
                )
