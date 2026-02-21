# -*- encoding: utf-8 -*-
"""
EVM Backer
evm_backer.backer module

keripy integration for the EVM backer service.

Sets up Kevery, Tevery, Parser, and HTTP endpoint for receiving KERI events
from controllers. The backer validates events via keripy, signs receipts
immediately (receipt-first model), and queues events for asynchronous
on-chain anchoring.

Reference:
  - evm-backer-spec.md section 5 (Backer Service)
  - docs/06-design-challenges.md C3 (backer designation check)
  - docs/06-design-challenges.md C5 (receipt-first model)
"""

from hio.help import decking
from keri.core import eventing, parsing, routing
from keri.vdr import verifying, viring
from keri.vdr.eventing import Tevery


def setup_kevery(hby, cues=None):
    """Create a Kevery for the backer to process incoming key events.

    Args:
        hby: keripy Habery instance.
        cues: Optional Deck for receipt generation. Created if not provided.

    Returns:
        dict with keys: kevery, reply_router, cues
    """
    if cues is None:
        cues = decking.Deck()
    reply_router = routing.Revery(db=hby.db, cues=cues)
    kevery = eventing.Kevery(
        db=hby.db,
        lax=True,
        local=False,
        rvy=reply_router,
        cues=cues,
    )
    kevery.registerReplyRoutes(router=reply_router.rtr)
    return {"kevery": kevery, "reply_router": reply_router, "cues": cues}


def setup_tevery(hby, hab, kevery_components):
    """Create a Tevery for the backer to process TEL events.

    Args:
        hby: keripy Habery instance.
        hab: Backer's Hab (non-transferable).
        kevery_components: dict from setup_kevery (provides cues and reply_router).

    Returns:
        dict with keys: tevery, tel_registry, tel_verifier
    """
    tel_registry = viring.Reger(name=hab.name, db=hab.db, temp=True)
    tel_verifier = verifying.Verifier(hby=hby, reger=tel_registry)
    cues = kevery_components["cues"]

    tevery = Tevery(
        reger=tel_verifier.reger,
        db=hby.db,
        local=False,
        cues=cues,
    )
    tevery.registerReplyRoutes(router=kevery_components["reply_router"].rtr)

    return {"tevery": tevery, "tel_registry": tel_registry, "tel_verifier": tel_verifier}


def setup_parser(kevery_components, tevery_components):
    """Create a Parser wired to the backer's Kevery and Tevery.

    Args:
        kevery_components: dict from setup_kevery.
        tevery_components: dict from setup_tevery.

    Returns:
        A keripy Parser instance.
    """
    return parsing.Parser(
        framed=True,
        kvy=kevery_components["kevery"],
        tvy=tevery_components["tevery"],
        rvy=kevery_components["reply_router"],
    )


def is_designated_backer(hab, controller_pre, kevers):
    """Check if this backer is designated in the controller's b field.

    C3 fix: The backer must verify its own AID appears in the controller's
    backer/witness list before queuing events for anchoring. Without this
    check, any controller could submit events and drain the backer's ETH.

    Args:
        hab: Backer's Hab (provides hab.pre).
        controller_pre: Controller's AID prefix string.
        kevers: dict of {prefix: Kever} from kevery.kevers.

    Returns:
        True if this backer is in the controller's current witness list.
    """
    key_state = kevers.get(controller_pre)
    if key_state is None:
        return False
    return hab.pre in key_state.wits


def process_event(hab, parser, kevery_components, queuer, raw_msg):
    """Process an incoming KERI event message.

    This is the core backer flow:
    1. Parse the message through Kevery/Tevery (validates signatures, chaining)
    2. Queue designated events for on-chain anchoring (C3, C5 fix)
    3. Generate receipt immediately (receipt-first model)

    Args:
        hab: Backer's Hab.
        parser: keripy Parser instance.
        kevery_components: dict from setup_kevery (provides kevery, cues).
        queuer: Queuer instance for on-chain batching.
        raw_msg: Raw CESR message bytes.

    Returns:
        Receipt message bytes, or None if event was rejected.
    """
    kevery = kevery_components["kevery"]

    # Parse the incoming event (validates signatures, chaining)
    parser.parse(ims=bytearray(raw_msg), kvy=kevery)

    # Inspect accepted events from cues before processCues consumes them.
    # Each "receipt" cue means Kevery accepted and stored the event.
    for cue in kevery.cues:
        if cue.get("kin") != "receipt":
            continue
        event = cue.get("serder")
        if event is None:
            continue
        # C3: only anchor events from controllers that designate this backer
        if not is_designated_backer(hab, event.pre, kevery.kevers):
            continue
        queuer.enqueue(event.pre, event.sn, event.said)

    # Generate receipts (receipt-first model, C5 fix) — consumes cues
    return hab.processCues(kevery.cues)
