# -*- encoding: utf-8 -*-
"""
EVM Backer
evm_backer.http_server module

HTTP endpoint for receiving KERI events from controllers.

Uses falcon (WSGI) — the same HTTP framework keripy uses for witnesses.
Controllers POST raw CESR-encoded events to /events. The backer validates
them via keripy's Kevery/Tevery/Parser pipeline, queues accepted events
for on-chain anchoring, and returns receipts in the response body.

Reference:
  - evm-backer-spec.md section 5 (Backer Service)
  - docs/05-keri-backers.md (witness HTTP interface)
"""

import concurrent.futures
import falcon

from evm_backer.backer import process_event

PARSE_TIMEOUT = 10  # seconds to allow for event processing


class EventResource:
    """Falcon resource for POST /events.

    Accepts raw CESR bytes in the request body, processes them through
    the backer pipeline, and returns receipt bytes.
    """

    def __init__(self, hab, parser, kevery_components, queuer):
        self.hab = hab
        self.parser = parser
        self.kevery_components = kevery_components
        self.queuer = queuer

    def on_post(self, req, resp):
        raw_msg = req.bounded_stream.read()
        if not raw_msg:
            resp.status = falcon.HTTP_400
            resp.content_type = falcon.MEDIA_TEXT
            resp.text = "Empty request body"
            return

        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                future = pool.submit(
                    process_event,
                    self.hab,
                    self.parser,
                    self.kevery_components,
                    self.queuer,
                    raw_msg,
                )
                receipt = future.result(timeout=PARSE_TIMEOUT)
        except concurrent.futures.TimeoutError:
            resp.status = falcon.HTTP_422
            resp.content_type = falcon.MEDIA_TEXT
            resp.text = "Event processing timed out"
            return
        except Exception as exc:
            resp.status = falcon.HTTP_422
            resp.content_type = falcon.MEDIA_TEXT
            resp.text = f"Event processing failed: {exc}"
            return

        resp.status = falcon.HTTP_200
        resp.content_type = "application/cesr"
        if receipt:
            resp.data = bytes(receipt) if not isinstance(receipt, bytes) else receipt
        else:
            resp.data = b""


class HealthResource:
    """Simple health check endpoint at GET /health."""

    def on_get(self, req, resp):
        resp.status = falcon.HTTP_200
        resp.content_type = falcon.MEDIA_JSON
        resp.media = {"status": "ok"}


def create_app(hab, parser, kevery_components, queuer):
    """Create and return a falcon WSGI application.

    Args:
        hab: Backer's Hab (non-transferable).
        parser: keripy Parser instance.
        kevery_components: dict from setup_kevery.
        queuer: Queuer instance.

    Returns:
        A falcon.App instance ready to be served.
    """
    app = falcon.App()
    events_resource = EventResource(hab, parser, kevery_components, queuer)
    health_resource = HealthResource()
    app.add_route("/events", events_resource)
    app.add_route("/health", health_resource)
    return app
