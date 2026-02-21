# -*- encoding: utf-8 -*-
"""
EVM Backer
evm_backer.rpc module

Multi-RPC provider with automatic failover and exponential backoff.

Wraps multiple Web3 HTTP endpoints so that if the primary RPC node is
unreachable, the backer automatically retries on the next available node.

Reference:
  - evm-backer-spec.md section 5.6 (Transaction Submission)
"""

import logging
import time

from web3 import Web3

logger = logging.getLogger(__name__)

DEFAULT_INITIAL_BACKOFF = 1.0  # seconds
DEFAULT_MAX_BACKOFF = 60.0     # seconds
DEFAULT_BACKOFF_FACTOR = 2.0


class MultiRPCProvider:
    """Wraps multiple Web3 HTTP providers with automatic failover.

    On any RPC call failure (connection error, timeout), rotates to the
    next URL with exponential backoff on failing endpoints.

    Usage:
        provider = MultiRPCProvider(["http://rpc1:8545", "http://rpc2:8545"])
        w3 = provider.get_web3()
        # Use w3 normally; call provider.get_web3() again if it fails.
    """

    def __init__(
        self,
        urls,
        initial_backoff=DEFAULT_INITIAL_BACKOFF,
        max_backoff=DEFAULT_MAX_BACKOFF,
        backoff_factor=DEFAULT_BACKOFF_FACTOR,
    ):
        if not urls:
            raise ValueError("At least one RPC URL is required")

        self._urls = list(urls)
        self._instances = [
            Web3(Web3.HTTPProvider(url)) for url in self._urls
        ]
        self._current_index = 0
        self._initial_backoff = initial_backoff
        self._max_backoff = max_backoff
        self._backoff_factor = backoff_factor
        # Per-endpoint backoff state: maps index -> next backoff duration
        self._backoffs = {i: initial_backoff for i in range(len(self._urls))}
        self._blocked_until = {i: 0.0 for i in range(len(self._urls))}

    def get_web3(self):
        """Return the current active Web3 instance.

        Returns:
            The Web3 instance for the current endpoint.
        """
        return self._instances[self._current_index]

    def report_failure(self):
        """Report that the current endpoint has failed.

        Applies exponential backoff to the current endpoint and rotates
        to the next available one.

        Returns:
            The new active Web3 instance, or None if all endpoints are
            in backoff and no fallback is immediately available.
        """
        idx = self._current_index
        backoff = self._backoffs[idx]
        self._blocked_until[idx] = time.monotonic() + backoff
        self._backoffs[idx] = min(backoff * self._backoff_factor, self._max_backoff)

        logger.warning(
            "RPC endpoint %s failed, backing off for %.1fs",
            self._urls[idx],
            backoff,
        )

        return self._rotate()

    def report_success(self):
        """Report that the current endpoint succeeded. Resets its backoff."""
        idx = self._current_index
        self._backoffs[idx] = self._initial_backoff
        self._blocked_until[idx] = 0.0

    def _rotate(self):
        """Rotate to the next available endpoint.

        Returns:
            The Web3 instance for the next available endpoint, or None if
            all endpoints are currently in backoff.
        """
        now = time.monotonic()
        n = len(self._urls)

        for offset in range(1, n + 1):
            candidate = (self._current_index + offset) % n
            if self._blocked_until[candidate] <= now:
                self._current_index = candidate
                logger.info("Switched to RPC endpoint %s", self._urls[candidate])
                return self._instances[candidate]

        # All endpoints in backoff — find the one that unblocks soonest
        soonest_idx = min(self._blocked_until, key=self._blocked_until.get)
        wait_time = self._blocked_until[soonest_idx] - now
        if wait_time > 0:
            logger.warning(
                "All RPC endpoints in backoff, waiting %.1fs for %s",
                wait_time,
                self._urls[soonest_idx],
            )
            time.sleep(wait_time)

        self._current_index = soonest_idx
        # Reset backoff since we waited
        self._backoffs[soonest_idx] = self._initial_backoff
        self._blocked_until[soonest_idx] = 0.0
        return self._instances[soonest_idx]

    @property
    def current_url(self):
        """The URL of the currently active endpoint."""
        return self._urls[self._current_index]

    @property
    def endpoint_count(self):
        """Number of configured RPC endpoints."""
        return len(self._urls)
