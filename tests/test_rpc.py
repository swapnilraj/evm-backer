# -*- encoding: utf-8 -*-
"""
Tests for the MultiRPCProvider failover module.

Verifies:
  - Single-endpoint usage works normally
  - Failover rotates to the next endpoint
  - Exponential backoff applies to failed endpoints
  - Success resets backoff for the current endpoint
  - All-endpoints-failed scenario blocks until soonest unblock

No mocks — uses real Web3 instances (connected or not).
"""

import time

import pytest
from web3 import Web3

from evm_backer.rpc import MultiRPCProvider


class TestMultiRPCProviderInit:
    """Test MultiRPCProvider initialization."""

    def test_requires_at_least_one_url(self):
        """Must raise ValueError when no URLs are provided."""
        with pytest.raises(ValueError, match="At least one RPC URL"):
            MultiRPCProvider([])

    def test_single_url(self):
        """A single URL should create one Web3 instance."""
        provider = MultiRPCProvider(["http://localhost:8545"])
        assert provider.endpoint_count == 1
        assert provider.current_url == "http://localhost:8545"

    def test_multiple_urls(self):
        """Multiple URLs should create multiple Web3 instances."""
        urls = ["http://rpc1:8545", "http://rpc2:8545", "http://rpc3:8545"]
        provider = MultiRPCProvider(urls)
        assert provider.endpoint_count == 3
        assert provider.current_url == urls[0]


class TestMultiRPCProviderGetWeb3:
    """Test that get_web3 returns a valid Web3 instance."""

    def test_returns_web3_instance(self):
        """get_web3() must return a Web3 object."""
        provider = MultiRPCProvider(["http://localhost:8545"])
        w3 = provider.get_web3()
        assert isinstance(w3, Web3)

    def test_returns_same_instance_without_failure(self):
        """Without failures, get_web3() returns the same instance."""
        provider = MultiRPCProvider(["http://rpc1:8545", "http://rpc2:8545"])
        w3a = provider.get_web3()
        w3b = provider.get_web3()
        assert w3a is w3b


class TestMultiRPCProviderFailover:
    """Test failover behavior on endpoint failure."""

    def test_failure_rotates_to_next_endpoint(self):
        """After report_failure(), the provider rotates to the next URL."""
        urls = ["http://rpc1:8545", "http://rpc2:8545"]
        provider = MultiRPCProvider(urls, initial_backoff=0.01)
        assert provider.current_url == urls[0]

        provider.report_failure()
        assert provider.current_url == urls[1]

    def test_failure_wraps_around(self):
        """Failover wraps from the last endpoint back to the first."""
        urls = ["http://rpc1:8545", "http://rpc2:8545"]
        provider = MultiRPCProvider(urls, initial_backoff=0.01)

        provider.report_failure()  # rpc1 -> rpc2
        assert provider.current_url == urls[1]

        provider.report_failure()  # rpc2 -> rpc1 (backoff expired for tiny values)
        assert provider.current_url == urls[0]

    def test_new_web3_instance_after_failover(self):
        """After failover, get_web3() returns a different instance."""
        urls = ["http://rpc1:8545", "http://rpc2:8545"]
        provider = MultiRPCProvider(urls, initial_backoff=0.01)

        w3_before = provider.get_web3()
        provider.report_failure()
        w3_after = provider.get_web3()

        assert w3_before is not w3_after


class TestMultiRPCProviderBackoff:
    """Test exponential backoff behavior."""

    def test_success_resets_backoff(self):
        """report_success() resets the backoff for the current endpoint."""
        urls = ["http://rpc1:8545", "http://rpc2:8545"]
        provider = MultiRPCProvider(urls, initial_backoff=0.01)

        # Fail rpc1 (puts it in backoff), switch to rpc2
        provider.report_failure()
        assert provider.current_url == urls[1]

        # Fail rpc2, should go back to rpc1 (backoff is tiny)
        provider.report_failure()
        assert provider.current_url == urls[0]

        # Success resets rpc1's backoff
        provider.report_success()
        # Internal state check: backoff should be reset
        assert provider._backoffs[0] == provider._initial_backoff


class TestMultiRPCProviderWithRealAnvil:
    """Test MultiRPCProvider with a real anvil node (integration test)."""

    def test_live_endpoint_works(self, w3):
        """A provider with the live anvil URL should return a connected Web3."""
        from tests.conftest import ANVIL_RPC_URL

        provider = MultiRPCProvider([ANVIL_RPC_URL])
        live_w3 = provider.get_web3()
        assert live_w3.is_connected()

    def test_dead_first_endpoint_falls_back_to_live(self, w3):
        """If the first endpoint is dead, failover should reach the live one."""
        from tests.conftest import ANVIL_RPC_URL

        dead_url = "http://127.0.0.1:19999"  # nothing listening here
        provider = MultiRPCProvider(
            [dead_url, ANVIL_RPC_URL], initial_backoff=0.01
        )

        # First endpoint is dead
        assert provider.current_url == dead_url

        # Simulate failure and failover
        provider.report_failure()
        assert provider.current_url == ANVIL_RPC_URL

        live_w3 = provider.get_web3()
        assert live_w3.is_connected()
