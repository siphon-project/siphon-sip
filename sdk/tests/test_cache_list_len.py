"""Tests for the SDK's ``cache.list_len`` / ``cache.list_len_sum`` mocks.

Mirrors the ip-sm-gw "SMS Queued" tile pattern: the live depth of a set of
sharded per-key queues is the summed ``LLEN`` over ``ims_queue_*`` — truthful
because a drained (or, in production, TTL-expired) key simply leaves the
keyspace.
"""
import asyncio

import pytest

from siphon_sdk import mock_module

mock_module.install()

from siphon import cache  # noqa: E402  (must come after install)


def setup_function(_):
    cache.clear()


def _run(coro):
    return asyncio.run(coro)


def test_list_len_counts_pushed_items():
    cache.set_data("queue")
    _run(cache.list_push("queue", "ims_queue_1", "a"))
    _run(cache.list_push("queue", "ims_queue_1", "b"))
    assert _run(cache.list_len("queue", "ims_queue_1")) == 2


def test_list_len_missing_key_is_zero():
    cache.set_data("queue")
    assert _run(cache.list_len("queue", "ims_queue_absent")) == 0


def test_list_len_unknown_cache_is_none():
    assert _run(cache.list_len("nope", "k")) is None


def test_list_len_sum_over_prefix():
    cache.set_data("queue")
    _run(cache.list_push("queue", "ims_queue_1", "a"))
    _run(cache.list_push("queue", "ims_queue_1", "b"))
    _run(cache.list_push("queue", "ims_queue_2", "c"))
    _run(cache.list_push("queue", "other_key", "z"))
    # Only the ims_queue_* lists count (4 items pushed, 3 under the prefix).
    assert _run(cache.list_len_sum("queue", "ims_queue_")) == 3


def test_list_len_sum_drops_when_key_drained():
    cache.set_data("queue")
    _run(cache.list_push("queue", "ims_queue_1", "a"))
    _run(cache.list_push("queue", "ims_queue_2", "b"))
    assert _run(cache.list_len_sum("queue", "ims_queue_")) == 2
    # Draining a key (mock analogue of a TTL expiry) drops the depth.
    _run(cache.list_pop_all("queue", "ims_queue_1"))
    assert _run(cache.list_len_sum("queue", "ims_queue_")) == 1


def test_list_len_sum_no_match_is_zero():
    cache.set_data("queue")
    assert _run(cache.list_len_sum("queue", "ims_queue_")) == 0


def test_list_len_sum_unknown_cache_is_none():
    assert _run(cache.list_len_sum("nope", "ims_queue_")) is None


def test_list_len_sum_empty_prefix_raises():
    cache.set_data("queue")
    with pytest.raises(ValueError):
        _run(cache.list_len_sum("queue", ""))
