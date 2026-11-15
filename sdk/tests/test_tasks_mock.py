"""The mock ``tasks`` namespace: gather, as a script uses it."""

import asyncio

import pytest

from siphon_sdk.mock_module import install, reset


def setup_function():
    install()
    reset()


async def lookup(value, seconds=0.0):
    await asyncio.sleep(seconds)
    return value * 10


async def failing(seconds=0.0):
    await asyncio.sleep(seconds)
    raise ValueError("lookup failed")


def test_results_come_in_argument_order():
    from siphon import tasks

    async def handler():
        # The slowest first: argument order, not completion order.
        return await tasks.gather(lookup(1, 0.02), lookup(2), lookup(3, 0.01))

    assert asyncio.run(handler()) == [10, 20, 30]


def test_an_empty_gather_is_an_empty_list():
    from siphon import tasks

    async def handler():
        return await tasks.gather()

    assert asyncio.run(handler()) == []


def test_coroutines_and_futures_mix_and_a_repeated_argument_runs_once():
    from siphon import tasks

    runs = []

    async def counted():
        runs.append(1)
        return "once"

    async def handler():
        future = asyncio.get_running_loop().create_future()
        asyncio.get_running_loop().call_later(0.005, future.set_result, "future")
        coroutine = counted()
        return await tasks.gather(future, coroutine, lookup(4), coroutine)

    assert asyncio.run(handler()) == ["future", "once", 40, "once"]
    assert runs == [1]


def test_the_first_exception_is_raised_and_cancels_the_others():
    from siphon import tasks

    cancelled = []

    async def slow(name):
        try:
            await asyncio.sleep(5)
        except asyncio.CancelledError:
            cancelled.append(name)
            raise

    async def handler():
        with pytest.raises(ValueError, match="lookup failed"):
            await tasks.gather(slow("a"), failing(0.005), slow("b"))
        await asyncio.sleep(0)
        return sorted(cancelled)

    assert asyncio.run(handler()) == ["a", "b"]


def test_return_exceptions_makes_an_exception_a_result_and_cancels_nothing():
    from siphon import tasks

    async def handler():
        return await tasks.gather(failing(), lookup(2, 0.005), return_exceptions=True)

    failure, value = asyncio.run(handler())
    assert isinstance(failure, ValueError)
    assert value == 20


def test_cancelling_the_handler_cancels_what_it_gathered():
    from siphon import tasks

    cancelled = []

    async def slow(name):
        try:
            await asyncio.sleep(5)
        except asyncio.CancelledError:
            cancelled.append(name)
            raise

    async def handler():
        await tasks.gather(slow("a"), slow("b"))

    async def scenario():
        task = asyncio.ensure_future(handler())
        await asyncio.sleep(0.005)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        return sorted(cancelled)

    assert asyncio.run(scenario()) == ["a", "b"]


def test_an_argument_that_cannot_be_awaited_is_a_type_error():
    from siphon import tasks

    async def handler():
        with pytest.raises(TypeError):
            tasks.gather(5)

    asyncio.run(handler())
