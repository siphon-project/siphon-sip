"""The mock ``tasks`` namespace: spawn, wait_first and event, as a script uses them."""

import asyncio

import pytest

from siphon_sdk import mock_module
from siphon_sdk.mock_module import install, reset


def setup_function():
    install()
    reset()


async def release(session, seconds=0.0):
    await asyncio.sleep(seconds)
    return f"released:{session}"


async def failing_release():
    await asyncio.sleep(0)
    raise ValueError("release failed")


def test_delete_path_releases_in_the_background_and_answers_on_the_first_result():
    """The SMF-style delete: release in the background, answer on the first reply."""
    from siphon import tasks

    async def delete_session(session):
        handle = tasks.spawn(release(session, 0.01), name="release")
        answered = tasks.event()
        first = await tasks.wait_first([handle, answered.wait()], timeout=1.0)
        return first.index, first.result()

    async def scenario():
        outcome = await delete_session("s1")
        await mock_module.get_tasks().drain()
        assert mock_module.get_tasks().outstanding == 0
        return outcome

    assert asyncio.run(scenario()) == (0, "released:s1")


def test_event_set_by_other_code_wins_the_wait():
    from siphon import tasks

    async def scenario():
        answered = tasks.event()
        slow = tasks.spawn(release("s2", 5.0))
        asyncio.get_running_loop().call_later(0.01, answered.set)
        first = await tasks.wait_first(
            [slow, answered.wait()], timeout=2.0, cancel_losers=True
        )
        await asyncio.sleep(0)
        return first.index, first.result(), slow.cancelled(), answered.is_set()

    assert asyncio.run(scenario()) == (1, True, True, True)


def test_timeout_reports_timed_out_and_leaves_the_losers_by_default():
    from siphon import tasks

    async def scenario():
        slow = tasks.spawn(release("s3", 0.05))
        first = await tasks.wait_first([slow], timeout=0.005)
        timed_out = (first.timed_out, first.index, first.awaitable, first.exception)
        with pytest.raises(TimeoutError):
            first.result()
        return timed_out, await slow

    assert asyncio.run(scenario()) == ((True, None, None, None), "released:s3")


def test_cancel_losers_cancels_everything_after_a_timeout():
    from siphon import tasks

    async def scenario():
        slow = tasks.spawn(release("s4", 5.0))
        first = await tasks.wait_first([slow], timeout=0.005, cancel_losers=True)
        await asyncio.sleep(0)
        return first.timed_out, slow.cancelled()

    assert asyncio.run(scenario()) == (True, True)


def test_a_failing_winner_raises_through_result():
    from siphon import tasks

    async def scenario():
        failing = tasks.spawn(failing_release())
        first = await tasks.wait_first([failing], timeout=1.0)
        assert isinstance(first.exception, ValueError)
        with pytest.raises(ValueError, match="release failed"):
            first.result()
        return first.index

    assert asyncio.run(scenario()) == 0


def test_a_handle_can_be_awaited_and_cancelled():
    from siphon import tasks

    async def scenario():
        quick = tasks.spawn(release("s5"))
        value = await quick
        wedged = tasks.spawn(release("s6", 5.0))
        cancelled = wedged.cancel()
        with pytest.raises(asyncio.CancelledError):
            await wedged
        return value, cancelled, wedged.cancelled(), quick.cancel()

    assert asyncio.run(scenario()) == ("released:s5", True, True, False)


def test_an_unawaited_failure_is_recorded_and_an_awaited_one_is_not():
    from siphon import tasks

    async def scenario():
        tasks.spawn(failing_release(), name="unawaited")
        awaited = tasks.spawn(failing_release(), name="awaited")
        with pytest.raises(ValueError):
            await awaited
        await mock_module.get_tasks().drain()

    asyncio.run(scenario())
    names = [name for name, _failure in mock_module.get_tasks().unawaited_failures]
    assert names == ["unawaited"]


def test_arguments_are_checked():
    from siphon import tasks

    async def scenario():
        with pytest.raises(TypeError):
            tasks.spawn(release)  # the function, not a coroutine
        with pytest.raises(ValueError):
            await tasks.wait_first([])
        with pytest.raises(TypeError):
            await tasks.wait_first([1])
        quick = tasks.spawn(release("s7"))
        with pytest.raises(ValueError):
            await tasks.wait_first([quick], timeout=-1)
        await quick

    asyncio.run(scenario())


def test_an_event_that_is_already_set_finishes_at_once_and_clear_unsets_it():
    from siphon import tasks

    async def scenario():
        event = tasks.event()
        event.set()
        assert await event.wait() is True
        event.clear()
        assert not event.is_set()
        first = await tasks.wait_first([event.wait()], timeout=0.005, cancel_losers=True)
        return first.timed_out

    assert asyncio.run(scenario()) is True
