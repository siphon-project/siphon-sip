"""Mock ``tasks`` namespace: background work and wait-for-the-first-answer.

Mirrors the Rust ``PyTasksNamespace`` / ``Event`` / ``FirstResult`` and the
handle ``tasks.spawn`` returns. In siphon these run on the executor with no
asyncio task; the mock runs them on the asyncio loop pytest drives, with the
same surface and outcomes, so a script that uses them is testable as written.

Usage in a script::

    from siphon import tasks, log

    async def delete_session(session):
        release = tasks.spawn(release_resources(session), name="release")
        answered = tasks.event()             # set by another handler
        first = await tasks.wait_first([release, answered.wait()], timeout=2.0)
        if first.timed_out:
            log.warning("release still running, answering anyway")
        return "deleted"

Usage in a test (any ``async`` test runner, or ``asyncio.run``)::

    from siphon_sdk import mock_module

    async def scenario():
        result = await delete_session(session)
        await mock_module.get_tasks().drain()      # let background work finish
        assert mock_module.get_tasks().outstanding == 0
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any, Awaitable, Coroutine, Iterable, List, Optional

_log = logging.getLogger("siphon_sdk.tasks")


class TaskHandle:
    """What ``tasks.spawn`` returns: an awaitable for the coroutine's outcome.

    Awaiting it gives the coroutine's value or raises its exception.
    ``cancel()`` cancels the coroutine, as ``Task.cancel()`` does.

    Example::

        handle = tasks.spawn(release(session), name="release")
        value = await handle              # or: tasks.wait_first([handle], ...)
        handle.cancel()                   # False once it has finished
    """

    def __init__(self, task: "asyncio.Future[Any]", name: str) -> None:
        self._task = task
        self.name = name
        self._observed = False

    def __await__(self):
        self._observed = True
        return self._task.__await__()

    def cancel(self, msg: Optional[str] = None) -> bool:
        """Cancel the coroutine. ``False`` if it had finished."""
        return self._task.cancel()

    def done(self) -> bool:
        """Whether it finished, failed or was cancelled."""
        return self._task.done()

    def cancelled(self) -> bool:
        """Whether it was cancelled."""
        return self._task.cancelled()

    def result(self) -> Any:
        """The value, or raise its exception
        (``asyncio.InvalidStateError`` while it is still running)."""
        return self._task.result()

    def exception(self) -> Optional[BaseException]:
        """The exception it ended with, or ``None``
        (``asyncio.InvalidStateError`` while it is still running)."""
        return self._task.exception()

    def __repr__(self) -> str:
        return f"<TaskHandle {self.name!r} done={self.done()}>"


class FirstResult:
    """How a ``tasks.wait_first`` ended.

    Attributes:
        index: position, in the list given, of the awaitable that finished
            first; ``None`` if the timeout did.
        timed_out: whether the timeout ended the wait.
        awaitable: the awaitable that finished first; ``None`` on a timeout.
        exception: the exception the winner ended with, or ``None``.

    Example::

        first = await tasks.wait_first([release, answered.wait()], timeout=2.0)
        if first.timed_out:
            ...
        elif first.index == 0:
            value = first.result()       # raises the winner's exception
    """

    def __init__(
        self,
        index: Optional[int],
        awaitable: Any = None,
        value: Any = None,
        exception: Optional[BaseException] = None,
    ) -> None:
        self.index = index
        self.awaitable = awaitable
        self.exception = exception
        self._value = value

    @property
    def timed_out(self) -> bool:
        return self.index is None

    def result(self) -> Any:
        """The winner's value; raises its exception, or ``TimeoutError`` if
        the timeout ended the wait."""
        if self.index is None:
            raise TimeoutError("tasks.wait_first() timed out before any awaitable finished")
        if self.exception is not None:
            raise self.exception
        return self._value

    def __repr__(self) -> str:
        if self.index is None:
            return "<FirstResult timed_out>"
        return f"<FirstResult index={self.index}>"


class Event:
    """A flag one piece of code sets and another awaits.

    Example::

        answered = tasks.event()
        ...
        answered.set()                    # from another handler
        await answered.wait()             # True once set
    """

    def __init__(self) -> None:
        self._event = asyncio.Event()

    def set(self) -> None:
        """Set the event: everything awaiting ``wait()`` finishes."""
        self._event.set()

    def clear(self) -> None:
        """Unset the event."""
        self._event.clear()

    def is_set(self) -> bool:
        """Whether the event is set."""
        return self._event.is_set()

    def wait(self) -> Awaitable[bool]:
        """An awaitable that finishes with ``True`` once the event is set."""
        return asyncio.ensure_future(self._wait())

    async def _wait(self) -> bool:
        await self._event.wait()
        return True


class MockTasksNamespace:
    """The ``tasks`` namespace: ``spawn``, ``wait_first`` and ``event``."""

    def __init__(self) -> None:
        self._running: List[TaskHandle] = []
        #: Failures of background work nothing was awaiting, as
        #: ``(name, exception)``. siphon logs these at error level.
        self.unawaited_failures: List[tuple] = []

    # -- test helpers ------------------------------------------------------

    @property
    def outstanding(self) -> int:
        """Spawned coroutines that have not finished yet."""
        return len([handle for handle in self._running if not handle.done()])

    async def drain(self) -> None:
        """Wait for every spawned coroutine to finish (test helper)."""
        pending = [handle._task for handle in self._running if not handle.done()]
        if pending:
            await asyncio.wait(pending)
        self._running = [handle for handle in self._running if not handle.done()]

    def clear(self) -> None:
        for handle in self._running:
            handle.cancel()
        self._running = []
        self.unawaited_failures = []

    # -- the script API ----------------------------------------------------

    def spawn(self, coroutine: Coroutine[Any, Any, Any], *, name: Optional[str] = None) -> TaskHandle:
        """Start ``coroutine`` as background work and return a handle for it.

        The handle is awaitable (the coroutine's value, or its exception), can
        be passed to ``wait_first``, and ``cancel()`` cancels the coroutine.
        An exception nothing is awaiting is logged at error level.

        Args:
            coroutine: a coroutine object (call the ``async def``), not the
                function. Anything else is a ``TypeError``.
            name: the name used in the log line when it fails.

        Example::

            handle = tasks.spawn(release(session), name="release")
        """
        if not asyncio.iscoroutine(coroutine):
            raise TypeError(
                "tasks.spawn() takes a coroutine: call the async def function and "
                "pass the result, e.g. tasks.spawn(release(session))"
            )
        label = name or getattr(coroutine, "__qualname__", "task")
        task = asyncio.ensure_future(coroutine)
        handle = TaskHandle(task, label)
        self._running.append(handle)
        task.add_done_callback(lambda finished: self._finished(handle, finished))
        return handle

    def _finished(self, handle: TaskHandle, task: "asyncio.Future[Any]") -> None:
        if handle in self._running:
            self._running.remove(handle)
        if task.cancelled():
            return
        failure = task.exception()
        if failure is not None and not handle._observed:
            self.unawaited_failures.append((handle.name, failure))
            _log.error("background task %r failed and nothing was awaiting it: %r", handle.name, failure)

    async def wait_first(
        self,
        awaitables: Iterable[Awaitable[Any]],
        *,
        timeout: Optional[float] = None,
        cancel_losers: bool = False,
    ) -> FirstResult:
        """Finish with a ``FirstResult`` as soon as the first of ``awaitables``
        finishes (value, exception or cancellation), or with ``timed_out``
        after ``timeout`` seconds.

        The others are left running unless ``cancel_losers`` is true (all of
        them after a timeout). The default matches ``asyncio.wait``: a loser is
        usually a request already sent (a release, a Diameter answer) that still
        has to finish after the caller stopped waiting.

        Example::

            first = await tasks.wait_first([release, answered.wait()], timeout=2.0)
            if first.timed_out:
                log.warning("release still running, answering anyway")
        """
        items = list(awaitables)
        if not items:
            raise ValueError("tasks.wait_first() needs at least one awaitable")
        if timeout is not None and not (timeout >= 0 and timeout != float("inf")):
            raise ValueError(
                f"tasks.wait_first(timeout=) must be a non-negative number of seconds, got {timeout}"
            )
        futures = []
        for item in items:
            if isinstance(item, TaskHandle):
                item._observed = True
                futures.append(item._task)
            elif isinstance(item, (asyncio.Future, asyncio.Task)):
                futures.append(item)
            else:
                raise TypeError(
                    "tasks.wait_first() takes awaitables siphon returned (a tasks.spawn() "
                    f"handle, tasks.event().wait(), a siphon API call), not {type(item).__name__}"
                )
        done, _pending = await asyncio.wait(
            futures, timeout=timeout, return_when=asyncio.FIRST_COMPLETED
        )
        winner = next((index for index, future in enumerate(futures) if future in done), None)
        if winner is None:
            if cancel_losers:
                for future in futures:
                    future.cancel()
            return FirstResult(None)
        future = futures[winner]
        if cancel_losers:
            for index, other in enumerate(futures):
                if index != winner:
                    other.cancel()
        if future.cancelled():
            return FirstResult(winner, items[winner], exception=asyncio.CancelledError())
        failure = future.exception()
        if failure is not None:
            return FirstResult(winner, items[winner], exception=failure)
        return FirstResult(winner, items[winner], value=future.result())

    def event(self) -> Event:
        """A new, unset ``Event``."""
        return Event()
