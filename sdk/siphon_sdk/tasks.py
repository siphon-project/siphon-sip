"""Mock ``tasks`` namespace: running several awaitables of one handler at once.

Mirrors the Rust ``PyTasksNamespace``. In siphon, with
``script.direct_dispatch: on``, ``tasks.gather`` runs its arguments on the
asyncio driver that steps the handler, without an asyncio task for any of
them; the mock runs them on the asyncio loop the test drives, with the same
results and the same cancellation, so a script that uses it is testable as
written.

Usage in a script::

    from siphon import diameter, tasks

    @diameter.on_request("ULR")
    async def on_update_location(request):
        profile, vectors = await tasks.gather(
            load_profile(request),                    # a coroutine of the script
            diameter.send_request(vector_request()),  # a siphon awaitable
        )
        return build_answer(request, profile, vectors)

Usage in a test (any ``async`` test runner, or ``asyncio.run``)::

    async def scenario():
        profile, vectors = await tasks.gather(load_profile(request), fetch_vectors())
        assert profile["imsi"] == "001010000000001"

    asyncio.run(scenario())
"""

from __future__ import annotations

import asyncio
import inspect
from typing import Any, Awaitable, Dict, List


class MockTasksNamespace:
    """The ``tasks`` namespace: ``gather``."""

    def gather(
        self, *awaitables: Awaitable[Any], return_exceptions: bool = False
    ) -> "asyncio.Future[List[Any]]":
        """Run ``awaitables`` at the same time and return their results as a
        list, in argument order.

        Each argument is a coroutine, an awaitable a siphon API returned, or
        anything else ``await`` accepts. Await the result in the handler that
        made it.

        If one raises, the others are cancelled and ``gather`` raises that
        exception. This is where it differs from ``asyncio.gather``, which
        leaves the others running. With ``return_exceptions=True`` nothing is
        cancelled and an exception is that argument's result. Cancelling the
        handler, or its timeout, cancels every argument still running.

        Use it instead of ``asyncio.gather`` in a handler that otherwise
        awaits only siphon APIs: ``asyncio.gather`` makes siphon run the
        handler as an asyncio task from then on, ``tasks.gather`` does not.

        Args:
            *awaitables: what to run. An awaitable passed twice runs once and
                its result appears in both places.
            return_exceptions: collect exceptions as results instead of
                raising the first one.

        Returns:
            An awaitable for the list of results.

        Raises:
            TypeError: an argument cannot be awaited.

        Example::

            profile, location = await tasks.gather(
                load_profile(imsi), load_location(imsi))

            # Keep going when one lookup fails:
            results = await tasks.gather(
                primary(imsi), fallback(imsi), return_exceptions=True)
            usable = [r for r in results if not isinstance(r, Exception)]
        """
        for awaitable in awaitables:
            # Refused before anything is started, so nothing is left running.
            if not inspect.isawaitable(awaitable):
                raise TypeError(
                    "An asyncio.Future, a coroutine or an awaitable is required"
                )
        futures: Dict[int, "asyncio.Future[Any]"] = {}
        children: List["asyncio.Future[Any]"] = []
        for awaitable in awaitables:
            if id(awaitable) not in futures:
                futures[id(awaitable)] = asyncio.ensure_future(awaitable)
            children.append(futures[id(awaitable)])
        outer = asyncio.gather(*children, return_exceptions=return_exceptions)
        if children and not return_exceptions:

            def cancel_the_rest(done: "asyncio.Future[List[Any]]") -> None:
                if done.cancelled() or done.exception() is not None:
                    for child in children:
                        child.cancel()

            outer.add_done_callback(cancel_the_rest)
        return outer

    def clear(self) -> None:
        """Nothing to reset: the namespace keeps no state (test helper)."""
