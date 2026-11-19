"""Running a blocking step of a teardown without holding an event loop.

A browser's close WAITS: for its processes to exit (`close()` returns once the
browser has exited, as Playwright's does), and the reaper after it for the
survivors of the tree and the directories. Those waits are the point, so the
fix is not a shorter wait: it is that the waiting thread is not the loop's. Measured with
py-spy on four browsers in one Python process, closing one stopped the loop
that serves the other three for as long as it waited.

A thread per call, and not the loop's default executor: that has a few workers
for everything else the program does, and a close that waits a second would
queue behind them (or hold the one a user's own `to_thread` needs).
"""
from __future__ import annotations

import asyncio
import threading
from typing import Any, Callable


def _settle(future: "asyncio.Future", result: Any, failure: "BaseException | None") -> None:
    if future.done():                  # the awaiter was cancelled; the step ran to its end anyway
        return
    if failure is not None:
        future.set_exception(failure)
    else:
        future.set_result(result)


async def off_the_loop(step: Callable[..., Any], *args: Any) -> Any:
    """Await ``step(*args)`` run in a thread of its own, and return what it returns.

    A cancelled awaiter stops waiting; the step still runs to its end, which is
    what a close needs (a browser half closed is a leak). An exception of the
    step is raised to the awaiter.
    """
    loop = asyncio.get_running_loop()
    future = loop.create_future()

    def run() -> None:
        try:
            result = step(*args)
        except BaseException as failure:  # noqa: BLE001 - handed to the awaiter
            outcome = (None, failure)
        else:
            outcome = (result, None)
        try:
            loop.call_soon_threadsafe(_settle, future, *outcome)
        except RuntimeError:
            pass                      # the loop is closed: nobody is waiting any more

    threading.Thread(target=run, name="invisible-teardown").start()
    return await future
