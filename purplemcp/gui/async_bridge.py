"""Bridge between Qt (sync, its own event loop) and the async MCP/agent core.

The whole backend — :class:`~purplemcp.host.client.MCPHost`, the agent loop, the
scanner — is ``asyncio`` and spawns stdio subprocesses. Qt can't ``await``. So we
run **one** persistent asyncio loop on a daemon thread (:class:`AsyncLoop`) and
talk to it two ways:

* :func:`run_job` — fire a one-shot coroutine and get its result back on the GUI
  thread via a :class:`Job`'s signals. Used for list/call/scan/arena.
* :class:`ChatSession` — a long-lived task that owns an ``MCPHost`` + ``Agent``
  for its whole life (so anyio's task-scoped transports are opened and closed in
  the *same* task) and takes user turns off an inbox queue.

Qt signals emitted from the loop thread are delivered to GUI-thread slots via
queued connections, which is thread-safe — that's the entire trick.
"""

from __future__ import annotations

import asyncio
import threading
from concurrent.futures import Future
from typing import Any, Awaitable, Callable, Optional

from PySide6.QtCore import QObject, Signal

from ..config import ProviderConfig, ServerSpec


# --------------------------------------------------------------------------- #
#  the loop
# --------------------------------------------------------------------------- #
class AsyncLoop:
    """A persistent asyncio event loop running on its own daemon thread."""

    def __init__(self) -> None:
        self._loop = asyncio.new_event_loop()
        self._closed = False
        self._thread = threading.Thread(
            target=self._run, name="purplemcp-async", daemon=True
        )
        self._thread.start()

    def _run(self) -> None:
        asyncio.set_event_loop(self._loop)
        self._loop.run_forever()

    @property
    def loop(self) -> asyncio.AbstractEventLoop:
        return self._loop

    def submit(self, coro: Awaitable) -> Future:
        """Schedule a coroutine on the loop; returns a concurrent.futures.Future."""
        return asyncio.run_coroutine_threadsafe(coro, self._loop)

    def call_soon(self, fn: Callable, *args: Any) -> None:
        """Run ``fn(*args)`` on the loop thread (thread-safe)."""
        self._loop.call_soon_threadsafe(fn, *args)

    async def _drain(self) -> None:
        tasks = [t for t in asyncio.all_tasks(self._loop) if t is not asyncio.current_task()]
        for task in tasks:
            task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

    def shutdown(self) -> None:
        """Cancel in-flight jobs, then stop the loop — a tidy close with no
        'Task was destroyed but it is pending' noise. Best-effort and bounded so
        closing the app can never hang. Idempotent — safe to call more than once."""
        if self._closed:
            return
        self._closed = True
        try:
            asyncio.run_coroutine_threadsafe(self._drain(), self._loop).result(timeout=2.0)
        except Exception:  # noqa: BLE001 - never block shutdown on a stubborn task
            pass
        self._loop.call_soon_threadsafe(self._loop.stop)


# --------------------------------------------------------------------------- #
#  friendly errors (mirrors the CLI's translations)
# --------------------------------------------------------------------------- #
def format_error(exc: BaseException) -> str:
    name = type(exc).__name__
    msg = str(exc)
    if "does not support tools" in msg:
        return "That model can't use tools. Pick a tool-capable model (e.g. ollama pull qwen2.5)."
    if "ConnectError" in name or "ConnectionError" in name or "Connection error" in msg:
        return "Can't reach the model backend. Is it running?  For Ollama: `ollama serve`."
    if name == "ResponseError":
        return f"Model backend error: {msg}"
    if name == "ModuleNotFoundError":
        return f"Missing dependency: {msg}"
    if not msg:
        return name
    return f"{name}: {msg}"


# --------------------------------------------------------------------------- #
#  one-shot jobs
# --------------------------------------------------------------------------- #
class Job(QObject):
    """Result carrier for one coroutine. Connect to its signals on the GUI thread.

    ``event`` lets a long-running coroutine stream progress (kind, payload) back
    while it runs; ``succeeded``/``failed`` fire exactly once at the end.
    """

    succeeded = Signal(object)
    failed = Signal(str)
    event = Signal(str, object)

    def __init__(self, parent: Optional[QObject] = None) -> None:
        super().__init__(parent)
        self._future: Optional[Future] = None


class _Activity(QObject):
    """App-wide counter of in-flight jobs, so the status bar can show 'working…'."""

    changed = Signal(int)

    def __init__(self) -> None:
        super().__init__()
        self._n = 0

    @property
    def count(self) -> int:
        return self._n

    def inc(self) -> None:
        self._n += 1
        self._emit()

    def dec(self) -> None:
        self._n = max(0, self._n - 1)
        self._emit()

    def _emit(self) -> None:
        # Jobs finish on the loop thread; during app/test teardown the underlying
        # C++ object may already be gone. Emitting then is harmless to skip.
        try:
            self.changed.emit(self._n)
        except RuntimeError:
            pass


#: singleton activity tracker (connect ``ACTIVITY.changed`` from the GUI thread).
ACTIVITY = _Activity()


def run_job(
    loop: AsyncLoop,
    coro_or_factory: Awaitable | Callable[[Job], Awaitable],
    parent: Optional[QObject] = None,
) -> Job:
    """Run a coroutine on the async loop, reporting via a :class:`Job`.

    ``coro_or_factory`` is either a coroutine, or a callable taking the Job (so it
    can ``job.event.emit(...)`` as it streams). Keep a reference to the returned
    Job until it finishes (parenting it to a widget is enough).
    """
    job = Job(parent)
    coro = coro_or_factory(job) if callable(coro_or_factory) else coro_or_factory

    async def _runner() -> None:
        ACTIVITY.inc()
        try:
            result = await coro
        except Exception as exc:  # noqa: BLE001 - reported to the UI
            job.failed.emit(format_error(exc))
        else:
            job.succeeded.emit(result)
        finally:
            ACTIVITY.dec()

    job._future = loop.submit(_runner())
    return job


# --------------------------------------------------------------------------- #
#  long-lived chat session
# --------------------------------------------------------------------------- #
class ChatSession(QObject):
    """A persistent agent session: one MCPHost + Agent kept alive on the loop.

    User turns are pushed onto an inbox queue; replies and live tool events come
    back as signals. The host's transports are opened and closed inside a single
    task, satisfying anyio's task-scoping rules.
    """

    ready = Signal(object)          # list[ToolInfo]
    answer = Signal(str)
    tool_call = Signal(object)      # ToolCall
    tool_result = Signal(object, str)  # (ToolCall, rendered result)
    error = Signal(str)
    busy = Signal(bool)
    closed = Signal()

    def __init__(
        self,
        loop: AsyncLoop,
        provider_cfg: ProviderConfig,
        specs: list[ServerSpec],
        max_steps: int = 8,
        parent: Optional[QObject] = None,
    ) -> None:
        super().__init__(parent)
        self._loop = loop
        self._cfg = provider_cfg
        self._specs = specs
        self._max_steps = max_steps
        # Create the queue on the loop thread so it binds to the right loop.
        self._inbox: asyncio.Queue = loop.submit(self._make_queue()).result(timeout=5)
        loop.submit(self._serve())

    @staticmethod
    async def _make_queue() -> asyncio.Queue:
        return asyncio.Queue()

    async def _serve(self) -> None:
        from ..host import Agent, MCPHost
        from ..providers import build_provider

        def on_event(kind: str, payload: object) -> None:
            if kind == "tool_call":
                self.tool_call.emit(payload)
            elif kind == "tool_result":
                call, result = payload  # type: ignore[misc]
                self.tool_result.emit(call, result)

        try:
            provider = build_provider(self._cfg)
            async with MCPHost(self._specs) as host:
                agent = Agent(
                    provider, host, max_steps=self._max_steps, on_event=on_event
                )
                self.ready.emit(list(host.tool_info))
                while True:
                    text = await self._inbox.get()
                    if text is None:
                        break
                    self.busy.emit(True)
                    try:
                        reply = await agent.run(text)
                        self.answer.emit(reply)
                    except Exception as exc:  # noqa: BLE001 - keep session alive
                        self.error.emit(format_error(exc))
                    finally:
                        self.busy.emit(False)
        except Exception as exc:  # noqa: BLE001 - failed to start
            self.error.emit(format_error(exc))
        finally:
            self.closed.emit()

    def send(self, text: str) -> None:
        self._loop.call_soon(self._inbox.put_nowait, text)

    def close(self) -> None:
        self._loop.call_soon(self._inbox.put_nowait, None)
