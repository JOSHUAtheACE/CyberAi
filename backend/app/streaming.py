from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from threading import Lock


@dataclass(eq=False)
class _Subscriber:
    loop: asyncio.AbstractEventLoop
    queue: asyncio.Queue = field(default_factory=lambda: asyncio.Queue(maxsize=256))


class EventBus:
    """Fan-out bus for backend-processed events.

    Producers run in worker threads, so delivery is scheduled onto the loop that
    owns each WebSocket. Bounded queues apply backpressure per connection.
    """

    def __init__(self) -> None:
        self._subs: dict[str, set[_Subscriber]] = {}
        self._lock = Lock()

    def subscribe(self, environment: str) -> _Subscriber:
        sub = _Subscriber(loop=asyncio.get_running_loop())
        with self._lock:
            self._subs.setdefault(environment, set()).add(sub)
        return sub

    def unsubscribe(self, environment: str, sub: _Subscriber) -> None:
        with self._lock:
            bucket = self._subs.get(environment)
            if bucket:
                bucket.discard(sub)

    def publish(self, environment: str, event: dict) -> None:
        with self._lock:
            subscribers = list(self._subs.get(environment, ())) + list(self._subs.get("*", ()))
        for sub in subscribers:
            try:
                sub.loop.call_soon_threadsafe(self._offer, sub, {**event, "environment": environment})
            except RuntimeError:
                continue

    @staticmethod
    def _offer(sub: _Subscriber, event: dict) -> None:
        if sub.queue.full():
            try:
                sub.queue.get_nowait()
            except asyncio.QueueEmpty:
                pass
        try:
            sub.queue.put_nowait(event)
        except asyncio.QueueFull:
            pass


bus = EventBus()
