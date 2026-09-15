from collections.abc import Callable, Iterator
from threading import Event

from app.api.schemas import EventResponse
from app.services.monitoring import MonitoringService


class MonitoringWorker:
    """Consume collected events and forward them to the monitoring service."""

    def __init__(
        self,
        events: Iterator[dict[str, object]],
        service: MonitoringService | None = None,
    ) -> None:
        self._events = events
        self._service = service or MonitoringService()

    def run(
        self,
        stop_event: Event | None = None,
        on_response: Callable[[EventResponse], None] | None = None,
    ) -> None:
        for event in self._events:
            if stop_event is not None and stop_event.is_set():
                return

            response = self._service.process_collected_event(event)

            if on_response is not None:
                on_response(response)
