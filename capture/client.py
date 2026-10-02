"""
capture/client.py: Resilient HTTP client for NIDS flow ingestion.

Buffers and transmits computed flow payloads to the FastAPI backend (/ingest/flows)
with local queue resiliency (collections.deque bounded buffer) so packet capture
never drops telemetry or crashes when the API is temporarily unreachable.
"""

import collections
import logging
from typing import Any, Deque, Dict, Optional

import httpx

logger = logging.getLogger("capture_client")


class FlowClient:
    """
    Manages HTTP communication with the NIDS backend, maintaining a bounded buffer
    of unsent flows during API downtime.
    """

    def __init__(
        self,
        api_url: str = "http://localhost:8000",
        max_buffer_size: int = 500,
        timeout: float = 5.0,
    ):
        self.api_url = api_url.rstrip("/")
        self.target_url = f"{self.api_url}/ingest/flows"
        self.buffer: Deque[Dict[str, Any]] = collections.deque(maxlen=max_buffer_size)
        self.timeout = timeout
        self._client: Optional[httpx.Client] = None

    def _get_client(self) -> httpx.Client:
        if self._client is None or self._client.is_closed:
            self._client = httpx.Client(timeout=self.timeout)
        return self._client

    def close(self) -> None:
        if self._client is not None and not self._client.is_closed:
            self._client.close()

    def _post_payload(self, payload: Dict[str, Any]) -> bool:
        """Attempts a single POST request to the ingestion endpoint."""
        client = self._get_client()
        try:
            resp = client.post(self.target_url, json=payload)
            if resp.status_code == 200:
                return True
            else:
                logger.warning(
                    "Ingest API rejected payload with status %d: %s",
                    resp.status_code,
                    resp.text,
                )
                return False
        except (httpx.RequestError, httpx.HTTPError) as exc:
            logger.debug("Ingest API connection error: %s", exc)
            return False

    def flush_buffer(self) -> int:
        """
        Attempts to deliver previously buffered flows in FIFO order.
        Stops flushing as soon as a delivery fails.
        """
        sent_count = 0
        while self.buffer:
            item = self.buffer[0]
            if self._post_payload(item):
                self.buffer.popleft()
                sent_count += 1
            else:
                # API is still unreachable, leave remaining in buffer
                break
        return sent_count

    def send_flow(
        self,
        src_ip: str,
        dst_ip: str,
        dst_port: int,
        features: Dict[str, float],
    ) -> bool:
        """
        Sends a single flow to the API. Flushes any queued backlog first.
        If delivery fails, enqueues the payload to the local buffer.
        """
        payload = {
            "src_ip": str(src_ip),
            "dst_ip": str(dst_ip),
            "dst_port": int(dst_port),
            "features": features,
        }

        # First flush backlog if API came back online
        if self.buffer:
            self.flush_buffer()

        # If backlog was cleared, attempt immediate delivery
        if not self.buffer:
            if self._post_payload(payload):
                return True

        # Failed or backlog still active: enqueue to buffer
        self.buffer.append(payload)
        logger.debug(
            "API unreachable. Queued flow to buffer (buffer length: %d)",
            len(self.buffer),
        )
        return False


# Global default client instance for modular convenience
_default_client: Optional[FlowClient] = None


def send_flow(
    src_ip: str,
    dst_ip: str,
    dst_port: int,
    features: Dict[str, float],
    api_url: str = "http://localhost:8000",
) -> bool:
    """
    Convenience functional wrapper to transmit a flow payload.
    """
    global _default_client
    if _default_client is None or _default_client.api_url != api_url.rstrip("/"):
        _default_client = FlowClient(api_url=api_url)

    return _default_client.send_flow(
        src_ip=src_ip,
        dst_ip=dst_ip,
        dst_port=dst_port,
        features=features,
    )
