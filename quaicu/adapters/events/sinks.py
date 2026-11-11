"""Event-bus sinks — record every sealed governed action to an external stream (K·07).

These are `EventBus` subscribers (``Callable[[Action, LedgerEntry], Any]``) registered via
``event_bus.subscribe(...)``. They give a **durable, queryable record of every governed decision even
when the ledger is in-memory**: the kernel emits a `LedgerEntry` after each seal, and
these sinks fan it out off-box.

- `LoggingEventSink` — writes one structured audit line per action to the ``quaicu.audit`` logger. On
  Cloud Run / Kubernetes the stdout line is captured by the platform's logging (Cloud Logging), so no
  database is required to see "what each client's product is doing". Pure stdlib, zero dependencies.
- `PubSubEventSink` — publishes each action as JSON to a GCP Pub/Sub topic for fan-out to BigQuery /
  SIEM / Chronicle. Lazy ``google-cloud-pubsub`` (``[gcp]`` extra); publisher injectable for tests.

Both are **best-effort** (the contract for K·07 emit): a sink failure is logged, never raised into the
seal path. Wire them config-driven via ``[events].log_sink`` / ``[events].pubsub_topic`` (see
``Kernel.from_config``).
"""

from __future__ import annotations

import json
import logging
import threading
import urllib.request
from collections.abc import Callable, Mapping
from typing import Any

from quaicu.core.types import Action, Decision, LedgerEntry

audit_log = logging.getLogger("quaicu.audit")
log = logging.getLogger("quaicu.events")


def _entry_record(entry: LedgerEntry) -> dict[str, Any]:
    """A JSON-serializable record of a sealed governed action (the durable audit shape)."""
    decision = entry.decision.value if isinstance(entry.decision, Decision) else str(entry.decision)
    return {
        "event": "governed_action",
        "ledger_seq": entry.ledger_seq,
        "tenant": str(entry.tenant),
        "action_id": str(entry.action_id),
        "action_type": entry.action_type,
        "actor_id": str(entry.actor_id),
        "decision": decision,
        "policy_versions": list(entry.policy_versions),
        "leaf_hash": entry.leaf_hash.hex(),
        "sealed_at": entry.sealed_at.isoformat(),
    }


class LoggingEventSink:
    """Log one structured audit line per sealed governed action (→ Cloud Logging on managed hosts)."""

    def __init__(self, *, logger: logging.Logger | None = None, level: int = logging.INFO) -> None:
        self._log = logger or audit_log
        self._level = level

    def __call__(self, action: Action, entry: LedgerEntry) -> None:
        rec = _entry_record(entry)
        # Human-readable message + structured `extra` (mirrors RequestLoggingMiddleware's pattern).
        self._log.log(
            self._level,
            "governed_action sealed seq=%s tenant=%s action=%s type=%s decision=%s",
            rec["ledger_seq"], rec["tenant"], rec["action_id"], rec["action_type"], rec["decision"],
            extra=rec,
        )


class PubSubEventSink:
    """Publish each sealed governed action as JSON to a GCP Pub/Sub topic (best-effort)."""

    def __init__(self, topic: str, *, publisher: Any | None = None) -> None:
        self._topic = topic
        if publisher is None:
            from google.cloud import pubsub_v1  # lazy ([gcp] extra)

            publisher = pubsub_v1.PublisherClient()
        self._publisher = publisher

    def __call__(self, action: Action, entry: LedgerEntry) -> None:
        data = json.dumps(_entry_record(entry)).encode("utf-8")
        try:
            self._publisher.publish(self._topic, data)  # fire-and-forget; returns a future
        except Exception as exc:  # noqa: BLE001 — emit must never fail on a best-effort sink
            log.warning("PubSubEventSink publish failed (topic=%s): %s", self._topic, exc)


class EventBridgeEventSink:
    """Publish each sealed governed action to an AWS EventBridge bus via ``put_events`` (best-effort).

    boto3 is lazily imported (``[aws]`` extra) and the client is injectable for tests. Routes/rules on
    the bus fan the events out to a SIEM / Kinesis / Lambda / CloudWatch downstream.
    """

    def __init__(
        self,
        event_bus: str,
        *,
        source: str = "quaicu.governance",
        detail_type: str = "GovernedAction",
        client: Any | None = None,
    ) -> None:
        self._bus = event_bus
        self._source = source
        self._detail_type = detail_type
        if client is None:
            import boto3  # lazy ([aws] extra)

            client = boto3.client("events")
        self._client = client

    def __call__(self, action: Action, entry: LedgerEntry) -> None:
        detail = json.dumps(_entry_record(entry))
        try:
            self._client.put_events(
                Entries=[
                    {
                        "Source": self._source,
                        "DetailType": self._detail_type,
                        "Detail": detail,
                        "EventBusName": self._bus,
                    }
                ]
            )
        except Exception as exc:  # noqa: BLE001 — emit must never fail on a best-effort sink
            log.warning("EventBridgeEventSink put_events failed (bus=%s): %s", self._bus, exc)


# Sync HTTP POST signature for the webhook sink (so tests inject a recording stub).
WebhookPost = Callable[[str, bytes, Mapping[str, str]], Any]


def _threaded_urllib_post(url: str, body: bytes, headers: Mapping[str, str]) -> None:
    """Fire-and-forget POST on a daemon thread so a slow SIEM never blocks the seal path."""

    def _send() -> None:
        try:
            req = urllib.request.Request(url, data=body, headers=dict(headers), method="POST")
            urllib.request.urlopen(req, timeout=5)  # noqa: S310 — operator-configured SIEM URL
        except Exception as exc:  # noqa: BLE001 — best-effort
            log.warning("WebhookEventSink POST failed (url=%s): %s", url, exc)

    threading.Thread(target=_send, daemon=True).start()


class WebhookEventSink:
    """POST each sealed governed action (as JSON) to any SIEM HTTP endpoint (Splunk HEC, Datadog,
    Sumo, a generic collector). ``post`` is injectable; the default is a fire-and-forget urllib POST."""

    def __init__(
        self,
        url: str,
        *,
        headers: Mapping[str, str] | None = None,
        post: WebhookPost | None = None,
    ) -> None:
        self._url = url
        self._headers = {"Content-Type": "application/json", **dict(headers or {})}
        self._post = post or _threaded_urllib_post

    def __call__(self, action: Action, entry: LedgerEntry) -> None:
        body = json.dumps(_entry_record(entry)).encode("utf-8")
        try:
            self._post(self._url, body, self._headers)
        except Exception as exc:  # noqa: BLE001 — emit must never fail on a best-effort sink
            log.warning("WebhookEventSink dispatch failed (url=%s): %s", self._url, exc)
