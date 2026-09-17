"""
Reference CDR collector for SIPhon — a runnable example of the HTTP webhook
sink, built on the typed record in `siphon_sdk.cdr`.

This is **illustrative**: an in-memory dict stands in for the database a real
collector writes to. What is not illustrative is the shape — `CallDetailRecord`
mirrors the Rust struct siphon serializes, so the parsing here is what a
production collector does.

Two things worth copying:

* The handler takes `payload: dict`, not the dataclass. Custom fields from
  `cdr.write(extra={...})` are flattened into the top level of the JSON, and a
  validating body model drops them before the handler runs. `from_dict` keeps
  them in `record.extra`.
* A `MEDIA` record is joined to the call record on `call_id` — it carries the
  per-leg quality figures and no URIs.

Answer fast and always: there is no retry and no durable queue behind the HTTP
sink, so a record this endpoint rejects or times out on is gone. Do the slow
work (database, billing) off the request path, and keep a `file` sink beside the
`http` one for durability.

Run:
    pip install fastapi uvicorn siphon-sip
    uvicorn examples.cdr_collector:app --host 0.0.0.0 --port 8080

Point siphon at it:
    cdr:
      enabled: true
      auto_emit: true
      backends:
        - type: file
          path: /var/log/siphon/cdr.jsonl
        - type: http
          url: http://collector.example.com:8080/cdr
          auth_header: "Bearer ..."
"""
from __future__ import annotations

from fastapi import FastAPI

from siphon_sdk.cdr import CallDetailRecord

app = FastAPI(title="SIPhon CDR reference collector")

CALLS: dict[str, CallDetailRecord] = {}


def store_call(record: CallDetailRecord) -> None:
    """A finished call leg — replace with your billing / reporting write."""
    CALLS[record.call_id] = record
    billing_id = record.extra.get("billing_id", "-")
    print(
        f"call {record.call_id} {record.method} -> {record.response_code} "
        f"{record.duration_secs:.1f}s "
        f"ended_by={record.disconnect_initiator or '-'} billing_id={billing_id}"
    )


def store_media(record: CallDetailRecord) -> None:
    """End-of-call media quality, joined to the call record on Call-ID."""
    call = CALLS.get(record.call_id)
    known = f"{call.from_uri} -> {call.to_uri}" if call else "call record not seen (yet)"
    print(f"media {record.call_id} {known} reason={record.media_reason}")
    for leg in record.media_legs:
        if leg.mos_average is None:
            # A relay leg with no userspace actor reports counters only.
            print(f"  {leg.role:5} {leg.codec or '-':8} {leg.packets_in} pkts in")
            continue
        print(
            f"  {leg.role:5} {leg.codec or '-':8} "
            f"mos={leg.mos_average:.2f} (min {leg.mos_min:.2f}, {leg.mos_basis}) "
            f"loss={leg.loss_percent:.2f}% jitter={leg.jitter_ms:.1f}ms"
        )


def store_registration(record: CallDetailRecord) -> None:
    """A registrar state change (`cdr.include_register`)."""
    print(f"registration {record.to_uri} {record.reg_event}")


@app.post("/cdr")
async def collect(payload: dict) -> dict:
    record = CallDetailRecord.from_dict(payload)
    if record.is_media:
        store_media(record)
    elif record.is_register:
        store_registration(record)
    else:
        store_call(record)
    return {"ok": True}
