# fake-payments

A small payments service run as a foreign actor; the billing examples
charge invoices with it and refund them as compensation. No money moves. It
is a standalone Cargo project (std only, no dependencies), not part of the
`examples/` workspace.

```text
fake-payments [--listen ADDR] [--data-dir DIR]    defaults: 0.0.0.0:8080, /data
```

| Endpoint | Answer |
|---|---|
| `GET /healthz` | `200 ok` |
| `POST /v1/charges` `{"customer","invoice","amount","currency"}` | `201 {"id":"ch_...","customer","invoice","amount","currency","status":"succeeded"}` |
| `GET /v1/charges/{id}` | `200` the charge (`status` becomes `refunded` once refunded), or `404` |
| `POST /v1/refunds` `{"charge":"ch_..."}` | `201 {"id":"re_...","charge","amount","status":"succeeded"}`, `404` unknown charge, `409` already refunded |

- **Validation**: `amount` is an integer in minor units, greater than 0;
  `currency` is 3 uppercase letters; `customer` and `invoice` are non-empty
  strings. Otherwise `400 {"error":{"code":"invalid_request","message"}}`.
- **Declines**: a customer id starting with `declined` gets
  `402 {"error":{"code":"card_declined","message"}}`.
- **Idempotency**: with an `Idempotency-Key` header, the first answer
  (success or decline) is saved with a hash of the method, path and body.
  The same key with the same request replays the saved body with
  `Idempotent-Replayed: true`: status `200` for a saved success, the saved
  status for a saved decline (so a retried declined charge still fails). The
  same key with a different request is
  `409 {"error":{"code":"idempotency_key_reused"}}`. Validation errors, `404`
  and `409` are not saved. Ids are the first 16 hex digits of
  SHA-256(key) when there is a key, else a counter.
- **Auth**: when `PAYMENTS_API_KEY` is set, every `/v1/*` request needs
  `Authorization: Bearer <key>`, else `401 {"error":{"code":"unauthorized"}}`.
- **State**: charges, refunds and idempotency records are written to
  `DIR/payments.json` (temporary file, then rename) after every change and
  loaded at start. A missing or unwritable directory logs a warning and keeps
  state in memory only; a corrupt file stops the service from starting.

Build the image with `scripts/build-foreign-examples.sh` (it writes
`examples/dist/fake-payments.oci`, `fake-payments:dev`, running as `nobody`
on port 8080). For local development: `cargo test` and
`cargo run -- --listen 127.0.0.1:18081 --data-dir /var/tmp/payments-data`.
