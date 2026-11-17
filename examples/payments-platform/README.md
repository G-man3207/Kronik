# Payments platform (dogfood)

Reference scenarios for issue [#136](https://github.com/G-man3207/Kronik/issues/136):
realistic billing-ts traffic, fork/replay/diff, and propose expectations.

| # | Scenario | Demo | Expected diff |
|---|----------|------|---------------|
| 1 | Pure refactor | [`demo/payments-platform-pure-refactor.sh`](../demo/payments-platform-pure-refactor.sh) | Empty (`divergent_turns` 0, policy `allow`) |
| 2 | EU VAT rule | [`demo/payments-platform-eu-vat.sh`](../demo/payments-platform-eu-vat.sh) | Four divergent turns (DE, US); two payment consequences; policy `require_approval` |
| 3 | Inserted outbound call | [`demo/payments-platform-reorder.sh`](../demo/payments-platform-reorder.sh) | Three `effects.added` tail items (live GET `payments.internal/healthz`); six divergent turns; policy blocks promotion |

The scenarios reuse [`billing-ts`](../billing-ts/) and [`fake-payments`](../fake-payments/)
rather than a separate app tree. More scenarios from #136 will land here as the
library grows.