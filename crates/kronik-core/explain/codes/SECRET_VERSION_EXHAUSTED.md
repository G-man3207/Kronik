# SECRET_VERSION_EXHAUSTED

The next immutable version would exceed 9,007,199,254,740,991 (`2^53−1`). This bound is positive in SQLite and exactly representable in the existing numeric JSON API.

Use a new secret name and update the relevant grants and application configuration deliberately. Do not reset a counter, remove failed reservations or rewrite the version ledger: doing so could make an old recorded reference resolve to another value. Migrated legacy data reserves the old `u32` range and can continue above it; that normal migration is not exhaustion.
