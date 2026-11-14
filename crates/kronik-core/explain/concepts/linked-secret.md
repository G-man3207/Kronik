A linked secret is a secret name bound to an external backend (M23): OpenBao or Vault, AWS Secrets Manager, GCP Secret Manager or Azure Key Vault, configured in `[secrets.backends.<id>]`. `kronik secret link` records the binding as a log record, and guest code uses the name like any other secret handle: the value never enters guest memory or the log. The node reads values through an in-memory cache, refreshed every `[secrets] refresh`; an effect records the version it used, so `history` shows a rotation as a new version. While a backend is unavailable, a value that was authorized stays in use for up to `[secrets] max_stale`; after that, or after a definitive refusal, the effect fails with `SECRET_UNAVAILABLE`. A fork never fetches: it uses only a value the cache already holds for the fork point's link. A version the backend later destroys is still removed from what the views show, from an encrypted, scrub-only copy that never answers an effect.

    kronik secret link stripe-key --backend vault --ref secret/stripe#api_key --reason "keep it in Vault"
    kronik secret backends

See also: `secret-handle`, `SECRET_UNAVAILABLE`.
