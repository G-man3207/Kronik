# SECRET_VERSION_GONE

Kronik cannot recover the exact immutable secret identity recorded for this operation. The value may have been destroyed, an environment value may have changed across restart, access may have been revoked, or the trusted backend binding/reference may no longer match.

Restore access to the matching backend configuration and exact retained version where possible. Never substitute the current value, another reference or a plaintext fallback: that would change an already recorded outcome. A recorded successful reveal or resend stops before exposing a different guest result. Missing values also keep scrub-dependent publication incomplete rather than allowing unsanitized output.

The node's encrypted scrub-only copy of the version (ADR 0142) does not help here: it is for scrubbing only and never answers an effect. It does keep the reads that need scrubbing working after a restart; only a version without a copy (recorded by an earlier release) leaves them at 503 `SECRET_UNAVAILABLE` until the provider serves it again.
