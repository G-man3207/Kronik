# SECRET_VERSION_GONE

Kronik cannot recover the exact immutable secret identity recorded for this operation. The value may have been destroyed, an environment value may have changed across restart, access may have been revoked, or the trusted backend binding/reference may no longer match.

Restore access to the matching backend configuration and exact retained version where possible. Never substitute the current value, another reference or a plaintext fallback: that would change an already recorded outcome. A recorded successful reveal or resend stops before exposing a different guest result. Missing values also keep scrub-dependent publication incomplete rather than allowing unsanitized output.

The same loss leaves the reads that need scrubbing at 503 `SECRET_UNAVAILABLE` after the next restart, until the provider serves the version again; that is a known defect. To rotate an `env` secret, link the name to a new variable and keep every variable it has used at its recorded value.
