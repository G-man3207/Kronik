# KEY_HELPER_FAILED

The optional PKCS#11 helper was unavailable or returned a bounded failure code. Kronik did not substitute a file/environment seed, replace the envelope, or continue with an unlocked key. A failed PIN or authentication request is not retried automatically: repeated attempts can lock a token.

Check the configured helper executable, module path and SHA-256 load-integrity digest, private `pin_file`, exact token manufacturer/model/serial, unique AES-256 key ID, key version and enrolled possession probe. The PIN travels only over the helper's private descriptor; one optional final LF is removed. Never put it in arguments, environment variables, configuration text or diagnostics. Fix the cause deliberately before retrying.

Keep the original key and probe. A replacement object with the same label or ID is not the enrolled key. Module security updates may change the trusted path/digest without changing cryptographic key identity; they must still load the same token/key and pass the original probe. The helper is a Linux capability; ordinary file/environment sources remain available on supported development platforms.

`kronik keys enroll --config <file>` verifies an existing configured probe, or prints a non-secret probe for a previously unenrolled configuration. It does not load or change the master seed. Normal startup, wrap, rewrap and restore require the probe. Retained envelopes and backups still need their matching wrapping key; losing it loses the encrypted data.
