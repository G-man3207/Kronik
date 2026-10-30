The secret value or complete retained-secret inventory needed by this operation is unavailable. Kronik refuses the affected effect or redaction-dependent response rather than returning an unsanitized success body or substituting another version.

Typical causes include an unavailable external backend, denied access to a required immutable version, or a local secret-store value that cannot be decrypted. A successfully empty inventory is different from a failed or incomplete inventory.

Check `kronik doctor`, the configured backend and access to the required retained versions. Retry after coverage is restored; a destroyed old version cannot be replaced with the backend's current value. Metadata-only health and key status remain available, and turns that need no linked secret do not wait for provider recovery.

This is not `KEY_SOURCE_UNAVAILABLE`: that code concerns loading the master seed. Do not switch master-key sources or create a fallback key to work around missing secret coverage.
