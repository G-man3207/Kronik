The configured KMS source could not finish within `[keys] start_timeout`. This is one total window for loading the key, including verification of a newly wrapped seed. Kronik does not write a plaintext key or create a fallback key when the provider is unavailable.

Check the provider endpoint, credentials or instance identity, wrapping-key permissions and whether the recorded provider key version remains enabled. The key reference in the envelope must match the configured source and key. Unsupported local credential sources are configuration errors, not service outages; their safe variable or credential-type name is reported without the value.

The KMS is needed when loading a key and when wrapping or rewrapping it. Once the daemon starts, ordinary turns and keystore shipping use its loaded key and make no KMS requests. A restart during a KMS outage cannot load the seed and is an installation outage.

Use `kronik keys status` for the loaded source, and `kronik doctor --config <file>` to check it. Keep wrapping-key versions enabled while retained backups need them. Losing the wrapping key loses the encrypted data.
