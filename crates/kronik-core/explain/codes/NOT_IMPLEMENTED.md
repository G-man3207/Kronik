The operation is part of Kronik's design but not available in this version, for example the `microvm` isolation level, which is reserved in v0.1, or an API endpoint that a later milestone adds.

To fix it, use what this version supports, for example the `gvisor` isolation level instead of `microvm`. `kronik --version` shows which version you run:

    kronik --version

See also: `isolation-level`.
