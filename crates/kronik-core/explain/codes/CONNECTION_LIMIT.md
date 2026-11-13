The gateway refused to open a WebSocket or SSE connection because it already holds as many as it may: in total (`[connections] max_open`, which the open-file limit can lower further), for the actor that the route names (`max_per_actor`), or for the client's address (`max_per_client`; clients behind `[gateway] trusted_proxies` are not counted per address). No turn ran and nothing was recorded. The answer is 503 with `retry-after: 5`.

Clients should reconnect with jittered backoff. Operators who expect more connections raise the limits in `kronik.toml` and give the daemon a higher open-file limit (the shipped unit has `LimitNOFILE=65536`); `kronik doctor` warns when the open-file limit is below `max_open`.

    kronik doctor

See also: `connections`, `UNAVAILABLE`.
