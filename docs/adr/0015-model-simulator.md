# 0015. The model simulator: an OpenAI-compatible endpoint, no personal data, cached per proposal

- **Status:** Accepted
- **Date:** 2026-10-26

## Context

M12's `ModelSimulator` asks a configured model for an answer to an effect
without a recording, using recorded examples for the target. It is off by
default and must never see personal data (the criterion: never a sealed
value). The brief leaves open which models and providers it supports
(open question, M12). A model's answer is not deterministic, but the same
proposal run twice must give a byte-identical diff. Tests must not call a
paid API.

## Decision

- **Protocol**: the OpenAI chat completions request and response shape
  (`POST <endpoint>` with `model`, `messages`, `temperature: 0`;
  `choices[0].message.content`), which OpenAI, Ollama, vLLM and llama.cpp
  servers all accept. The answer must be a JSON object `{"status",
  "headers", "body"}`; anything else is a refusal.
- **Where it is configured**: the endpoint, model name, the name of an
  environment variable holding the API key, the timeout and the number of
  examples are server settings (`[simulators.model]` in `kronik.toml`), like
  the object store endpoint: infrastructure, and the key never enters the log.
  Whether a target may use the model is history (`SimulatorConfig.model`,
  ADR 0014). Both are needed.
- **Calls** go through `Env::net` like `[fork] live_allowlist` GETs, so the
  daemon's network seam (and DST) applies. Forks still make no live
  effect for the guest (I7): the model's answer is synthetic.
- **No personal data**: recorded examples qualify only from production
  turns that show no subject or sealed value anywhere (input, effects,
  writes, messages, timers, reply) and ran no SQL, with a plain,
  subject-free request and response and no secret header. State reads are
  not recorded, so a turn without a subject may still have copied personal
  data into a request: while privacy mode is on, or was on in the window,
  no examples are sent unless `[simulators.model] examples_under_privacy =
  true`. The request qualifies only if the turn has seen no subject (its
  request, its root input, its state reads, earlier effect results,
  `actor.call` replies) and no secret (`secret.reveal` or a crypto effect
  with a secret), and ran no SQL. Otherwise the simulator declines.
  Credentials are stripped from URLs, sensitive request headers are dropped,
  and of a recorded response only `content-type` is shown.
- **No secrets (I8)**: a request whose serialized prompt, URL or body holds
  the value of any secret in the store is never sent (a refusal), and secret
  values in the model's answer are replaced by `[secret:<name>]` before the
  answer is cached or recorded.
- **Cache** per proposal (`branches/<id>/simulator-cache.json`) and per
  (target, fingerprint), loaded before a replay and written durably after
  it and after a message into the fork (a synced temporary file, a rename
  and a directory sync); one call per key even with parallel workers;
  refusals are cached too. A cache file that cannot be read or parsed fails
  the replay rather than silently asking the model again. A dry run never
  calls the model and writes no cache.

## Alternatives

- **A provider-specific client (Anthropic, OpenAI SDKs).** More code and
  dependencies; the chat completions shape covers local and hosted models.
- **Redacting personal data instead of declining.** Redaction rules can
  miss data a guest copied into a URL or body; declining is the only rule a
  test can prove.
- **Caching per fingerprint across proposals.** Two proposals would share
  answers from a model that may have changed, and deleting one proposal
  would change another's diff.

## Consequences

- A proposal's diff is reproducible as long as its cache file exists; a
  fresh proposal over the same window may get different model answers.
- Turns that touch personal data never get model answers; their effects
  fall to `FailClosed` (or an earlier simulator) and the diff says so.
- Tests run a local fake server that records what it receives.
