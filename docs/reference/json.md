# JSON output

<!-- Generated from crates/kronik/src/cli/schemas.rs and the API's types by
`KRONIK_UPDATE_DOCS=1 cargo test -p kronik --bin kronik json_output`.
Edit those, not this file; the test fails when it is out of date. -->

With `--json`, every command prints one JSON object on stdout, so a script
never parses the human output. A client command prints the JSON API's
response body unchanged, so its schema is that of the operation it calls,
as in [openapi.json](openapi.json), the OpenAPI 3.1 description that
`GET /v1/openapi.json` serves. `explain`, `doctor`, `init`, `build`,
`restore`, `upgrade check` and `audit verify` answer themselves. A
failure prints the [`Error`](#error) object instead, with exit code 1,
except `upgrade check`, which prints its report either way and exits 1
when the replay is not empty (`code` is `ENGINE_UPGRADE_DIVERGED`), and
`audit verify`, which prints its report either way and exits 1 when it
is not `complete`. The
schemas are JSON Schema 2020-12; `$ref`s name the definitions below.

Two bodies are not generated from types but written by hand, and also
stand alone for validators: the behavior diff,
[diff-v1.schema.json](diff-v1.schema.json) (`kronik diff show --json`,
[`Diff`](#diff) below), and the turn JSON of `GET /v1/turns/{id}`,
[turn.schema.json](turn.schema.json). Tests validate real diffs and turns
against both.

| Command | `--json` prints |
| --- | --- |
| `kronik serve` | no JSON: the daemon; it refuses --json |
| `kronik doctor` | [`Report`](#report), from the CLI itself |
| `kronik restore` | [`RestoreOutput`](#restoreoutput), from the CLI itself |
| `kronik upgrade check` | [`UpgradeCheckOutput`](#upgradecheckoutput), from the CLI itself |
| `kronik init` | [`Created`](#created), from the CLI itself |
| `kronik build` | [`BuildOutput`](#buildoutput), from the CLI itself |
| `kronik deploy` | [`DeployResponse`](#deployresponse) (`POST /v1/deployments`) |
| `kronik deployments list` | [`DeploymentsResponse`](#deploymentsresponse) (`GET /v1/deployments`) |
| `kronik send` | [`TurnResponse`](#turnresponse) (`POST /v1/actors/{kind}/{key}/messages`); with --fork: [`ForkTurnResponse`](#forkturnresponse) (`POST /v1/forks/{name}/actors/{kind}/{key}/messages`) |
| `kronik actors list` | [`ActorsResponse`](#actorsresponse) (`GET /v1/actors`) |
| `kronik actors inspect` | [`InspectResponse`](#inspectresponse) (`GET /v1/actors/{kind}/{key}`) |
| `kronik actors timers` | [`TimersResponse`](#timersresponse) (`GET /v1/actors/{kind}/{key}/timers`) |
| `kronik history` | [`HistoryResponse`](#historyresponse) (`GET /v1/actors/{kind}/{key}/history`); with --orphans: [`OrphansResponse`](#orphansresponse) (`GET /v1/orphans`) |
| `kronik trace` | [`TraceResponse`](#traceresponse) (`GET /v1/turns/{id}/trace`) |
| `kronik dead-letters list` | [`DeadLettersResponse`](#deadlettersresponse) (`GET /v1/dead-letters`) |
| `kronik dead-letters resend` | [`TurnResponse`](#turnresponse) (`POST /v1/dead-letters/{id}/resend`) |
| `kronik grant` | [`GrantResponse`](#grantresponse) (`POST /v1/grants`) |
| `kronik revoke` | [`RevokeResponse`](#revokeresponse) (`POST /v1/grants/revoke`) |
| `kronik grants list` | [`GrantsResponse`](#grantsresponse) (`GET /v1/grants`) |
| `kronik limits set` | [`LimitsResponse`](#limitsresponse) (`POST /v1/limits`) |
| `kronik limits show` | [`LimitsListResponse`](#limitslistresponse) (`GET /v1/limits`) |
| `kronik secret set` | [`SecretResponse`](#secretresponse) (`PUT /v1/secrets/{name}`) |
| `kronik secret list` | [`SecretsResponse`](#secretsresponse) (`GET /v1/secrets`) |
| `kronik secret delete` | [`SecretDeleteResponse`](#secretdeleteresponse) (`DELETE /v1/secrets/{name}`) |
| `kronik fork create` | [`ForkCreateResponse`](#forkcreateresponse) (`POST /v1/forks`) |
| `kronik fork list` | [`ForksResponse`](#forksresponse) (`GET /v1/forks`) |
| `kronik fork deploy` | [`ForkDeployResponse`](#forkdeployresponse) (`POST /v1/forks/{name}/deployments`) |
| `kronik fork delete` | [`ForkDeleteResponse`](#forkdeleteresponse) (`DELETE /v1/forks/{name}`) |
| `kronik replay` | [`ReplayResponse`](#replayresponse) (`POST /v1/forks/{name}/replay`) |
| `kronik diff show` | with a proposal: [`Diff`](#diff) (`GET /v1/proposals/{id}/diff`); with a fork: [`Diff`](#diff) (`GET /v1/forks/{name}/diff`) |
| `kronik propose` | [`ProposeResponse`](#proposeresponse) (`POST /v1/proposals`) |
| `kronik proposals list` | [`ProposalsResponse`](#proposalsresponse) (`GET /v1/proposals`) |
| `kronik proposals show` | [`ProposalInfo`](#proposalinfo) (`GET /v1/proposals/{id}`) |
| `kronik proposal status` | [`ProposalInfo`](#proposalinfo) (`GET /v1/proposals/{id}`) |
| `kronik proposal wait` | [`ProposalInfo`](#proposalinfo) (`GET /v1/proposals/{id}`) |
| `kronik approve` | [`ApproveResponse`](#approveresponse) (`POST /v1/proposals/{id}/approve`) |
| `kronik promote` | [`PromoteResponse`](#promoteresponse) (`POST /v1/proposals/{id}/promote`) |
| `kronik rollback` | [`RollbackResponse`](#rollbackresponse) (`POST /v1/deployments/{epoch}/rollback`); with --by-replay: [`ProposeResponse`](#proposeresponse) (`POST /v1/deployments/{epoch}/rebase`) |
| `kronik watch` | [`WatchInfo`](#watchinfo) (`GET /v1/watches/{id}`); with with --async or --dry-run: [`WatchResponse`](#watchresponse) (`POST /v1/deployments/{epoch}/watch`) |
| `kronik watches list` | [`WatchesResponse`](#watchesresponse) (`GET /v1/watches`) |
| `kronik watches show` | [`WatchInfo`](#watchinfo) (`GET /v1/watches/{id}`) |
| `kronik watches stop` | [`WatchResponse`](#watchresponse) (`POST /v1/watches/{id}/stop`) |
| `kronik policy show` | [`PolicyResponse`](#policyresponse) (`GET /v1/policy`) |
| `kronik policy set` | [`PolicySetResponse`](#policysetresponse) (`PUT /v1/policy`) |
| `kronik policy test` | [`PolicyEvaluation`](#policyevaluation) (`POST /v1/policy/test`) |
| `kronik preview create` | [`PreviewCreateResponse`](#previewcreateresponse) (`POST /v1/previews`) |
| `kronik preview list` | [`PreviewsResponse`](#previewsresponse) (`GET /v1/previews`) |
| `kronik preview delete` | [`PreviewDeleteResponse`](#previewdeleteresponse) (`DELETE /v1/previews/{id}`) |
| `kronik token create` | [`TokenCreateResponse`](#tokencreateresponse) (`POST /v1/tokens`) |
| `kronik token list` | [`TokensResponse`](#tokensresponse) (`GET /v1/tokens`) |
| `kronik token revoke` | [`TokenRevokeResponse`](#tokenrevokeresponse) (`POST /v1/tokens/{name}/revoke`) |
| `kronik foreign add` | [`ForeignAddResponse`](#foreignaddresponse) (`POST /v1/foreign`) |
| `kronik foreign list` | [`ForeignListResponse`](#foreignlistresponse) (`GET /v1/foreign`) |
| `kronik foreign logs` | [`ForeignLogsResponse`](#foreignlogsresponse) (`GET /v1/foreign/{name}/logs`) |
| `kronik foreign remove` | [`ForeignRemoveResponse`](#foreignremoveresponse) (`DELETE /v1/foreign/{name}`) |
| `kronik foreign cleanup` | [`CleanupOutput`](#cleanupoutput), from the CLI itself |
| `kronik stubs set` | [`SimulatorsSetResponse`](#simulatorssetresponse) (`PUT /v1/simulators/{target}`) |
| `kronik simulators list` | [`SimulatorsResponse`](#simulatorsresponse) (`GET /v1/simulators`) |
| `kronik privacy mode` | [`PrivacyModeResponse`](#privacymoderesponse) (`POST /v1/privacy/mode`) |
| `kronik privacy status` | [`PrivacyStatus`](#privacystatus) (`GET /v1/privacy`) |
| `kronik privacy erase` | [`ErasureResponse`](#erasureresponse) (`POST /v1/privacy/erase`) |
| `kronik privacy reseal` | [`ResealResponse`](#resealresponse) (`POST /v1/privacy/reseal`) |
| `kronik snapshot list` | [`SnapshotsResponse`](#snapshotsresponse) (`GET /v1/snapshots`) |
| `kronik snapshot create` | [`SnapshotCreateResponse`](#snapshotcreateresponse) (`POST /v1/snapshots`) |
| `kronik integrity` | [`IntegrityResponse`](#integrityresponse) (`GET /v1/integrity`) |
| `kronik export status` | [`ExportStatusResponse`](#exportstatusresponse) (`GET /v1/export`) |
| `kronik export rewind` | [`ExportRewindResponse`](#exportrewindresponse) (`POST /v1/export/{stream}/rewind`) |
| `kronik audit show` | [`AuditResponse`](#auditresponse) (`GET /v1/audit`) |
| `kronik audit verify` | [`Report2`](#report2), from the CLI itself |
| `kronik mcp` | no JSON: MCP's JSON-RPC on stdout instead |
| `kronik explain` | [explain output](#explain-output), from the CLI itself |

## Schemas

### explain output

```json
{
  "oneOf": [
    {
      "$ref": "#/components/schemas/Topic"
    },
    {
      "$ref": "#/components/schemas/TopicList"
    }
  ]
}
```

### Actor

```json
{
  "properties": {
    "key": {
      "type": "string"
    },
    "kind": {
      "type": "string"
    },
    "last_turn_id": {
      "type": "string"
    },
    "schema_version": {
      "format": "uint32",
      "minimum": 0,
      "type": "integer"
    },
    "sql": {
      "type": "boolean"
    },
    "turns": {
      "format": "uint64",
      "minimum": 0,
      "type": "integer"
    }
  },
  "required": [
    "kind",
    "key",
    "schema_version",
    "turns",
    "last_turn_id",
    "sql"
  ],
  "type": "object"
}
```

### ActorsResponse

```json
{
  "properties": {
    "actors": {
      "items": {
        "$ref": "#/components/schemas/Actor"
      },
      "type": "array"
    },
    "next": {
      "description": "`kind/key` to pass as `after` for the next page.",
      "type": [
        "string",
        "null"
      ]
    }
  },
  "required": [
    "actors"
  ],
  "type": "object"
}
```

### ApprovalInfo

```json
{
  "properties": {
    "diff_hash": {
      "type": "string"
    },
    "lsn": {
      "format": "uint64",
      "minimum": 0,
      "type": "integer"
    },
    "proposal_id": {
      "type": "string"
    },
    "verified_through_lsn": {
      "format": "uint64",
      "minimum": 0,
      "type": "integer"
    }
  },
  "required": [
    "proposal_id",
    "diff_hash",
    "verified_through_lsn",
    "lsn"
  ],
  "type": "object"
}
```

### ApprovalRequestInfo

```json
{
  "properties": {
    "command": {
      "type": "string"
    },
    "lsn": {
      "format": "uint64",
      "minimum": 0,
      "type": "integer"
    },
    "pending": {
      "description": "No approval followed it yet.",
      "type": "boolean"
    },
    "reason": {
      "type": "string"
    },
    "token_id": {
      "type": "string"
    }
  },
  "required": [
    "lsn",
    "command",
    "token_id",
    "reason",
    "pending"
  ],
  "type": "object"
}
```

### ApproveResponse

```json
{
  "properties": {
    "approval": {
      "$ref": "#/components/schemas/ApprovalInfo"
    },
    "dry_run": {
      "type": "boolean"
    }
  },
  "required": [
    "dry_run",
    "approval"
  ],
  "type": "object"
}
```

### AuditResponse

```json
{
  "description": "`GET /v1/audit`: `kronik.audit/v1` lines in LSN order (m28-otel §4.3).",
  "properties": {
    "applied_lsn": {
      "format": "uint64",
      "minimum": 0,
      "type": "integer"
    },
    "lines": {
      "items": {
        "$ref": "#/components/schemas/Line"
      },
      "type": "array"
    },
    "next": {
      "description": "The `from` of the next page; absent at the applied LSN.",
      "format": "uint64",
      "minimum": 0,
      "type": [
        "integer",
        "null"
      ]
    }
  },
  "required": [
    "lines",
    "applied_lsn"
  ],
  "type": "object"
}
```

### BuildOutput

```json
{
  "description": "What `kronik build --json` prints.",
  "properties": {
    "bytes": {
      "format": "uint64",
      "minimum": 0,
      "type": "integer"
    },
    "cached": {
      "description": "The inputs were unchanged since the last build, so the previous\ncomponent was kept.",
      "type": "boolean"
    },
    "code_hash": {
      "description": "`b3:` and 12 hex characters of the component's BLAKE3 hash, as\n`kronik deploy` and `kronik deployments list` show it.",
      "type": "string"
    },
    "imports": {
      "description": "The interfaces the component imports, all within the allowlist.",
      "items": {
        "type": "string"
      },
      "type": "array"
    },
    "wasm": {
      "description": "The component, relative to the current directory when it is inside\nit.",
      "type": "string"
    }
  },
  "required": [
    "wasm",
    "code_hash",
    "bytes",
    "cached",
    "imports"
  ],
  "type": "object"
}
```

### Check

```json
{
  "properties": {
    "code": {
      "description": "An error code from the catalog, when one applies.",
      "type": [
        "string",
        "null"
      ]
    },
    "hint": {
      "type": [
        "string",
        "null"
      ]
    },
    "message": {
      "type": "string"
    },
    "name": {
      "description": "Stable: config, kernel, runsc, kvm, cgroup, root, disk, clock, tls,\ndns01_hook, ship, export.",
      "type": "string"
    },
    "status": {
      "$ref": "#/components/schemas/Status"
    }
  },
  "required": [
    "name",
    "status",
    "message"
  ],
  "type": "object"
}
```

### CheckpointView

```json
{
  "description": "One checkpoint of a foreign actor (M14).",
  "properties": {
    "at_ms": {
      "format": "uint64",
      "minimum": 0,
      "type": "integer"
    },
    "bytes": {
      "description": "The size of its copy of the data directory.",
      "format": "uint64",
      "minimum": 0,
      "type": "integer"
    },
    "lsn": {
      "description": "Main's LSN the checkpoint is at.",
      "format": "uint64",
      "minimum": 0,
      "type": "integer"
    }
  },
  "required": [
    "lsn",
    "at_ms",
    "bytes"
  ],
  "type": "object"
}
```

### CleanupOutput

```json
{
  "description": "What `kronik foreign cleanup --json` prints: how many leftovers it\nremoved, and how many it could not (then it exits 1).",
  "properties": {
    "configs": {
      "format": "uint64",
      "minimum": 0,
      "type": "integer"
    },
    "failed": {
      "format": "uint64",
      "minimum": 0,
      "type": "integer"
    },
    "namespaces": {
      "format": "uint64",
      "minimum": 0,
      "type": "integer"
    },
    "sandboxes": {
      "format": "uint64",
      "minimum": 0,
      "type": "integer"
    }
  },
  "required": [
    "sandboxes",
    "namespaces",
    "configs",
    "failed"
  ],
  "type": "object"
}
```

### Compensation

```json
{
  "properties": {
    "message_id": {
      "type": "string"
    },
    "state": {
      "description": "pending, dead_letter or done.",
      "type": "string"
    }
  },
  "required": [
    "message_id",
    "state"
  ],
  "type": "object"
}
```

### ContractView

```json
{
  "description": "The contract of a target.",
  "properties": {
    "bytes": {
      "format": "uint64",
      "minimum": 0,
      "type": "integer"
    },
    "digest": {
      "description": "BLAKE3 of the document, `b3:` + hex.",
      "type": "string"
    },
    "title": {
      "description": "The document's `info.title`.",
      "type": [
        "string",
        "null"
      ]
    }
  },
  "required": [
    "digest",
    "bytes"
  ],
  "type": "object"
}
```

### Created

```json
{
  "description": "What `kronik init` made: its `--json` output.",
  "properties": {
    "files": {
      "description": "The files written, relative to the project; the vendored SDK and its\nWIT (`vendor/kronik-sdk`, for Go `kronik-sdk`) are not listed.",
      "items": {
        "type": "string"
      },
      "type": "array"
    },
    "kind": {
      "description": "The project's actor type: the project's name.",
      "type": "string"
    },
    "lang": {
      "description": "`ts`, `rust`, `python` or `go`.",
      "type": "string"
    },
    "next": {
      "description": "The commands that follow, in order.",
      "items": {
        "type": "string"
      },
      "type": "array"
    },
    "project": {
      "description": "The project's directory, relative to the current directory.",
      "type": "string"
    }
  },
  "required": [
    "project",
    "lang",
    "kind",
    "files",
    "next"
  ],
  "type": "object"
}
```

### DeadLetter

```json
{
  "properties": {
    "actor": {
      "type": "string"
    },
    "error_code": {
      "type": "string"
    },
    "id": {
      "type": "string"
    },
    "input": {
      "$ref": "#/components/schemas/InputSummary"
    },
    "message": {
      "type": "string"
    },
    "resent_as": {
      "type": [
        "string",
        "null"
      ]
    }
  },
  "required": [
    "id",
    "actor",
    "input",
    "error_code",
    "message"
  ],
  "type": "object"
}
```

### DeadLettersResponse

```json
{
  "properties": {
    "dead_letters": {
      "items": {
        "$ref": "#/components/schemas/DeadLetter"
      },
      "type": "array"
    }
  },
  "required": [
    "dead_letters"
  ],
  "type": "object"
}
```

### DeployResponse

```json
{
  "properties": {
    "deployment": {
      "$ref": "#/components/schemas/Deployment"
    },
    "dry_run": {
      "type": "boolean"
    },
    "unchanged": {
      "type": "boolean"
    },
    "warnings": {
      "items": {
        "type": "string"
      },
      "type": "array"
    }
  },
  "required": [
    "dry_run",
    "unchanged",
    "deployment",
    "warnings"
  ],
  "type": "object"
}
```

### Deployment

```json
{
  "properties": {
    "capabilities": {
      "items": {
        "type": "string"
      },
      "type": "array"
    },
    "code_hash": {
      "type": "string"
    },
    "epoch": {
      "format": "uint64",
      "minimum": 0,
      "type": "integer"
    },
    "kind": {
      "type": "string"
    },
    "lsn": {
      "description": "0 for dry runs and unchanged deploys.",
      "format": "uint64",
      "minimum": 0,
      "type": "integer"
    },
    "routes": {
      "items": {
        "$ref": "#/components/schemas/Route"
      },
      "type": "array"
    },
    "schema_version": {
      "format": "uint32",
      "minimum": 0,
      "type": "integer"
    }
  },
  "required": [
    "epoch",
    "lsn",
    "kind",
    "code_hash",
    "schema_version",
    "routes",
    "capabilities"
  ],
  "type": "object"
}
```

### DeploymentEntry

```json
{
  "properties": {
    "cause": {
      "type": "string"
    },
    "epoch": {
      "format": "uint64",
      "minimum": 0,
      "type": "integer"
    },
    "kinds": {
      "items": {
        "$ref": "#/components/schemas/DeploymentKind"
      },
      "type": "array"
    },
    "lsn": {
      "format": "uint64",
      "minimum": 0,
      "type": "integer"
    },
    "reason": {
      "default": "",
      "description": "Why, as recorded with the deployment.",
      "type": "string"
    },
    "token_id": {
      "default": "",
      "description": "Who: `token:<name>`, or `unix:uid=<n>` on the socket without a token.",
      "type": "string"
    }
  },
  "required": [
    "epoch",
    "lsn",
    "cause",
    "kinds"
  ],
  "type": "object"
}
```

### DeploymentKind

```json
{
  "properties": {
    "code_hash": {
      "type": "string"
    },
    "kind": {
      "type": "string"
    },
    "schema_version": {
      "format": "uint32",
      "minimum": 0,
      "type": "integer"
    }
  },
  "required": [
    "kind",
    "code_hash",
    "schema_version"
  ],
  "type": "object"
}
```

### DeploymentsResponse

```json
{
  "properties": {
    "deployments": {
      "items": {
        "$ref": "#/components/schemas/DeploymentEntry"
      },
      "type": "array"
    }
  },
  "required": [
    "deployments"
  ],
  "type": "object"
}
```

### Diff

```json
{
  "additionalProperties": false,
  "description": "A behavior diff: how a fork's code behaves on main's root inputs, next to production (docs/design/m3-fork.md §5). The same fork, code and options always give the same bytes, except for answers of copies of foreign actors (`forked`, M14, ADR 0020), which are real and not reproducible. `kronik diff show --md` and `format=md` render the same diff as Markdown.",
  "properties": {
    "base": {
      "$ref": "#/components/schemas/DiffBase"
    },
    "causes": {
      "description": "Sorted by origins descending, then kind, then input.",
      "items": {
        "$ref": "#/components/schemas/DiffCause"
      },
      "type": "array"
    },
    "code": {
      "additionalProperties": false,
      "description": "The code of every changed actor kind, before (production) and after (the fork).",
      "properties": {
        "after": {
          "items": {
            "$ref": "#/components/schemas/DiffCodeEntry"
          },
          "type": "array"
        },
        "before": {
          "items": {
            "$ref": "#/components/schemas/DiffCodeEntry"
          },
          "type": "array"
        }
      },
      "required": [
        "before",
        "after"
      ],
      "type": "object"
    },
    "cumulative": {
      "$ref": "#/components/schemas/DiffCumulative"
    },
    "effects": {
      "$ref": "#/components/schemas/DiffEffects"
    },
    "errors": {
      "$ref": "#/components/schemas/DiffErrors"
    },
    "fork": {
      "description": "The fork: `p-<12 hex>` for a proposal, else the name it was created with.",
      "type": "string"
    },
    "grounding": {
      "description": "One entry per external target, sorted by kind, host and route.",
      "items": {
        "$ref": "#/components/schemas/DiffGroundingRow"
      },
      "type": "array"
    },
    "irreversible": {
      "$ref": "#/components/schemas/DiffIrreversible"
    },
    "kinds": {
      "description": "Each actor kind on its own, sorted by kind: every kind of the fork's code and every kind a replayed turn ran as (M9). Absent from diffs written before M9.",
      "items": {
        "$ref": "#/components/schemas/DiffKind"
      },
      "type": "array"
    },
    "options": {
      "$ref": "#/components/schemas/DiffOptions"
    },
    "proposal_id": {
      "description": "The id the daemon keeps the diff under: the proposal's, or the plain fork's name.",
      "type": [
        "string",
        "null"
      ]
    },
    "resources": {
      "$ref": "#/components/schemas/DiffResources"
    },
    "responses": {
      "$ref": "#/components/schemas/DiffResponses"
    },
    "samples": {
      "$ref": "#/components/schemas/DiffSamples"
    },
    "schema": {
      "const": "kronik.diff/v1"
    },
    "state": {
      "$ref": "#/components/schemas/DiffState"
    },
    "summary": {
      "$ref": "#/components/schemas/DiffSummary"
    }
  },
  "required": [
    "schema",
    "fork",
    "proposal_id",
    "base",
    "code",
    "options",
    "summary",
    "causes",
    "grounding",
    "responses",
    "effects",
    "state",
    "cumulative",
    "errors",
    "resources",
    "samples"
  ],
  "title": "kronik.diff/v1",
  "type": "object"
}
```

### DiffActorState

```json
{
  "additionalProperties": false,
  "properties": {
    "actor": {
      "description": "`<kind>/<key>`.",
      "type": "string"
    },
    "keys": {
      "items": {
        "$ref": "#/components/schemas/DiffKeyChange"
      },
      "maxItems": 200,
      "type": "array"
    },
    "sql": {
      "items": {
        "$ref": "#/components/schemas/DiffSqlChange"
      },
      "maxItems": 200,
      "type": "array"
    }
  },
  "required": [
    "actor",
    "keys",
    "sql"
  ],
  "type": "object"
}
```

### DiffBase

```json
{
  "additionalProperties": false,
  "description": "Where the fork starts and which root inputs ran.",
  "properties": {
    "branch": {
      "description": "The branch the fork was taken from: `main`.",
      "type": "string"
    },
    "fork_lsn": {
      "$ref": "#/components/schemas/DiffCount",
      "description": "The fork point."
    },
    "from_lsn": {
      "$ref": "#/components/schemas/DiffCount",
      "description": "The first main LSN of the window."
    },
    "to_lsn": {
      "$ref": "#/components/schemas/DiffCount",
      "description": "The last main LSN of the window."
    },
    "window_cut": {
      "additionalProperties": false,
      "description": "Present when retention cut the proposal's window short: the window reaches back before the oldest point the log and snapshots still hold, so only the root inputs after `kept_from_lsn` were replayed.",
      "properties": {
        "kept_from_lsn": {
          "$ref": "#/components/schemas/DiffCount",
          "description": "The oldest snapshot the log continues; the fork starts there."
        },
        "window_ms": {
          "$ref": "#/components/schemas/DiffCount",
          "description": "The logical time the proposal asked to replay, back from the newest root input."
        }
      },
      "required": [
        "window_ms",
        "kept_from_lsn"
      ],
      "type": "object"
    }
  },
  "required": [
    "branch",
    "fork_lsn",
    "from_lsn",
    "to_lsn"
  ],
  "type": "object"
}
```

### DiffBodyOp

```json
{
  "additionalProperties": false,
  "properties": {
    "fork": {
      "$ref": "#/components/schemas/DiffValue"
    },
    "op": {
      "enum": [
        "add",
        "remove",
        "replace"
      ]
    },
    "path": {
      "description": "A JSON Pointer (`/a/0/b`); `\"\"` is the whole body.",
      "type": "string"
    },
    "prod": {
      "$ref": "#/components/schemas/DiffValue"
    }
  },
  "required": [
    "op",
    "path",
    "prod",
    "fork"
  ],
  "type": "object"
}
```

### DiffCause

```json
{
  "additionalProperties": false,
  "description": "The differences of one actor kind and input.",
  "properties": {
    "consequences": {
      "$ref": "#/components/schemas/DiffCount"
    },
    "input": {
      "description": "The method and route pattern for HTTP (`POST /counter/{key}/{op}`), else `message <name>` or `timer <name>`.",
      "type": "string"
    },
    "kind": {
      "description": "The actor kind.",
      "type": "string"
    },
    "origins": {
      "$ref": "#/components/schemas/DiffCount"
    },
    "root_inputs": {
      "$ref": "#/components/schemas/DiffCount",
      "description": "Root inputs whose trees differ here."
    },
    "samples": {
      "description": "Fork turns, at most 5.",
      "items": {
        "$ref": "#/components/schemas/DiffTurnId"
      },
      "maxItems": 5,
      "type": "array"
    }
  },
  "required": [
    "kind",
    "input",
    "origins",
    "consequences",
    "root_inputs",
    "samples"
  ],
  "type": "object"
}
```

### DiffCodeEntry

```json
{
  "additionalProperties": false,
  "properties": {
    "code_hash": {
      "description": "The component's hash, shortened: `b3:<12 hex>`.",
      "pattern": "^b3:[0-9a-f]+$",
      "type": "string"
    },
    "kind": {
      "description": "The actor kind.",
      "type": "string"
    },
    "schema_version": {
      "$ref": "#/components/schemas/DiffCount"
    }
  },
  "required": [
    "kind",
    "code_hash",
    "schema_version"
  ],
  "type": "object"
}
```

### DiffCount

```json
{
  "minimum": 0,
  "type": "integer"
}
```

### DiffCumulative

```json
{
  "additionalProperties": false,
  "description": "Differences only continuous replay shows: actors whose final state differs although no single isolated tree explains it, or whose drift grows.",
  "properties": {
    "actors_changed": {
      "$ref": "#/components/schemas/DiffCount"
    },
    "items": {
      "items": {
        "$ref": "#/components/schemas/DiffActorState"
      },
      "maxItems": 200,
      "type": "array"
    }
  },
  "required": [
    "actors_changed",
    "items"
  ],
  "type": "object"
}
```

### DiffEffectItem

```json
{
  "additionalProperties": false,
  "properties": {
    "change": {
      "enum": [
        "added",
        "removed",
        "changed"
      ]
    },
    "fields": {
      "description": "The parts that differ. Secret header values never appear, only their names and version hashes. When the request was recorded under a subject, its url, header and body values appear as `{redacted, subject, hash}` (see DiffValue), like state values.",
      "items": {
        "additionalProperties": false,
        "properties": {
          "field": {
            "description": "`url`, `method`, `header:<name>` or `body`.",
            "type": "string"
          },
          "fork": {
            "$ref": "#/components/schemas/DiffValue"
          },
          "prod": {
            "$ref": "#/components/schemas/DiffValue"
          }
        },
        "required": [
          "field",
          "prod",
          "fork"
        ],
        "type": "object"
      },
      "type": "array"
    },
    "grounding": {
      "description": "How the fork's effect was answered (`forked`: a copy of a foreign actor, M14).",
      "enum": [
        "exact",
        "approximate",
        "synthetic",
        "live",
        "forked"
      ]
    },
    "host": {
      "type": "string"
    },
    "kind": {
      "type": "string"
    },
    "method": {
      "type": "string"
    },
    "route": {
      "type": "string"
    },
    "simulator": {
      "description": "The simulator of a synthetic answer (M12); absent for other groundings.",
      "enum": [
        "stub",
        "contract",
        "neighbor",
        "model",
        "fail-closed",
        "placeholder"
      ]
    },
    "turn_fork": {
      "anyOf": [
        {
          "$ref": "#/components/schemas/DiffTurnId"
        },
        {
          "type": "null"
        }
      ]
    },
    "turn_prod": {
      "anyOf": [
        {
          "$ref": "#/components/schemas/DiffTurnId"
        },
        {
          "type": "null"
        }
      ]
    }
  },
  "required": [
    "change",
    "kind",
    "method",
    "host",
    "route",
    "grounding",
    "turn_prod",
    "turn_fork",
    "fields"
  ],
  "type": "object"
}
```

### DiffEffects

```json
{
  "additionalProperties": false,
  "description": "External effects that differ.",
  "properties": {
    "added": {
      "$ref": "#/components/schemas/DiffCount"
    },
    "changed": {
      "$ref": "#/components/schemas/DiffCount"
    },
    "items": {
      "description": "Sorted by kind, host, route, then turn; at most 200.",
      "items": {
        "$ref": "#/components/schemas/DiffEffectItem"
      },
      "maxItems": 200,
      "type": "array"
    },
    "removed": {
      "$ref": "#/components/schemas/DiffCount"
    }
  },
  "required": [
    "added",
    "removed",
    "changed",
    "items"
  ],
  "type": "object"
}
```

### DiffErrorItem

```json
{
  "additionalProperties": false,
  "properties": {
    "error_code": {
      "type": "string"
    },
    "input": {
      "description": "The turn's input, as in `causes`.",
      "type": "string"
    },
    "kind": {
      "enum": [
        "introduced",
        "fixed",
        "new_orphan",
        "outcome_unknown"
      ]
    },
    "message": {
      "type": "string"
    },
    "turn_fork": {
      "anyOf": [
        {
          "$ref": "#/components/schemas/DiffTurnId"
        },
        {
          "type": "null"
        }
      ]
    },
    "turn_prod": {
      "anyOf": [
        {
          "$ref": "#/components/schemas/DiffTurnId"
        },
        {
          "type": "null"
        }
      ]
    }
  },
  "required": [
    "kind",
    "error_code",
    "message",
    "turn_prod",
    "turn_fork",
    "input"
  ],
  "type": "object"
}
```

### DiffErrors

```json
{
  "additionalProperties": false,
  "properties": {
    "fixed": {
      "$ref": "#/components/schemas/DiffCount",
      "description": "Turns that committed in the fork but failed in production."
    },
    "introduced": {
      "$ref": "#/components/schemas/DiffCount",
      "description": "Fork turns that fail where production committed, and new turns that fail."
    },
    "items": {
      "description": "At most 20 per kind.",
      "items": {
        "$ref": "#/components/schemas/DiffErrorItem"
      },
      "maxItems": 80,
      "type": "array"
    },
    "new_orphans": {
      "$ref": "#/components/schemas/DiffCount",
      "description": "Orphaned calls the fork created and production did not."
    },
    "outcome_unknown": {
      "$ref": "#/components/schemas/DiffCount",
      "description": "Fork effects matched to a production effect whose outcome was unknown."
    }
  },
  "required": [
    "introduced",
    "fixed",
    "new_orphans",
    "outcome_unknown",
    "items"
  ],
  "type": "object"
}
```

### DiffGroundingRow

```json
{
  "additionalProperties": false,
  "description": "How the fork's effects to one target were answered. For crypto and secret reveals `method` and `route` are empty and `host` is the secret's name.",
  "properties": {
    "approximate": {
      "$ref": "#/components/schemas/DiffCount"
    },
    "confidence": {
      "$ref": "#/components/schemas/DiffRatio",
      "description": "exact / (exact + approximate + synthetic + live + forked) of this target; 1.0 without effects."
    },
    "exact": {
      "$ref": "#/components/schemas/DiffCount"
    },
    "forked": {
      "$ref": "#/components/schemas/DiffCount",
      "description": "Answers of a fork's copy of the foreign actor (M14)."
    },
    "host": {
      "type": "string"
    },
    "kind": {
      "description": "The effect kind: `http.fetch`, `foreign.http`, ...",
      "type": "string"
    },
    "live": {
      "$ref": "#/components/schemas/DiffCount"
    },
    "method": {
      "type": "string"
    },
    "route": {
      "description": "The path with ids replaced by `{}`.",
      "type": "string"
    },
    "synthetic": {
      "$ref": "#/components/schemas/DiffCount"
    },
    "synthetic_by": {
      "$ref": "#/components/schemas/DiffSyntheticBy"
    }
  },
  "required": [
    "kind",
    "method",
    "host",
    "route",
    "exact",
    "approximate",
    "synthetic",
    "live",
    "confidence"
  ],
  "type": "object"
}
```

### DiffIrreversible

```json
{
  "additionalProperties": false,
  "description": "A rollback via replay only (M13): main's external effects since the rolled-back deployment that the old code would not have made the same way (no exact match in the fork). The rebased state does not account for them.",
  "properties": {
    "count": {
      "$ref": "#/components/schemas/DiffCount"
    },
    "items": {
      "description": "At most 200, in log order.",
      "items": {
        "additionalProperties": false,
        "properties": {
          "delivery": {
            "description": "`replay-safe`, `idempotency-keyed` or `unsafe`.",
            "type": "string"
          },
          "host": {
            "type": "string"
          },
          "idempotency_key": {
            "type": "string"
          },
          "kind": {
            "type": "string"
          },
          "method": {
            "type": "string"
          },
          "route": {
            "type": "string"
          },
          "status": {
            "description": "`ok`, `outcome_unknown`, `network`, `timeout`, ...",
            "type": "string"
          },
          "turn_prod": {
            "$ref": "#/components/schemas/DiffTurnId"
          }
        },
        "required": [
          "turn_prod",
          "kind",
          "method",
          "host",
          "route",
          "status",
          "delivery"
        ],
        "type": "object"
      },
      "type": "array"
    }
  },
  "required": [
    "count",
    "items"
  ],
  "type": "object"
}
```

### DiffKeyChange

```json
{
  "additionalProperties": false,
  "properties": {
    "fork": {
      "$ref": "#/components/schemas/DiffValue"
    },
    "key": {
      "type": "string"
    },
    "op": {
      "description": "What the fork did to the key; `unchanged-missing` when it did not write a key that production wrote.",
      "enum": [
        "set",
        "delete",
        "unchanged-missing"
      ]
    },
    "prod": {
      "$ref": "#/components/schemas/DiffValue"
    }
  },
  "required": [
    "key",
    "op",
    "prod",
    "fork"
  ],
  "type": "object"
}
```

### DiffKind

```json
{
  "additionalProperties": false,
  "description": "One actor kind's share of the diff: the counts of `summary`, `responses`, `effects`, `state` and `errors` over that kind's turns and actors.",
  "properties": {
    "actors_changed": {
      "$ref": "#/components/schemas/DiffCount",
      "description": "Actors of this kind whose state differs, in isolated or continuous replay."
    },
    "code": {
      "description": "The kind's code in the fork against production's at the fork point; `absent` when neither has code for it (only turns that found no deployed kind ran as it).",
      "enum": [
        "changed",
        "unchanged",
        "new",
        "absent"
      ]
    },
    "consequences": {
      "$ref": "#/components/schemas/DiffCount",
      "description": "This kind's other differing turns."
    },
    "divergent_turns": {
      "$ref": "#/components/schemas/DiffCount",
      "description": "This kind's turns that behave differently, both modes counted once by causal key. The kinds' counts add up to `summary.divergent_turns`."
    },
    "effects": {
      "additionalProperties": false,
      "description": "External effect differences of this kind's turns.",
      "properties": {
        "added": {
          "$ref": "#/components/schemas/DiffCount"
        },
        "changed": {
          "$ref": "#/components/schemas/DiffCount"
        },
        "removed": {
          "$ref": "#/components/schemas/DiffCount"
        }
      },
      "required": [
        "added",
        "removed",
        "changed"
      ],
      "type": "object"
    },
    "errors": {
      "additionalProperties": false,
      "description": "Errors of this kind's turns, as in `errors`.",
      "properties": {
        "fixed": {
          "$ref": "#/components/schemas/DiffCount"
        },
        "introduced": {
          "$ref": "#/components/schemas/DiffCount"
        },
        "new_orphans": {
          "$ref": "#/components/schemas/DiffCount"
        },
        "outcome_unknown": {
          "$ref": "#/components/schemas/DiffCount"
        }
      },
      "required": [
        "introduced",
        "fixed",
        "new_orphans",
        "outcome_unknown"
      ],
      "type": "object"
    },
    "kind": {
      "description": "The actor kind.",
      "type": "string"
    },
    "origins": {
      "$ref": "#/components/schemas/DiffCount",
      "description": "This kind's differing turns whose input is the same as production's."
    },
    "responses": {
      "additionalProperties": false,
      "description": "HTTP root inputs served by this kind.",
      "properties": {
        "changed": {
          "$ref": "#/components/schemas/DiffCount"
        },
        "unchanged": {
          "$ref": "#/components/schemas/DiffCount"
        }
      },
      "required": [
        "unchanged",
        "changed"
      ],
      "type": "object"
    },
    "root_inputs": {
      "$ref": "#/components/schemas/DiffCount",
      "description": "Root inputs of the window addressed to an actor of this kind."
    },
    "turns_fork": {
      "$ref": "#/components/schemas/DiffCount",
      "description": "Fork turns of this kind in the replayed trees."
    },
    "turns_prod": {
      "$ref": "#/components/schemas/DiffCount",
      "description": "Production turns of this kind in the replayed trees."
    }
  },
  "required": [
    "kind",
    "code",
    "root_inputs",
    "turns_prod",
    "turns_fork",
    "divergent_turns",
    "origins",
    "consequences",
    "responses",
    "effects",
    "actors_changed",
    "errors"
  ],
  "type": "object"
}
```

### DiffOptions

```json
{
  "additionalProperties": false,
  "description": "The replay options the diff was made with.",
  "properties": {
    "foreign": {
      "description": "The fork's foreign actors with fork_mode sandbox (M14): the checkpoint a copy started from, or why the actor stayed recorded.",
      "items": {
        "additionalProperties": false,
        "properties": {
          "checkpoint_lsn": {
            "$ref": "#/components/schemas/DiffCount"
          },
          "mode": {
            "enum": [
              "sandbox",
              "recorded"
            ]
          },
          "name": {
            "type": "string"
          },
          "replayed_calls": {
            "$ref": "#/components/schemas/DiffCount"
          },
          "why": {
            "type": "string"
          }
        },
        "required": [
          "name",
          "mode",
          "replayed_calls"
        ],
        "type": "object"
      },
      "type": "array"
    },
    "fuel_threshold": {
      "description": "A fuel change below this share is not a change.",
      "minimum": 0,
      "type": "number"
    },
    "ignore_headers": {
      "description": "Response and effect headers left out of the comparison.",
      "items": {
        "type": "string"
      },
      "type": "array"
    },
    "ignore_json_paths": {
      "description": "Parts of JSON bodies left out of the comparison, as JSONPath (`$.a.b[*].c`).",
      "items": {
        "type": "string"
      },
      "type": "array"
    },
    "live_allowlist": {
      "description": "The `[fork] live_allowlist` hosts in force: a GET without a recording to one of them went out live.",
      "items": {
        "type": "string"
      },
      "type": "array"
    },
    "mode": {
      "description": "Isolated replay (each root input on production's state at its LSN), continuous replay (the fork's state evolves), or both.",
      "enum": [
        "isolated",
        "continuous",
        "both"
      ]
    },
    "no_pii": {
      "description": "A fork without access to personal data: it ran on pseudonyms (M8).",
      "type": "boolean"
    },
    "sample": {
      "description": "The share of root inputs replayed in isolated mode, in (0, 1].",
      "exclusiveMinimum": 0,
      "maximum": 1,
      "type": "number"
    },
    "simulator_overrides": {
      "description": "Per-target simulator configuration the replay request carried, replacing main's for this fork (the fields of `PUT /v1/simulators/{target}`). Absent when there are none.",
      "items": {
        "$ref": "#/components/schemas/DiffSimulatorOverride"
      },
      "type": "array"
    },
    "simulators": {
      "description": "The simulator configuration the replay used, per target (M12): main's as of the fork point (I5), with the request's overrides. Absent when no target has one.",
      "items": {
        "$ref": "#/components/schemas/DiffSimulatorOption"
      },
      "type": "array"
    },
    "stubs": {
      "description": "Canned answers for effects without a recording, tried in order (synthetic grounding).",
      "items": {
        "$ref": "#/components/schemas/DiffStubRule"
      },
      "type": "array"
    }
  },
  "required": [
    "mode",
    "sample",
    "ignore_headers",
    "ignore_json_paths",
    "fuel_threshold",
    "stubs",
    "live_allowlist",
    "no_pii"
  ],
  "type": "object"
}
```

### DiffPercentiles

```json
{
  "additionalProperties": false,
  "properties": {
    "p50": {
      "$ref": "#/components/schemas/DiffCount"
    },
    "p95": {
      "$ref": "#/components/schemas/DiffCount"
    },
    "p99": {
      "$ref": "#/components/schemas/DiffCount"
    }
  },
  "required": [
    "p50",
    "p95",
    "p99"
  ],
  "type": "object"
}
```

### DiffPreviewInput

```json
{
  "additionalProperties": false,
  "description": "A request a preview fork took (M11): its root turn, the method and route pattern (never the path), the HTTP status of its answer (null when it answered with a reply or not at all) and its outcome.",
  "properties": {
    "method": {
      "type": "string"
    },
    "outcome": {
      "description": "committed, rejected, failed, trap, fuel_exhausted, memory_limit, effect_outcome_unknown or unspecified.",
      "type": "string"
    },
    "route": {
      "type": "string"
    },
    "status": {
      "type": [
        "integer",
        "null"
      ]
    },
    "turn": {
      "$ref": "#/components/schemas/DiffTurnId"
    }
  },
  "required": [
    "turn",
    "method",
    "route",
    "status",
    "outcome"
  ],
  "type": "object"
}
```

### DiffProdForkPercentiles

```json
{
  "additionalProperties": false,
  "properties": {
    "fork": {
      "$ref": "#/components/schemas/DiffPercentiles"
    },
    "prod": {
      "$ref": "#/components/schemas/DiffPercentiles"
    }
  },
  "required": [
    "prod",
    "fork"
  ],
  "type": "object"
}
```

### DiffRatio

```json
{
  "description": "A share from 0 to 1, with at most 6 decimals.",
  "maximum": 1,
  "minimum": 0,
  "type": "number"
}
```

### DiffResources

```json
{
  "additionalProperties": false,
  "description": "Fuel and memory of matched turns.",
  "properties": {
    "fuel": {
      "$ref": "#/components/schemas/DiffProdForkPercentiles"
    },
    "fuel_p99_change": {
      "description": "(fork - prod) / prod at p99; 0.0 when prod is 0.",
      "type": "number"
    },
    "memory": {
      "$ref": "#/components/schemas/DiffProdForkPercentiles"
    },
    "memory_p99_change": {
      "description": "(fork - prod) / prod at p99; 0.0 when prod is 0.",
      "type": "number"
    }
  },
  "required": [
    "fuel",
    "memory",
    "fuel_p99_change",
    "memory_p99_change"
  ],
  "type": "object"
}
```

### DiffResponseItem

```json
{
  "additionalProperties": false,
  "properties": {
    "body": {
      "description": "When both bodies are JSON, the operations from production's body to the fork's, by JSON Pointer; otherwise one `replace` at the path `\"\"` with each body as text (or base64).",
      "items": {
        "$ref": "#/components/schemas/DiffBodyOp"
      },
      "type": "array"
    },
    "headers": {
      "description": "Headers that differ.",
      "items": {
        "additionalProperties": false,
        "properties": {
          "fork": {
            "$ref": "#/components/schemas/DiffValue"
          },
          "name": {
            "type": "string"
          },
          "prod": {
            "$ref": "#/components/schemas/DiffValue"
          }
        },
        "required": [
          "name",
          "prod",
          "fork"
        ],
        "type": "object"
      },
      "type": "array"
    },
    "root_lsn": {
      "$ref": "#/components/schemas/DiffCount"
    },
    "route": {
      "description": "The method and route pattern.",
      "type": "string"
    },
    "status": {
      "additionalProperties": false,
      "properties": {
        "fork": {
          "type": [
            "integer",
            "null"
          ]
        },
        "prod": {
          "type": [
            "integer",
            "null"
          ]
        }
      },
      "required": [
        "prod",
        "fork"
      ],
      "type": "object"
    },
    "turn_fork": {
      "anyOf": [
        {
          "$ref": "#/components/schemas/DiffTurnId"
        },
        {
          "type": "null"
        }
      ],
      "description": "Null when the fork gave no response."
    },
    "turn_prod": {
      "$ref": "#/components/schemas/DiffTurnId"
    }
  },
  "required": [
    "root_lsn",
    "route",
    "turn_prod",
    "turn_fork",
    "status",
    "headers",
    "body"
  ],
  "type": "object"
}
```

### DiffResponses

```json
{
  "additionalProperties": false,
  "description": "HTTP root inputs in isolated replay.",
  "properties": {
    "changed": {
      "$ref": "#/components/schemas/DiffCount"
    },
    "items": {
      "description": "The changed responses in root LSN order, at most 200.",
      "items": {
        "$ref": "#/components/schemas/DiffResponseItem"
      },
      "maxItems": 200,
      "type": "array"
    },
    "unchanged": {
      "$ref": "#/components/schemas/DiffCount"
    }
  },
  "required": [
    "unchanged",
    "changed",
    "items"
  ],
  "type": "object"
}
```

### DiffSampleList

```json
{
  "items": {
    "$ref": "#/components/schemas/DiffTurnId"
  },
  "maxItems": 20,
  "type": "array"
}
```

### DiffSamples

```json
{
  "additionalProperties": false,
  "description": "Fork turns per category, at most 20 each, for `kronik trace`.",
  "properties": {
    "consequences": {
      "$ref": "#/components/schemas/DiffSampleList"
    },
    "effects_changed": {
      "$ref": "#/components/schemas/DiffSampleList"
    },
    "errors_introduced": {
      "$ref": "#/components/schemas/DiffSampleList"
    },
    "origins": {
      "$ref": "#/components/schemas/DiffSampleList"
    },
    "pii_masked": {
      "$ref": "#/components/schemas/DiffSampleList",
      "description": "Turns counted in `summary.pii_masked`. Absent when empty."
    },
    "preview": {
      "description": "Requests counted in `summary.preview_inputs`, in log order, at most 20. Absent when empty.",
      "items": {
        "$ref": "#/components/schemas/DiffPreviewInput"
      },
      "maxItems": 20,
      "type": "array"
    },
    "responses_changed": {
      "$ref": "#/components/schemas/DiffSampleList"
    },
    "synthetic": {
      "$ref": "#/components/schemas/DiffSampleList"
    }
  },
  "required": [
    "origins",
    "consequences",
    "responses_changed",
    "effects_changed",
    "errors_introduced",
    "synthetic"
  ],
  "type": "object"
}
```

### DiffSimulatorOption

```json
{
  "additionalProperties": false,
  "description": "One target's simulator configuration (a `SimulatorConfig` record).",
  "properties": {
    "contract": {
      "description": "BLAKE3 of the OpenAPI document as stored (`b3:` + hex); absent without a contract.",
      "type": "string"
    },
    "epoch": {
      "$ref": "#/components/schemas/DiffCount"
    },
    "lsn": {
      "$ref": "#/components/schemas/DiffCount"
    },
    "model": {
      "type": "boolean"
    },
    "neighbor": {
      "type": "boolean"
    },
    "request": {
      "const": true,
      "description": "From `simulator_overrides` (epoch and LSN are 0); absent for main's configuration."
    },
    "stubs": {
      "$ref": "#/components/schemas/DiffCount",
      "description": "The number of stub rules."
    },
    "target": {
      "description": "`http:<host>` or `foreign:<name>`.",
      "type": "string"
    }
  },
  "required": [
    "target",
    "epoch",
    "lsn",
    "stubs",
    "neighbor",
    "model"
  ],
  "type": "object"
}
```

### DiffSimulatorOverride

```json
{
  "additionalProperties": false,
  "description": "One target's simulator configuration for this replay only.",
  "properties": {
    "contract": {
      "description": "An OpenAPI 3 document; absent for none.",
      "type": "object"
    },
    "model": {
      "type": "boolean"
    },
    "neighbor": {
      "type": "boolean"
    },
    "stubs": {
      "items": {
        "$ref": "#/components/schemas/DiffStubRule"
      },
      "type": "array"
    },
    "target": {
      "description": "`http:<host>` or `foreign:<name>`.",
      "type": "string"
    }
  },
  "required": [
    "target",
    "stubs",
    "neighbor",
    "model"
  ],
  "type": "object"
}
```

### DiffSqlChange

```json
{
  "additionalProperties": false,
  "description": "A row change. The values of a subject's row (a changeset with a subject, or a `_subject` column in the final state) appear as `[redacted:s:<12 hex>:k:<16 hex>]` (see DiffValue).",
  "properties": {
    "fork": {
      "$ref": "#/components/schemas/DiffValue"
    },
    "op": {
      "enum": [
        "insert",
        "update",
        "delete"
      ]
    },
    "pk": {
      "description": "The primary key's values.",
      "type": "array"
    },
    "prod": {
      "$ref": "#/components/schemas/DiffValue"
    },
    "table": {
      "type": "string"
    }
  },
  "required": [
    "table",
    "op",
    "pk",
    "prod",
    "fork"
  ],
  "type": "object"
}
```

### DiffState

```json
{
  "additionalProperties": false,
  "properties": {
    "continuous": {
      "description": "Each actor's final state that differs: the fork's store against production at `to_lsn`.",
      "items": {
        "$ref": "#/components/schemas/DiffActorState"
      },
      "type": "array"
    },
    "isolated": {
      "description": "The writes of each root input's tree that differ, at most 200 entries.",
      "items": {
        "additionalProperties": false,
        "properties": {
          "actor": {
            "description": "`<kind>/<key>`.",
            "type": "string"
          },
          "keys": {
            "items": {
              "$ref": "#/components/schemas/DiffKeyChange"
            },
            "maxItems": 200,
            "type": "array"
          },
          "root_lsn": {
            "$ref": "#/components/schemas/DiffCount"
          },
          "sql": {
            "items": {
              "$ref": "#/components/schemas/DiffSqlChange"
            },
            "maxItems": 200,
            "type": "array"
          }
        },
        "required": [
          "root_lsn",
          "actor",
          "keys",
          "sql"
        ],
        "type": "object"
      },
      "maxItems": 200,
      "type": "array"
    }
  },
  "required": [
    "isolated",
    "continuous"
  ],
  "type": "object"
}
```

### DiffStubRule

```json
{
  "additionalProperties": false,
  "description": "Requests whose method (when given) and URL prefix match get this response, or this error.",
  "properties": {
    "body": {
      "description": "The response body as text.",
      "type": "string"
    },
    "error": {
      "description": "Instead of a response.",
      "enum": [
        "network",
        "timeout",
        "too-large",
        "denied"
      ]
    },
    "headers": {
      "description": "`[name, value]` pairs.",
      "items": {
        "items": false,
        "minItems": 2,
        "prefixItems": [
          {
            "type": "string"
          },
          {
            "type": "string"
          }
        ],
        "type": "array"
      },
      "type": "array"
    },
    "method": {
      "description": "GET, POST, ...; any method when absent.",
      "type": "string"
    },
    "status": {
      "maximum": 999,
      "minimum": 100,
      "type": "integer"
    },
    "url_prefix": {
      "type": "string"
    }
  },
  "required": [
    "url_prefix",
    "status",
    "headers",
    "body"
  ],
  "type": "object"
}
```

### DiffSummary

```json
{
  "additionalProperties": false,
  "description": "A behavior diff in numbers (kronik.diff/v1 `summary`).",
  "properties": {
    "approximate": {
      "$ref": "#/components/schemas/DiffCount",
      "description": "Fork effects answered by a similar recording (same target, different request)."
    },
    "changed": {
      "description": "Any difference anywhere in the diff.",
      "type": "boolean"
    },
    "confidence": {
      "$ref": "#/components/schemas/DiffRatio",
      "description": "exact / (exact + approximate + synthetic + live + forked); 1.0 without effects."
    },
    "consequences": {
      "$ref": "#/components/schemas/DiffCount",
      "description": "Every other difference in the same causal trees."
    },
    "divergent_turns": {
      "$ref": "#/components/schemas/DiffCount",
      "description": "Turns that behave differently, both modes counted once by causal key."
    },
    "exact": {
      "$ref": "#/components/schemas/DiffCount",
      "description": "Fork effects answered by an identical recording."
    },
    "forked": {
      "$ref": "#/components/schemas/DiffCount",
      "description": "Answers of the fork's copies of foreign actors (M14)."
    },
    "live": {
      "$ref": "#/components/schemas/DiffCount",
      "description": "Allowlisted GETs that went out live from the fork."
    },
    "origins": {
      "$ref": "#/components/schemas/DiffCount",
      "description": "Differing turns whose input is the same as production's."
    },
    "pii_masked": {
      "$ref": "#/components/schemas/DiffCount",
      "description": "In a fork without personal data: differing turns that read pseudonyms instead of personal data, and production turns missing below them. They are not verified: not counted as divergent, errors or causes (M8), and the policy needs at least an approval while pii_masked + pii_unverified is above 0 (pii-masked-needs-approval, ADR 0031). Always written (0 when none); diffs written before v0.1 lack it when 0."
    },
    "pii_unverified": {
      "$ref": "#/components/schemas/DiffCount",
      "description": "In a fork without personal data: turns of a kind whose code changed that read pseudonyms and came out identical to production. They did not run on the real values either, so they count for the approval floor (ADR 0031). 0 in identity replays. Always written; diffs written before v0.1 lack it."
    },
    "preview_inputs": {
      "$ref": "#/components/schemas/DiffCount",
      "description": "In a preview fork (M11): the requests it took at its URL, root inputs of their own. They and their turns are never compared with production: not in `turns_fork`, divergence, effects, grounding or errors; their state changes are in `state.continuous`. Absent when 0."
    },
    "replayed": {
      "$ref": "#/components/schemas/DiffCount",
      "description": "Root inputs replayed in isolated mode."
    },
    "root_inputs": {
      "$ref": "#/components/schemas/DiffCount",
      "description": "Root inputs in the window."
    },
    "sample": {
      "$ref": "#/components/schemas/DiffRatio",
      "description": "replayed / root_inputs; 1.0 for an empty window."
    },
    "synthetic": {
      "$ref": "#/components/schemas/DiffCount",
      "description": "Fork effects with no recording: a simulator answered (stub, contract, neighbor, model), or the effect failed closed."
    },
    "synthetic_by": {
      "$ref": "#/components/schemas/DiffSyntheticBy"
    },
    "turns_fork": {
      "$ref": "#/components/schemas/DiffCount",
      "description": "Fork turns of the replayed trees."
    },
    "turns_prod": {
      "$ref": "#/components/schemas/DiffCount",
      "description": "Production turns of the replayed trees."
    },
    "verified_through_lsn": {
      "$ref": "#/components/schemas/DiffCount",
      "description": "The last main LSN whose root inputs ran through the fork's code."
    }
  },
  "required": [
    "root_inputs",
    "replayed",
    "sample",
    "turns_prod",
    "turns_fork",
    "divergent_turns",
    "origins",
    "consequences",
    "exact",
    "approximate",
    "synthetic",
    "live",
    "confidence",
    "verified_through_lsn",
    "changed"
  ],
  "type": "object"
}
```

### DiffSyntheticBy

```json
{
  "additionalProperties": {
    "$ref": "#/components/schemas/DiffCount"
  },
  "description": "Synthetic answers per simulator (M12); absent when there are none.",
  "propertyNames": {
    "enum": [
      "stub",
      "contract",
      "neighbor",
      "model",
      "fail-closed",
      "placeholder"
    ]
  },
  "type": "object"
}
```

### DiffTurnId

```json
{
  "description": "A turn: `main:<lsn>` in production; in the fork `<fork>:<lsn>` (continuous replay) or `<fork>:r<root_lsn>.<n>` (the n-th turn of an isolated tree).",
  "pattern": "^[^:]+:(r[0-9]+\\.)?[0-9]+$",
  "type": "string"
}
```

### DiffValue

```json
{
  "description": "A value on one side: a state value, a header, a body or part of one, an SQL row; null when that side has none. A value with a subject is never shown, nor is the subject id: a state value, body or header value is `{\"redacted\": true, \"subject\": \"s:<12 hex>\", \"hash\": \"k:<16 hex>\"}`, a value in an SQL row `\"[redacted:s:<12 hex>:k:<16 hex>]\"`. `s:` is a keyed hash of the subject id (equal subjects give equal ones), `k:` a keyed hash of the subject and the value; both are `-` when the diff was built without the master key (`kronik upgrade check`). In a `--no-pii` fork, what a turn that used SQL produced is redacted under the subject `[sql]`, shown as is."
}
```

### EffectSummary

```json
{
  "properties": {
    "delivery": {
      "type": [
        "string",
        "null"
      ]
    },
    "error": {
      "type": [
        "string",
        "null"
      ]
    },
    "grounding": {
      "description": "Fork turns only: how the effect was answered, `exact`,\n`approximate`, `synthetic` or `forked` (a copy of a foreign actor,\nM14). Absent for production and live effects.",
      "type": [
        "string",
        "null"
      ]
    },
    "hint": {
      "description": "For denied effects: the exact command that grants the capability.",
      "type": [
        "string",
        "null"
      ]
    },
    "kind": {
      "type": "string"
    },
    "ordinal": {
      "format": "uint32",
      "minimum": 0,
      "type": "integer"
    },
    "request": {
      "description": "In history, for an HTTP effect: the request's method, host and path,\nsuch as `POST api.example.com/hooks`. Omitted otherwise, and when the\nrequest is sealed for a data subject.",
      "type": [
        "string",
        "null"
      ]
    },
    "simulator": {
      "description": "Synthetic fork effects only: the simulator that answered (`stub`,\n`contract`, `neighbor`, `model`, `fail-closed`, `placeholder`; M12). Absent for a\nfork turn recorded before M12.",
      "type": [
        "string",
        "null"
      ]
    },
    "status": {
      "description": "ok, denied, network, timeout, too_large, outcome_unknown, not_found,\nrejected, failed, reentrant.",
      "type": "string"
    },
    "target": {
      "type": "string"
    }
  },
  "required": [
    "ordinal",
    "kind",
    "target",
    "status"
  ],
  "type": "object"
}
```

### ErasureResponse

```json
{
  "description": "The answer to `POST /v1/privacy/erase`.",
  "properties": {
    "complete_after_ms": {
      "default": 0,
      "description": "When shipped keystore backups of this erasure expire\n(`erased_at + privacy.keystore_backup_retention`, §6.7). For a dry\nrun, the would-be time.",
      "format": "uint64",
      "minimum": 0,
      "type": "integer"
    },
    "dry_run": {
      "type": "boolean"
    },
    "epoch": {
      "description": "The `Erasure` record's epoch (the would-be one for a dry run).",
      "format": "uint64",
      "minimum": 0,
      "type": "integer"
    },
    "key_version": {
      "description": "The last erased key version (0: the subject had no key); 0 for a dry\nrun.",
      "format": "uint32",
      "minimum": 0,
      "type": "integer"
    },
    "lsn": {
      "description": "The record's LSN; `null` for a dry run.",
      "format": "uint64",
      "minimum": 0,
      "type": [
        "integer",
        "null"
      ]
    },
    "plain_values": {
      "description": "The subject's values written in `off` mode that are still plain in\nthe log, until a reseal (§8).",
      "format": "uint64",
      "minimum": 0,
      "type": "integer"
    },
    "subject": {
      "type": "string"
    }
  },
  "required": [
    "dry_run",
    "subject",
    "key_version",
    "epoch",
    "plain_values"
  ],
  "type": "object"
}
```

### Error

```json
{
  "description": "The stable error JSON, the same from the API, the CLI's --json and MCP.",
  "properties": {
    "error": {
      "properties": {
        "code": {
          "description": "Stable; `kronik explain <code>` documents it.",
          "enum": [
            "ACTOR_NOT_FOUND",
            "APPROVAL_REQUIRED",
            "AUDIT_RANGE_GONE",
            "BAD_REQUEST",
            "CAPABILITY_NOT_GRANTED",
            "DEAD_LETTER_ALREADY_RESENT",
            "DEAD_LETTER_NOT_FOUND",
            "DEPLOYMENT_NOT_FOUND",
            "EFFECT_OUTCOME_UNKNOWN",
            "ENGINE_UPGRADE_DIVERGED",
            "ENGINE_VERSION_MISMATCH",
            "EXPORT_NOT_CONFIGURED",
            "FOREIGN_EXISTS",
            "FOREIGN_NOT_FOUND",
            "FOREIGN_UNAVAILABLE",
            "FORK_NOT_FOUND",
            "FUEL_EXHAUSTED",
            "GATEWAY_TIMEOUT",
            "IDEMPOTENCY_IN_FLIGHT",
            "IDEMPOTENCY_KEY_REUSED",
            "IMAGE_INVALID",
            "IMPORT_NOT_ALLOWED",
            "INTERNAL",
            "KEYSTORE_INCOMPLETE",
            "KVM_UNAVAILABLE",
            "MASTER_KEY_MISMATCH",
            "MASTER_KEY_MISSING",
            "NOTHING_TO_PROPOSE",
            "NOT_IMPLEMENTED",
            "PAYLOAD_TOO_LARGE",
            "POLICY_DENIED",
            "PREVIEW_FULL",
            "PREVIEW_LIMIT",
            "PREVIEW_NOT_FOUND",
            "PROPOSAL_NOT_FOUND",
            "PROPOSAL_RUNNING",
            "PROPOSAL_STALE",
            "REASON_REQUIRED",
            "REPLAY_DIVERGED",
            "ROLLBACK_SCHEMA_CHANGED",
            "ROUTE_CONFLICT",
            "ROUTE_NOT_FOUND",
            "RUNC_MISSING",
            "RUNSC_MISSING",
            "SCOPE_MISSING",
            "SECRET_NOT_FOUND",
            "STORAGE_CORRUPT",
            "SUBJECT_ERASED",
            "TOKEN_NOT_FOUND",
            "TURN_FAILED",
            "TURN_NOT_FOUND",
            "UNAUTHENTICATED",
            "UNAVAILABLE",
            "VERIFY_REQUIRED",
            "WATCH_NOT_FOUND"
          ],
          "type": "string"
        },
        "docs": {
          "description": "`kronik explain <code>`.",
          "type": "string"
        },
        "hint": {
          "description": "What to do next, often the exact command.",
          "type": "string"
        },
        "message": {
          "type": "string"
        }
      },
      "required": [
        "code",
        "message"
      ],
      "type": "object"
    }
  },
  "required": [
    "error"
  ],
  "type": "object"
}
```

### ExportRewindResponse

```json
{
  "properties": {
    "dry_run": {
      "type": "boolean"
    },
    "from": {
      "description": "The cursor before the rewind.",
      "format": "uint64",
      "minimum": 0,
      "type": "integer"
    },
    "stream": {
      "type": "string"
    },
    "to": {
      "format": "uint64",
      "minimum": 0,
      "type": "integer"
    }
  },
  "required": [
    "dry_run",
    "stream",
    "from",
    "to"
  ],
  "type": "object"
}
```

### ExportStatusResponse

```json
{
  "description": "`GET /v1/export`: every export stream of the daemon.",
  "properties": {
    "streams": {
      "items": {
        "$ref": "#/components/schemas/ExportStream"
      },
      "type": "array"
    }
  },
  "required": [
    "streams"
  ],
  "type": "object"
}
```

### ExportStream

```json
{
  "properties": {
    "applied_lsn": {
      "format": "uint64",
      "minimum": 0,
      "type": "integer"
    },
    "cursor": {
      "description": "The last LSN the sink acknowledged.",
      "format": "uint64",
      "minimum": 0,
      "type": "integer"
    },
    "enabled": {
      "type": "boolean"
    },
    "gaps": {
      "description": "Ranges retention deleted before the stream read them, since the\nstart.",
      "format": "uint64",
      "minimum": 0,
      "type": "integer"
    },
    "lag": {
      "description": "`applied_lsn - cursor` while enabled, else 0.",
      "format": "uint64",
      "minimum": 0,
      "type": "integer"
    },
    "last_error": {
      "description": "The last failure's code (`http_503`, `connect`, `timeout`, ...),\nnever its text.",
      "type": [
        "string",
        "null"
      ]
    },
    "last_success_wall_ms": {
      "description": "Wall-clock milliseconds of the last delivered batch since the start.",
      "format": "uint64",
      "minimum": 0,
      "type": [
        "integer",
        "null"
      ]
    },
    "name": {
      "description": "`traces` or `audit`.",
      "type": "string"
    },
    "sink": {
      "description": "The sink's or endpoint's scheme and host only (never a path, query\nor credentials); empty when not configured.",
      "type": "string"
    },
    "stalled_ms": {
      "default": null,
      "description": "While there is lag: milliseconds since the last delivered batch, or\nsince the stream started without one. `kronik doctor` warns on it.",
      "format": "uint64",
      "minimum": 0,
      "type": [
        "integer",
        "null"
      ]
    }
  },
  "required": [
    "name",
    "enabled",
    "sink",
    "cursor",
    "applied_lsn",
    "lag",
    "gaps"
  ],
  "type": "object"
}
```

### ForeignAddResponse

```json
{
  "properties": {
    "dry_run": {
      "type": "boolean"
    },
    "foreign": {
      "$ref": "#/components/schemas/ForeignView"
    },
    "warnings": {
      "items": {
        "type": "string"
      },
      "type": "array"
    }
  },
  "required": [
    "dry_run",
    "foreign",
    "warnings"
  ],
  "type": "object"
}
```

### ForeignListResponse

```json
{
  "properties": {
    "foreign": {
      "items": {
        "$ref": "#/components/schemas/ForeignView"
      },
      "type": "array"
    },
    "unavailable": {
      "description": "Why this daemon runs no foreign actor (another daemon holds\n`run_dir`, or the foreign actors' directory could not be prepared).",
      "type": [
        "string",
        "null"
      ]
    }
  },
  "required": [
    "foreign"
  ],
  "type": "object"
}
```

### ForeignLogsResponse

```json
{
  "properties": {
    "lines": {
      "items": {
        "type": "string"
      },
      "type": "array"
    },
    "name": {
      "type": "string"
    },
    "truncated": {
      "type": "boolean"
    }
  },
  "required": [
    "name",
    "lines",
    "truncated"
  ],
  "type": "object"
}
```

### ForeignRemoveResponse

```json
{
  "properties": {
    "dry_run": {
      "type": "boolean"
    },
    "removed": {
      "$ref": "#/components/schemas/ForeignRemoved"
    }
  },
  "required": [
    "dry_run",
    "removed"
  ],
  "type": "object"
}
```

### ForeignRemoved

```json
{
  "properties": {
    "epoch": {
      "format": "uint64",
      "minimum": 0,
      "type": "integer"
    },
    "lsn": {
      "format": "uint64",
      "minimum": 0,
      "type": "integer"
    },
    "name": {
      "type": "string"
    }
  },
  "required": [
    "name",
    "epoch",
    "lsn"
  ],
  "type": "object"
}
```

### ForeignStatusView

```json
{
  "description": "A foreign actor's supervision state.",
  "properties": {
    "error": {
      "type": [
        "string",
        "null"
      ]
    },
    "last_exit": {
      "anyOf": [
        {
          "$ref": "#/components/schemas/LastExitView"
        },
        {
          "type": "null"
        }
      ]
    },
    "next_start_ms": {
      "format": "uint64",
      "minimum": 0,
      "type": [
        "integer",
        "null"
      ]
    },
    "restarts": {
      "format": "uint64",
      "minimum": 0,
      "type": "integer"
    },
    "since_ms": {
      "format": "uint64",
      "minimum": 0,
      "type": "integer"
    },
    "starts": {
      "format": "uint64",
      "minimum": 0,
      "type": "integer"
    },
    "state": {
      "description": "`starting`, `running`, `backoff`, `stopping` or `stopped`.",
      "type": "string"
    }
  },
  "required": [
    "state",
    "since_ms",
    "starts",
    "restarts"
  ],
  "type": "object"
}
```

### ForeignView

```json
{
  "description": "A declared foreign actor.",
  "properties": {
    "checkpoints": {
      "description": "Checkpoints for forks (`sandbox`), oldest first.",
      "items": {
        "$ref": "#/components/schemas/CheckpointView"
      },
      "type": "array"
    },
    "cpu_millis": {
      "format": "uint32",
      "minimum": 0,
      "type": "integer"
    },
    "epoch": {
      "format": "uint64",
      "minimum": 0,
      "type": "integer"
    },
    "fork_mode": {
      "description": "`recorded` or `sandbox` (M14).",
      "type": "string"
    },
    "image": {
      "type": "string"
    },
    "isolation": {
      "type": "string"
    },
    "lsn": {
      "description": "0 for a dry run.",
      "format": "uint64",
      "minimum": 0,
      "type": "integer"
    },
    "memory_bytes": {
      "format": "uint64",
      "minimum": 0,
      "type": "integer"
    },
    "name": {
      "type": "string"
    },
    "platform": {
      "type": "string"
    },
    "port": {
      "format": "uint32",
      "minimum": 0,
      "type": "integer"
    },
    "reason": {
      "type": "string"
    },
    "secrets": {
      "description": "`ENV=secret-name`; never values.",
      "items": {
        "type": "string"
      },
      "type": "array"
    },
    "status": {
      "anyOf": [
        {
          "$ref": "#/components/schemas/ForeignStatusView"
        },
        {
          "type": "null"
        }
      ],
      "description": "Null for a dry run, or when this daemon does not run foreign actors."
    }
  },
  "required": [
    "name",
    "image",
    "port",
    "cpu_millis",
    "memory_bytes",
    "isolation",
    "platform",
    "secrets",
    "fork_mode",
    "checkpoints",
    "epoch",
    "lsn",
    "reason"
  ],
  "type": "object"
}
```

### ForkCreateResponse

```json
{
  "properties": {
    "dry_run": {
      "type": "boolean"
    },
    "fork": {
      "$ref": "#/components/schemas/ForkInfo"
    }
  },
  "required": [
    "dry_run",
    "fork"
  ],
  "type": "object"
}
```

### ForkDeleteResponse

```json
{
  "properties": {
    "deleted": {
      "type": "string"
    },
    "dry_run": {
      "type": "boolean"
    }
  },
  "required": [
    "dry_run",
    "deleted"
  ],
  "type": "object"
}
```

### ForkDeployResponse

```json
{
  "properties": {
    "deployment": {
      "$ref": "#/components/schemas/DeploymentKind"
    },
    "dry_run": {
      "type": "boolean"
    },
    "fork": {
      "type": "string"
    }
  },
  "required": [
    "dry_run",
    "fork",
    "deployment"
  ],
  "type": "object"
}
```

### ForkEntry

```json
{
  "properties": {
    "fork_lsn": {
      "format": "uint64",
      "minimum": 0,
      "type": "integer"
    },
    "head_lsn": {
      "format": "uint64",
      "minimum": 0,
      "type": "integer"
    },
    "name": {
      "type": "string"
    },
    "proposal_id": {
      "type": [
        "string",
        "null"
      ]
    },
    "verified_through_lsn": {
      "format": "uint64",
      "minimum": 0,
      "type": "integer"
    }
  },
  "required": [
    "name",
    "fork_lsn",
    "head_lsn",
    "verified_through_lsn"
  ],
  "type": "object"
}
```

### ForkInfo

```json
{
  "properties": {
    "fork_lsn": {
      "format": "uint64",
      "minimum": 0,
      "type": "integer"
    },
    "name": {
      "type": "string"
    },
    "no_pii": {
      "type": "boolean"
    },
    "proposal_id": {
      "type": [
        "string",
        "null"
      ]
    }
  },
  "required": [
    "name",
    "fork_lsn",
    "no_pii"
  ],
  "type": "object"
}
```

### ForkTurnResponse

```json
{
  "description": "A turn run in a fork (`POST /v1/forks/{name}/actors/{kind}/{key}/messages`).",
  "properties": {
    "effects": {
      "items": {
        "$ref": "#/components/schemas/EffectSummary"
      },
      "type": "array"
    },
    "fork": {
      "type": "string"
    },
    "outcome": {
      "$ref": "#/components/schemas/Outcome"
    },
    "reply": {
      "anyOf": [
        {
          "$ref": "#/components/schemas/Reply"
        },
        {
          "type": "null"
        }
      ]
    },
    "turn_id": {
      "type": "string"
    }
  },
  "required": [
    "fork",
    "turn_id",
    "outcome",
    "effects"
  ],
  "type": "object"
}
```

### ForksResponse

```json
{
  "properties": {
    "forks": {
      "items": {
        "$ref": "#/components/schemas/ForkEntry"
      },
      "type": "array"
    }
  },
  "required": [
    "forks"
  ],
  "type": "object"
}
```

### GrantResponse

```json
{
  "properties": {
    "dry_run": {
      "type": "boolean"
    },
    "grant": {
      "$ref": "#/components/schemas/GrantView"
    }
  },
  "required": [
    "dry_run",
    "grant"
  ],
  "type": "object"
}
```

### GrantView

```json
{
  "properties": {
    "capability": {
      "type": "string"
    },
    "delivery": {
      "type": [
        "string",
        "null"
      ]
    },
    "epoch": {
      "format": "uint64",
      "minimum": 0,
      "type": "integer"
    },
    "kind": {
      "type": "string"
    },
    "lsn": {
      "description": "0 for dry runs.",
      "format": "uint64",
      "minimum": 0,
      "type": "integer"
    },
    "rate": {
      "type": [
        "string",
        "null"
      ]
    },
    "reason": {
      "default": "",
      "description": "Required: missing or blank answers REASON_REQUIRED.",
      "type": "string"
    }
  },
  "required": [
    "kind",
    "capability",
    "epoch",
    "lsn"
  ],
  "type": "object"
}
```

### GrantsResponse

```json
{
  "properties": {
    "grants": {
      "items": {
        "$ref": "#/components/schemas/GrantView"
      },
      "type": "array"
    }
  },
  "required": [
    "grants"
  ],
  "type": "object"
}
```

### GuardMetrics

```json
{
  "description": "What a guard sees: the deployment's kinds' turns after it and in the\nequally long window before it.",
  "properties": {
    "after": {
      "$ref": "#/components/schemas/GuardWindowMetrics"
    },
    "before": {
      "$ref": "#/components/schemas/GuardWindowMetrics"
    },
    "epoch": {
      "format": "uint64",
      "minimum": 0,
      "type": "integer"
    },
    "kinds": {
      "items": {
        "type": "string"
      },
      "type": "array"
    },
    "observed_ms": {
      "description": "Logical time of the window after the deployment seen so far.",
      "format": "uint64",
      "minimum": 0,
      "type": "integer"
    },
    "schema_changed": {
      "description": "A rollback would move a schema version back: guards alert instead.",
      "type": "boolean"
    }
  },
  "required": [
    "epoch",
    "kinds",
    "schema_changed",
    "observed_ms",
    "before",
    "after"
  ],
  "type": "object"
}
```

### GuardWindowMetrics

```json
{
  "properties": {
    "error_rate": {
      "description": "`failed / turns`; 0 without turns.",
      "format": "double",
      "type": "number"
    },
    "failed": {
      "description": "Turns whose outcome is not committed.",
      "format": "uint64",
      "minimum": 0,
      "type": "integer"
    },
    "latency_p50_ms": {
      "format": "double",
      "type": "number"
    },
    "latency_p99_ms": {
      "format": "double",
      "type": "number"
    },
    "turns": {
      "format": "uint64",
      "minimum": 0,
      "type": "integer"
    }
  },
  "required": [
    "turns",
    "failed",
    "error_rate",
    "latency_p50_ms",
    "latency_p99_ms"
  ],
  "type": "object"
}
```

### HistoryResponse

```json
{
  "properties": {
    "next": {
      "description": "LSN to pass as `before` for the next page.",
      "format": "uint64",
      "minimum": 0,
      "type": [
        "integer",
        "null"
      ]
    },
    "turns": {
      "items": {
        "$ref": "#/components/schemas/TurnSummary"
      },
      "type": "array"
    }
  },
  "required": [
    "turns"
  ],
  "type": "object"
}
```

### InputSummary

```json
{
  "properties": {
    "summary": {
      "type": "string"
    },
    "type": {
      "description": "http, message, timer or migrate.",
      "type": "string"
    }
  },
  "required": [
    "type",
    "summary"
  ],
  "type": "object"
}
```

### InspectResponse

```json
{
  "properties": {
    "actor": {
      "$ref": "#/components/schemas/Actor"
    },
    "sql": {
      "anyOf": [
        {
          "$ref": "#/components/schemas/SqlSummary"
        },
        {
          "type": "null"
        }
      ]
    },
    "state": {
      "items": {
        "$ref": "#/components/schemas/StateEntry"
      },
      "type": "array"
    }
  },
  "required": [
    "actor",
    "state"
  ],
  "type": "object"
}
```

### IntegrityResponse

```json
{
  "properties": {
    "applied_lsn": {
      "format": "uint64",
      "minimum": 0,
      "type": "integer"
    },
    "keys_missing": {
      "default": [],
      "description": "Subjects with sealed values (in the state or the log) whose key the\nprivacy keystore lacks and that were not erased: those values can't\nbe read (`KEYSTORE_INCOMPLETE`). Empty on a healthy node.",
      "items": {
        "type": "string"
      },
      "type": "array"
    },
    "log_first_lsn": {
      "description": "The first LSN the log still holds (retention deletes older segments).",
      "format": "uint64",
      "minimum": 0,
      "type": "integer"
    },
    "log_hash": {
      "description": "BLAKE3 over the records `log_first_lsn..=through_lsn` (LSN, kind and\nencoded record of each).",
      "type": "string"
    },
    "newest_logical_time_ms": {
      "default": 0,
      "description": "Newest record's logical time (`time_hwm`). Zero when the node has\nno storage config, or when nothing has advanced logical time.",
      "format": "uint64",
      "minimum": 0,
      "type": "integer"
    },
    "retention_cutoff_ms": {
      "default": 0,
      "description": "Forks whose turn logical time is strictly before this are outside\nthe window. Zero when the node has no storage config.",
      "format": "uint64",
      "minimum": 0,
      "type": "integer"
    },
    "retention_history_ms": {
      "default": 0,
      "description": "`[retention] history` in milliseconds. Zero when the node has no\nstorage config (`Node::start` with `storage: None`, including DST).\n`start_local` and `kronik serve` always install one; the default is\n7 days. An older response that omits the field decodes as 0.",
      "format": "uint64",
      "minimum": 0,
      "type": "integer"
    },
    "state_hash": {
      "description": "BLAKE3 over the materialized state (m6-storage §8).",
      "type": "string"
    },
    "through_lsn": {
      "default": 0,
      "description": "The last LSN `log_hash` covers: `applied_lsn`, or the `through`\nasked for. An older response that omits it decodes as 0.",
      "format": "uint64",
      "minimum": 0,
      "type": "integer"
    }
  },
  "required": [
    "applied_lsn",
    "state_hash",
    "log_first_lsn",
    "log_hash"
  ],
  "type": "object"
}
```

### Item

```json
{
  "description": "One item of a verification report.",
  "properties": {
    "action": {
      "type": "string"
    },
    "effect": {
      "format": "uint32",
      "minimum": 0,
      "type": [
        "integer",
        "null"
      ]
    },
    "kind": {
      "type": "string"
    },
    "lsn": {
      "format": "uint64",
      "minimum": 0,
      "type": "integer"
    },
    "record_hash": {
      "type": "string"
    }
  },
  "required": [
    "lsn",
    "kind",
    "action",
    "record_hash"
  ],
  "type": "object"
}
```

### KeystoreCounts

```json
{
  "description": "The keystore's counts.",
  "properties": {
    "erased": {
      "description": "Erased subjects.",
      "format": "uint64",
      "minimum": 0,
      "type": "integer"
    },
    "keys": {
      "format": "uint64",
      "minimum": 0,
      "type": "integer"
    },
    "subjects": {
      "description": "Subjects with at least one key.",
      "format": "uint64",
      "minimum": 0,
      "type": "integer"
    }
  },
  "required": [
    "subjects",
    "keys",
    "erased"
  ],
  "type": "object"
}
```

### LastExitView

```json
{
  "description": "How the last run of a foreign actor ended.",
  "properties": {
    "at_ms": {
      "format": "uint64",
      "minimum": 0,
      "type": "integer"
    },
    "code": {
      "format": "int32",
      "type": [
        "integer",
        "null"
      ]
    },
    "oom": {
      "type": "boolean"
    }
  },
  "required": [
    "oom",
    "at_ms"
  ],
  "type": "object"
}
```

### LimitsListResponse

```json
{
  "properties": {
    "limits": {
      "items": {
        "$ref": "#/components/schemas/LimitsView"
      },
      "type": "array"
    }
  },
  "required": [
    "limits"
  ],
  "type": "object"
}
```

### LimitsResponse

```json
{
  "properties": {
    "dry_run": {
      "type": "boolean"
    },
    "limits": {
      "$ref": "#/components/schemas/LimitsView"
    }
  },
  "required": [
    "dry_run",
    "limits"
  ],
  "type": "object"
}
```

### LimitsView

```json
{
  "properties": {
    "effect_response_bytes": {
      "format": "uint64",
      "minimum": 0,
      "type": "integer"
    },
    "effect_timeout_ms": {
      "format": "uint64",
      "minimum": 0,
      "type": "integer"
    },
    "epoch": {
      "description": "Set in responses to `POST /v1/limits` (lsn 0 for dry runs).",
      "format": "uint64",
      "minimum": 0,
      "type": [
        "integer",
        "null"
      ]
    },
    "fuel": {
      "format": "uint64",
      "minimum": 0,
      "type": "integer"
    },
    "kind": {
      "type": "string"
    },
    "lsn": {
      "format": "uint64",
      "minimum": 0,
      "type": [
        "integer",
        "null"
      ]
    },
    "memory_bytes": {
      "format": "uint64",
      "minimum": 0,
      "type": "integer"
    },
    "message_bytes": {
      "format": "uint64",
      "minimum": 0,
      "type": "integer"
    },
    "sql_bytes_per_actor": {
      "format": "uint64",
      "minimum": 0,
      "type": "integer"
    },
    "state_value_bytes": {
      "format": "uint64",
      "minimum": 0,
      "type": "integer"
    }
  },
  "required": [
    "kind",
    "fuel",
    "memory_bytes",
    "message_bytes",
    "state_value_bytes",
    "sql_bytes_per_actor",
    "effect_timeout_ms",
    "effect_response_bytes"
  ],
  "type": "object"
}
```

### Line

```json
{
  "description": "One exported line, keys in §4.3's order.",
  "properties": {
    "action": {
      "type": "string"
    },
    "at_wall_ms": {
      "format": "uint64",
      "minimum": 0,
      "type": "integer"
    },
    "branch": {
      "type": "string"
    },
    "details": {
      "additionalProperties": true,
      "type": "object"
    },
    "effect": {
      "description": "The effect ordinal of a reveal line; absent otherwise.",
      "format": "uint32",
      "minimum": 0,
      "type": [
        "integer",
        "null"
      ]
    },
    "epoch": {
      "format": "uint64",
      "minimum": 0,
      "type": [
        "integer",
        "null"
      ]
    },
    "kind": {
      "type": "string"
    },
    "lsn": {
      "format": "uint64",
      "minimum": 0,
      "type": "integer"
    },
    "reason": {
      "type": "string"
    },
    "reason_truncated": {
      "type": "boolean"
    },
    "record_hash": {
      "type": "string"
    },
    "schema": {
      "type": "string"
    },
    "token_id": {
      "type": "string"
    }
  },
  "required": [
    "schema",
    "lsn",
    "kind",
    "action",
    "at_wall_ms",
    "token_id",
    "reason",
    "branch",
    "details",
    "record_hash"
  ],
  "type": "object"
}
```

### MessageSummary

```json
{
  "properties": {
    "name": {
      "type": "string"
    },
    "to": {
      "type": "string"
    }
  },
  "required": [
    "to",
    "name"
  ],
  "type": "object"
}
```

### ModelView

```json
{
  "description": "The server's model simulator (`[simulators.model]`); never the key.",
  "properties": {
    "configured": {
      "type": "boolean"
    },
    "endpoint_host": {
      "description": "The endpoint's host, when configured.",
      "type": [
        "string",
        "null"
      ]
    },
    "model": {
      "type": [
        "string",
        "null"
      ]
    }
  },
  "required": [
    "configured"
  ],
  "type": "object"
}
```

### Orphan

```json
{
  "properties": {
    "actor": {
      "description": "The callee.",
      "type": "string"
    },
    "call_message_id": {
      "type": "string"
    },
    "caller": {
      "type": "string"
    },
    "caller_turn_id": {
      "type": "string"
    },
    "compensation": {
      "anyOf": [
        {
          "$ref": "#/components/schemas/Compensation"
        },
        {
          "type": "null"
        }
      ]
    },
    "resolved_turn_id": {
      "type": [
        "string",
        "null"
      ]
    },
    "turn_id": {
      "description": "The callee's turn that made the change.",
      "type": "string"
    }
  },
  "required": [
    "actor",
    "turn_id",
    "caller",
    "caller_turn_id",
    "call_message_id"
  ],
  "type": "object"
}
```

### OrphansResponse

```json
{
  "properties": {
    "orphans": {
      "items": {
        "$ref": "#/components/schemas/Orphan"
      },
      "type": "array"
    }
  },
  "required": [
    "orphans"
  ],
  "type": "object"
}
```

### Outcome

```json
{
  "properties": {
    "error_code": {
      "type": [
        "string",
        "null"
      ]
    },
    "kind": {
      "description": "committed, rejected, failed, trap, fuel_exhausted, memory_limit,\neffect_outcome_unknown.",
      "type": "string"
    },
    "message": {
      "type": [
        "string",
        "null"
      ]
    }
  },
  "required": [
    "kind"
  ],
  "type": "object"
}
```

### PolicyEvaluation

```json
{
  "description": "The policy's verdict on a behavior diff.",
  "properties": {
    "errors": {
      "description": "Rules that could not be evaluated; each also counts as fired, with at least require_approval.",
      "items": {
        "properties": {
          "message": {
            "type": "string"
          },
          "name": {
            "type": "string"
          }
        },
        "required": [
          "name",
          "message"
        ],
        "type": "object"
      },
      "type": "array"
    },
    "fired": {
      "description": "The rules that fired, in rule order, then pii-masked-needs-approval (a floor in code, ADR 0031) when the diff has pii-masked turns.",
      "items": {
        "properties": {
          "action": {
            "enum": [
              "allow",
              "require_approval",
              "deny"
            ],
            "type": "string"
          },
          "name": {
            "type": "string"
          },
          "reason": {
            "description": "Why, for the floor in code; absent for rules.",
            "type": "string"
          }
        },
        "required": [
          "name",
          "action"
        ],
        "type": "object"
      },
      "type": "array"
    },
    "outcome": {
      "allOf": [
        {
          "enum": [
            "allow",
            "require_approval",
            "deny"
          ],
          "type": "string"
        }
      ],
      "description": "The strictest action among the rules that fired; allow when none did."
    }
  },
  "required": [
    "outcome",
    "fired",
    "errors"
  ],
  "type": "object"
}
```

### PolicyGuard

```json
{
  "properties": {
    "action": {
      "description": "`alert` or `rollback`.",
      "type": "string"
    },
    "name": {
      "type": "string"
    },
    "when": {
      "type": "string"
    }
  },
  "required": [
    "name",
    "when",
    "action"
  ],
  "type": "object"
}
```

### PolicyResponse

```json
{
  "properties": {
    "default": {
      "type": "boolean"
    },
    "default_guards": {
      "description": "`guards` are the default guards: the policy has no `guard` key.",
      "type": "boolean"
    },
    "epoch": {
      "format": "uint64",
      "minimum": 0,
      "type": "integer"
    },
    "guards": {
      "description": "The guards `kronik watch` evaluates (M11). The policy's own when its\nfile has a `guard` key (`guard = []`: none), else the defaults.",
      "items": {
        "$ref": "#/components/schemas/PolicyGuard"
      },
      "type": "array"
    },
    "rules_toml": {
      "type": "string"
    }
  },
  "required": [
    "rules_toml",
    "epoch",
    "default",
    "guards",
    "default_guards"
  ],
  "type": "object"
}
```

### PolicySetResponse

```json
{
  "properties": {
    "dry_run": {
      "type": "boolean"
    },
    "epoch": {
      "format": "uint64",
      "minimum": 0,
      "type": "integer"
    },
    "lsn": {
      "format": "uint64",
      "minimum": 0,
      "type": "integer"
    }
  },
  "required": [
    "dry_run",
    "epoch",
    "lsn"
  ],
  "type": "object"
}
```

### PreviewCreateResponse

```json
{
  "properties": {
    "dry_run": {
      "type": "boolean"
    },
    "preview": {
      "$ref": "#/components/schemas/PreviewInfo"
    }
  },
  "required": [
    "dry_run",
    "preview"
  ],
  "type": "object"
}
```

### PreviewDeleteResponse

```json
{
  "properties": {
    "deleted": {
      "type": "string"
    },
    "dry_run": {
      "type": "boolean"
    }
  },
  "required": [
    "dry_run",
    "deleted"
  ],
  "type": "object"
}
```

### PreviewInfo

```json
{
  "description": "A preview fork: where its requests go and when it expires.",
  "properties": {
    "expires_ms": {
      "description": "Wall-clock Unix milliseconds after which it is deleted.",
      "format": "uint64",
      "minimum": 0,
      "type": "integer"
    },
    "fork_lsn": {
      "format": "uint64",
      "minimum": 0,
      "type": "integer"
    },
    "id": {
      "description": "The fork's name, `v-<12 hex>`.",
      "type": "string"
    },
    "no_pii": {
      "type": "boolean"
    },
    "proposal": {
      "type": "string"
    },
    "url": {
      "description": "`<scheme>://<id>.<preview_domain>/` with `[gateway] preview_domain`,\nelse `<scheme>://<gateway host>/__preview/<id>/`; `https` when the\ngateway serves TLS, else `http`.",
      "type": "string"
    }
  },
  "required": [
    "id",
    "proposal",
    "url",
    "fork_lsn",
    "no_pii",
    "expires_ms"
  ],
  "type": "object"
}
```

### PreviewsResponse

```json
{
  "properties": {
    "previews": {
      "items": {
        "$ref": "#/components/schemas/PreviewInfo"
      },
      "type": "array"
    }
  },
  "required": [
    "previews"
  ],
  "type": "object"
}
```

### PrivacyModeName

```json
{
  "description": "A privacy mode as the API writes it: `\"off\"` or `\"on\"`.",
  "enum": [
    "off",
    "on"
  ],
  "type": "string"
}
```

### PrivacyModeResponse

```json
{
  "description": "The answer to `POST /v1/privacy/mode`.",
  "properties": {
    "changed": {
      "description": "False when the mode already was the one asked for; nothing was\nrecorded.",
      "type": "boolean"
    },
    "dry_run": {
      "type": "boolean"
    },
    "epoch": {
      "description": "The `PrivacyMode` record's configuration epoch (the would-be one for\na dry run); `null` before the first record.",
      "format": "uint64",
      "minimum": 0,
      "type": [
        "integer",
        "null"
      ]
    },
    "lsn": {
      "description": "The new record's LSN; `null` for a dry run or when nothing changed.",
      "format": "uint64",
      "minimum": 0,
      "type": [
        "integer",
        "null"
      ]
    },
    "mode": {
      "$ref": "#/components/schemas/PrivacyModeName"
    },
    "previous": {
      "$ref": "#/components/schemas/PrivacyModeName"
    }
  },
  "required": [
    "dry_run",
    "changed",
    "mode",
    "previous"
  ],
  "type": "object"
}
```

### PrivacyStatus

```json
{
  "description": "`GET /v1/privacy`.",
  "properties": {
    "epoch": {
      "description": "The latest `PrivacyMode` record's epoch; `null` before the first.",
      "format": "uint64",
      "minimum": 0,
      "type": [
        "integer",
        "null"
      ]
    },
    "keystore": {
      "anyOf": [
        {
          "$ref": "#/components/schemas/KeystoreCounts"
        },
        {
          "type": "null"
        }
      ],
      "description": "`null` when the daemon runs without a keystore."
    },
    "mode": {
      "$ref": "#/components/schemas/PrivacyModeName"
    },
    "pending_erasures": {
      "default": 0,
      "description": "Erasures that still have a plain value in the log (§6.5). The count\nnames no subject.",
      "format": "uint64",
      "minimum": 0,
      "type": "integer"
    },
    "reseal": {
      "$ref": "#/components/schemas/ResealStatus",
      "default": {
        "pending_segments": 0,
        "segments_done": 0,
        "segments_total": 0,
        "tombstones": 0,
        "values_sealed": 0
      },
      "description": "Reseal progress (§8). Zero until the first reseal."
    }
  },
  "required": [
    "mode"
  ],
  "type": "object"
}
```

### PromoteResponse

```json
{
  "properties": {
    "deployment": {
      "$ref": "#/components/schemas/SwitchInfo"
    },
    "dry_run": {
      "type": "boolean"
    },
    "policy": {
      "$ref": "#/components/schemas/PolicyEvaluation"
    },
    "rebase": {
      "anyOf": [
        {
          "$ref": "#/components/schemas/RebaseSwitchInfo"
        },
        {
          "type": "null"
        }
      ],
      "description": "Set for a rollback via replay (M13)."
    }
  },
  "required": [
    "dry_run",
    "deployment",
    "policy"
  ],
  "type": "object"
}
```

### ProposalInfo

```json
{
  "properties": {
    "approval_requests": {
      "default": [],
      "items": {
        "$ref": "#/components/schemas/ApprovalRequestInfo"
      },
      "type": "array"
    },
    "diff_hash": {
      "type": "string"
    },
    "error": {
      "$ref": "#/components/schemas/Error",
      "description": "When `failed`: why, as the error JSON (M10)."
    },
    "fork": {
      "type": "string"
    },
    "fork_lsn": {
      "format": "uint64",
      "minimum": 0,
      "type": "integer"
    },
    "id": {
      "type": "string"
    },
    "kinds": {
      "description": "The code the proposal switches: one entry per changed actor kind.",
      "items": {
        "$ref": "#/components/schemas/DeploymentKind"
      },
      "type": "array"
    },
    "policy": {
      "anyOf": [
        {
          "$ref": "#/components/schemas/PolicyEvaluation"
        },
        {
          "type": "null"
        }
      ],
      "description": "The policy evaluation (§7); null while `running`."
    },
    "progress": {
      "anyOf": [
        {
          "$ref": "#/components/schemas/ProposalProgress"
        },
        {
          "type": "null"
        }
      ],
      "description": "While `running`: how far the replay has come (M10)."
    },
    "rebase": {
      "anyOf": [
        {
          "$ref": "#/components/schemas/RebaseView"
        },
        {
          "type": "null"
        }
      ],
      "description": "A rollback via replay (M13): what it rolls back."
    },
    "status": {
      "description": "`running`, `evaluated`, `approved`, `promoted`, `rejected`, `stale`\nor `failed`.",
      "type": "string"
    },
    "summary": {
      "anyOf": [
        {
          "$ref": "#/components/schemas/DiffSummary"
        },
        {
          "type": "null"
        }
      ],
      "description": "The diff's summary (§5.1); null while `running`."
    },
    "unchanged": {
      "default": [],
      "description": "Components of the request whose code main already ran: skipped, not\nin the fork's code (M9).",
      "items": {
        "$ref": "#/components/schemas/DeploymentKind"
      },
      "type": "array"
    },
    "verified_through_lsn": {
      "format": "uint64",
      "minimum": 0,
      "type": "integer"
    },
    "warnings": {
      "description": "What a reader must know about how the proposal was verified, e.g.\nthat retention cut its window short.",
      "items": {
        "type": "string"
      },
      "type": "array"
    }
  },
  "required": [
    "id",
    "fork",
    "status",
    "fork_lsn",
    "verified_through_lsn",
    "diff_hash",
    "policy",
    "summary",
    "kinds"
  ],
  "type": "object"
}
```

### ProposalProgress

```json
{
  "description": "Root inputs replayed so far and to replay, per replay mode (0 and 0 for\na mode that does not run, or has not counted its inputs yet).",
  "properties": {
    "continuous_done": {
      "format": "uint64",
      "minimum": 0,
      "type": "integer"
    },
    "continuous_total": {
      "format": "uint64",
      "minimum": 0,
      "type": "integer"
    },
    "isolated_done": {
      "format": "uint64",
      "minimum": 0,
      "type": "integer"
    },
    "isolated_total": {
      "format": "uint64",
      "minimum": 0,
      "type": "integer"
    }
  },
  "required": [
    "isolated_done",
    "isolated_total",
    "continuous_done",
    "continuous_total"
  ],
  "type": "object"
}
```

### ProposalsResponse

```json
{
  "properties": {
    "proposals": {
      "items": {
        "$ref": "#/components/schemas/ProposalInfo"
      },
      "type": "array"
    }
  },
  "required": [
    "proposals"
  ],
  "type": "object"
}
```

### ProposeResponse

```json
{
  "properties": {
    "dry_run": {
      "type": "boolean"
    },
    "proposal": {
      "$ref": "#/components/schemas/ProposalInfo"
    }
  },
  "required": [
    "dry_run",
    "proposal"
  ],
  "type": "object"
}
```

### RebaseSwitchInfo

```json
{
  "description": "The switch of a rollback via replay (M13).",
  "properties": {
    "base_lsn": {
      "format": "uint64",
      "minimum": 0,
      "type": "integer"
    },
    "irreversible_effects": {
      "format": "uint64",
      "minimum": 0,
      "type": "integer"
    },
    "lsn": {
      "description": "The `StateRebase` record (0 for a dry run).",
      "format": "uint64",
      "minimum": 0,
      "type": "integer"
    },
    "turns": {
      "description": "The replayed turns that became main's state.",
      "format": "uint64",
      "minimum": 0,
      "type": "integer"
    }
  },
  "required": [
    "lsn",
    "base_lsn",
    "turns",
    "irreversible_effects"
  ],
  "type": "object"
}
```

### RebaseView

```json
{
  "description": "What a rebase proposal rolls back (M13).",
  "properties": {
    "base_lsn": {
      "description": "The fork point: main's last LSN before the rolled-back deployment.",
      "format": "uint64",
      "minimum": 0,
      "type": "integer"
    },
    "irreversible_effects": {
      "description": "External effects of the rolled-back code the old code would not\nhave made (the diff's `irreversible`).",
      "format": "uint64",
      "minimum": 0,
      "type": "integer"
    },
    "rolled_back_epoch": {
      "format": "uint64",
      "minimum": 0,
      "type": "integer"
    },
    "switch_lsn": {
      "description": "The `StateRebase` switch, once promoted.",
      "format": "uint64",
      "minimum": 0,
      "type": [
        "integer",
        "null"
      ]
    }
  },
  "required": [
    "rolled_back_epoch",
    "base_lsn",
    "irreversible_effects"
  ],
  "type": "object"
}
```

### ReplayResponse

```json
{
  "properties": {
    "diff_hash": {
      "type": "string"
    },
    "fork": {
      "type": "string"
    },
    "summary": {
      "$ref": "#/components/schemas/DiffSummary",
      "description": "The diff's summary (§5.1)."
    }
  },
  "required": [
    "fork",
    "summary",
    "diff_hash"
  ],
  "type": "object"
}
```

### Reply

```json
{
  "description": "Bytes as JSON: `text` when valid UTF-8 (responses), and always `base64`.\nRequests give either one.",
  "properties": {
    "base64": {
      "type": [
        "string",
        "null"
      ]
    },
    "content_type": {
      "type": "string"
    },
    "name": {
      "type": "string"
    },
    "text": {
      "type": [
        "string",
        "null"
      ]
    }
  },
  "required": [
    "name",
    "content_type"
  ],
  "type": "object"
}
```

### Report

```json
{
  "description": "What `kronik doctor --json` prints.",
  "properties": {
    "checks": {
      "items": {
        "$ref": "#/components/schemas/Check"
      },
      "type": "array"
    },
    "fail": {
      "format": "uint",
      "minimum": 0,
      "type": "integer"
    },
    "pass": {
      "format": "uint",
      "minimum": 0,
      "type": "integer"
    },
    "warn": {
      "format": "uint",
      "minimum": 0,
      "type": "integer"
    }
  },
  "required": [
    "checks",
    "pass",
    "warn",
    "fail"
  ],
  "type": "object"
}
```

### Report2

```json
{
  "description": "`kronik audit verify` (§4.5): a sink's lines against the log's.",
  "properties": {
    "complete": {
      "description": "Nothing missing, extra or conflicting.",
      "type": "boolean"
    },
    "conflicting": {
      "description": "Lines whose (lsn, effect) the log has with a different record, or\nwith other fields.",
      "items": {
        "$ref": "#/components/schemas/Item"
      },
      "type": "array"
    },
    "expected": {
      "description": "Audited items of the log in the range.",
      "format": "uint",
      "minimum": 0,
      "type": "integer"
    },
    "extra": {
      "description": "Lines for no item of the log.",
      "items": {
        "$ref": "#/components/schemas/Item"
      },
      "type": "array"
    },
    "from": {
      "description": "The range checked, `(from, to]`.",
      "format": "uint64",
      "minimum": 0,
      "type": "integer"
    },
    "lines": {
      "description": "Distinct sink lines in the range.",
      "format": "uint",
      "minimum": 0,
      "type": "integer"
    },
    "missing": {
      "items": {
        "$ref": "#/components/schemas/Item"
      },
      "type": "array"
    },
    "superseded": {
      "description": "Lines of a tail that a later `restore` event replaced: exported\nbefore the restore, with LSNs past its `through_lsn`.",
      "format": "uint",
      "minimum": 0,
      "type": "integer"
    },
    "to": {
      "format": "uint64",
      "minimum": 0,
      "type": "integer"
    }
  },
  "required": [
    "complete",
    "from",
    "to",
    "expected",
    "lines",
    "missing",
    "extra",
    "conflicting",
    "superseded"
  ],
  "type": "object"
}
```

### ResealResponse

```json
{
  "description": "The answer to `POST /v1/privacy/reseal`.",
  "properties": {
    "dry_run": {
      "type": "boolean"
    },
    "segments": {
      "description": "Closed segments rewritten, or that a dry run would rewrite.",
      "format": "uint64",
      "minimum": 0,
      "type": "integer"
    },
    "started": {
      "description": "False for a dry run, and when no closed segment needed rewriting.",
      "type": "boolean"
    }
  },
  "required": [
    "dry_run",
    "started",
    "segments"
  ],
  "type": "object"
}
```

### ResealStatus

```json
{
  "description": "Progress of the latest reseal, and segments whose shipped copy is still\nthe pre-reseal bytes.",
  "properties": {
    "pending_segments": {
      "description": "Rewritten segments not yet replaced in object storage.",
      "format": "uint64",
      "minimum": 0,
      "type": "integer"
    },
    "segments_done": {
      "format": "uint64",
      "minimum": 0,
      "type": "integer"
    },
    "segments_total": {
      "format": "uint64",
      "minimum": 0,
      "type": "integer"
    },
    "tombstones": {
      "format": "uint64",
      "minimum": 0,
      "type": "integer"
    },
    "values_sealed": {
      "format": "uint64",
      "minimum": 0,
      "type": "integer"
    }
  },
  "required": [
    "segments_done",
    "segments_total",
    "values_sealed",
    "tombstones",
    "pending_segments"
  ],
  "type": "object"
}
```

### RestoreOutput

```json
{
  "description": "What `kronik restore --json` prints.",
  "properties": {
    "branch": {
      "type": "string"
    },
    "components": {
      "format": "uint64",
      "minimum": 0,
      "type": [
        "integer",
        "null"
      ]
    },
    "data_dir": {
      "type": "string"
    },
    "dry_run": {
      "type": "boolean"
    },
    "endpoint": {
      "description": "Absent when no endpoint was given.",
      "type": [
        "string",
        "null"
      ]
    },
    "from": {
      "type": "string"
    },
    "keys_missing": {
      "description": "With `--allow-missing-keys`: subjects whose sealed values have no key\nand stay unreadable. Absent when there are none.",
      "items": {
        "type": "string"
      },
      "type": "array"
    },
    "keystore": {
      "description": "The privacy keystore backup: `installed`, `none_in_bucket`, or\n`skipped` (`--without-keystore`). Absent for a dry run.",
      "type": [
        "string",
        "null"
      ]
    },
    "log_first_lsn": {
      "format": "uint64",
      "minimum": 0,
      "type": [
        "integer",
        "null"
      ]
    },
    "segments": {
      "format": "uint64",
      "minimum": 0,
      "type": [
        "integer",
        "null"
      ]
    },
    "snapshot_id": {
      "type": [
        "string",
        "null"
      ]
    },
    "snapshot_lsn": {
      "description": "Set after a restore. A dry run does not download, so these are absent.",
      "format": "uint64",
      "minimum": 0,
      "type": [
        "integer",
        "null"
      ]
    },
    "state_hash": {
      "type": [
        "string",
        "null"
      ]
    }
  },
  "required": [
    "dry_run",
    "from",
    "data_dir",
    "branch",
    "keys_missing"
  ],
  "type": "object"
}
```

### RevokeResponse

```json
{
  "properties": {
    "dry_run": {
      "type": "boolean"
    },
    "revoked": {
      "$ref": "#/components/schemas/Revoked"
    }
  },
  "required": [
    "dry_run",
    "revoked"
  ],
  "type": "object"
}
```

### Revoked

```json
{
  "properties": {
    "capability": {
      "type": "string"
    },
    "epoch": {
      "format": "uint64",
      "minimum": 0,
      "type": "integer"
    },
    "kind": {
      "type": "string"
    },
    "lsn": {
      "format": "uint64",
      "minimum": 0,
      "type": "integer"
    }
  },
  "required": [
    "kind",
    "capability",
    "epoch",
    "lsn"
  ],
  "type": "object"
}
```

### RollbackResponse

```json
{
  "properties": {
    "deployment": {
      "$ref": "#/components/schemas/SwitchInfo"
    },
    "dry_run": {
      "type": "boolean"
    }
  },
  "required": [
    "dry_run",
    "deployment"
  ],
  "type": "object"
}
```

### Route

```json
{
  "properties": {
    "method": {
      "type": "string"
    },
    "pattern": {
      "type": "string"
    }
  },
  "required": [
    "method",
    "pattern"
  ],
  "type": "object"
}
```

### SecretDeleteResponse

```json
{
  "properties": {
    "deleted": {
      "$ref": "#/components/schemas/SecretDeleted"
    },
    "dry_run": {
      "type": "boolean"
    }
  },
  "required": [
    "dry_run",
    "deleted"
  ],
  "type": "object"
}
```

### SecretDeleted

```json
{
  "properties": {
    "name": {
      "type": "string"
    },
    "versions": {
      "format": "uint32",
      "minimum": 0,
      "type": "integer"
    }
  },
  "required": [
    "name",
    "versions"
  ],
  "type": "object"
}
```

### SecretResponse

```json
{
  "properties": {
    "dry_run": {
      "type": "boolean"
    },
    "secret": {
      "anyOf": [
        {
          "$ref": "#/components/schemas/SecretView"
        },
        {
          "type": "null"
        }
      ],
      "description": "Absent for dry runs."
    }
  },
  "required": [
    "dry_run"
  ],
  "type": "object"
}
```

### SecretView

```json
{
  "properties": {
    "created_wall_ms": {
      "format": "uint64",
      "minimum": 0,
      "type": "integer"
    },
    "name": {
      "type": "string"
    },
    "version": {
      "format": "uint32",
      "minimum": 0,
      "type": "integer"
    },
    "version_hash": {
      "description": "Hex of the keyed version hash; never the value.",
      "type": "string"
    }
  },
  "required": [
    "name",
    "version",
    "version_hash",
    "created_wall_ms"
  ],
  "type": "object"
}
```

### SecretsResponse

```json
{
  "properties": {
    "secrets": {
      "items": {
        "$ref": "#/components/schemas/SecretView"
      },
      "type": "array"
    }
  },
  "required": [
    "secrets"
  ],
  "type": "object"
}
```

### SimulatorInfo

```json
{
  "description": "One simulator Kronik has.",
  "properties": {
    "description": {
      "type": "string"
    },
    "grounding": {
      "description": "`recorded` (exact and approximate matches) or `synthetic`.",
      "type": "string"
    },
    "name": {
      "description": "`recorded`, `stub`, `contract`, `neighbor`, `model`, `fail-closed`,\n`placeholder`.",
      "type": "string"
    }
  },
  "required": [
    "name",
    "grounding",
    "description"
  ],
  "type": "object"
}
```

### SimulatorsResponse

```json
{
  "properties": {
    "model": {
      "$ref": "#/components/schemas/ModelView"
    },
    "simulators": {
      "items": {
        "$ref": "#/components/schemas/SimulatorInfo"
      },
      "type": "array"
    },
    "targets": {
      "items": {
        "$ref": "#/components/schemas/TargetSimulatorsView"
      },
      "type": "array"
    }
  },
  "required": [
    "simulators",
    "targets",
    "model"
  ],
  "type": "object"
}
```

### SimulatorsSetResponse

```json
{
  "properties": {
    "dry_run": {
      "type": "boolean"
    },
    "epoch": {
      "format": "uint64",
      "minimum": 0,
      "type": "integer"
    },
    "lsn": {
      "description": "0 for a dry run.",
      "format": "uint64",
      "minimum": 0,
      "type": "integer"
    },
    "target": {
      "type": "string"
    }
  },
  "required": [
    "dry_run",
    "target",
    "epoch",
    "lsn"
  ],
  "type": "object"
}
```

### SnapshotCreateResponse

```json
{
  "properties": {
    "dry_run": {
      "type": "boolean"
    },
    "lsn": {
      "description": "The snapshot's LSN (for a dry run: the applied LSN it would take).",
      "format": "uint64",
      "minimum": 0,
      "type": "integer"
    },
    "snapshot": {
      "anyOf": [
        {
          "$ref": "#/components/schemas/SnapshotEntry"
        },
        {
          "type": "null"
        }
      ]
    }
  },
  "required": [
    "dry_run",
    "lsn"
  ],
  "type": "object"
}
```

### SnapshotEntry

```json
{
  "properties": {
    "bytes": {
      "description": "The files' total size.",
      "format": "uint64",
      "minimum": 0,
      "type": "integer"
    },
    "created_wall_ms": {
      "format": "uint64",
      "minimum": 0,
      "type": "integer"
    },
    "engine_version": {
      "type": "string"
    },
    "id": {
      "description": "`<branch>-<lsn>`.",
      "type": "string"
    },
    "lsn": {
      "description": "The state is exactly the log's through this LSN.",
      "format": "uint64",
      "minimum": 0,
      "type": "integer"
    },
    "reason": {
      "description": "`interval`, `shutdown` or `manual`.",
      "type": "string"
    },
    "shipped": {
      "default": false,
      "description": "True when this snapshot's LSN is recorded in `<data_dir>/ship.json`.\nFalse when shipping is off or the snapshot has not been uploaded.\nMissing on an older response decodes as false.",
      "type": "boolean"
    },
    "state_hash": {
      "description": "BLAKE3 over the materialized state at `lsn` (m6-storage §8).",
      "type": "string"
    }
  },
  "required": [
    "id",
    "lsn",
    "created_wall_ms",
    "engine_version",
    "bytes",
    "reason",
    "state_hash"
  ],
  "type": "object"
}
```

### SnapshotsResponse

```json
{
  "properties": {
    "snapshots": {
      "description": "Newest first.",
      "items": {
        "$ref": "#/components/schemas/SnapshotEntry"
      },
      "type": "array"
    }
  },
  "required": [
    "snapshots"
  ],
  "type": "object"
}
```

### SqlSummary

```json
{
  "properties": {
    "tables": {
      "items": {
        "$ref": "#/components/schemas/SqlTable"
      },
      "type": "array"
    }
  },
  "required": [
    "tables"
  ],
  "type": "object"
}
```

### SqlTable

```json
{
  "properties": {
    "name": {
      "type": "string"
    },
    "rows": {
      "format": "uint64",
      "minimum": 0,
      "type": "integer"
    }
  },
  "required": [
    "name",
    "rows"
  ],
  "type": "object"
}
```

### StateEntry

```json
{
  "description": "Bytes as JSON: `text` when valid UTF-8 (responses), and always `base64`.\nRequests give either one.",
  "properties": {
    "base64": {
      "type": [
        "string",
        "null"
      ]
    },
    "key": {
      "type": "string"
    },
    "lsn": {
      "format": "uint64",
      "minimum": 0,
      "type": "integer"
    },
    "subject": {
      "description": "The value's subject; null for a caller without `pii:read`.",
      "type": [
        "string",
        "null"
      ]
    },
    "text": {
      "type": [
        "string",
        "null"
      ]
    }
  },
  "required": [
    "key",
    "lsn"
  ],
  "type": "object"
}
```

### Status

```json
{
  "enum": [
    "pass",
    "warn",
    "fail"
  ],
  "type": "string"
}
```

### SwitchInfo

```json
{
  "properties": {
    "effective_lsn": {
      "description": "0 means \"at its own LSN\".",
      "format": "uint64",
      "minimum": 0,
      "type": "integer"
    },
    "epoch": {
      "format": "uint64",
      "minimum": 0,
      "type": "integer"
    },
    "kinds": {
      "items": {
        "$ref": "#/components/schemas/DeploymentKind"
      },
      "type": "array"
    },
    "lsn": {
      "format": "uint64",
      "minimum": 0,
      "type": "integer"
    },
    "unverified_inputs": {
      "format": "uint64",
      "minimum": 0,
      "type": "integer"
    },
    "verified_through_lsn": {
      "format": "uint64",
      "minimum": 0,
      "type": "integer"
    }
  },
  "required": [
    "epoch",
    "lsn",
    "effective_lsn",
    "verified_through_lsn",
    "unverified_inputs",
    "kinds"
  ],
  "type": "object"
}
```

### TargetSimulatorsView

```json
{
  "description": "A target's simulator configuration in force.",
  "properties": {
    "contract": {
      "anyOf": [
        {
          "$ref": "#/components/schemas/ContractView"
        },
        {
          "type": "null"
        }
      ]
    },
    "epoch": {
      "format": "uint64",
      "minimum": 0,
      "type": "integer"
    },
    "lsn": {
      "format": "uint64",
      "minimum": 0,
      "type": "integer"
    },
    "model": {
      "type": "boolean"
    },
    "neighbor": {
      "type": "boolean"
    },
    "reason": {
      "type": "string"
    },
    "stubs": {
      "description": "The number of stub rules.",
      "format": "uint64",
      "minimum": 0,
      "type": "integer"
    },
    "target": {
      "type": "string"
    }
  },
  "required": [
    "target",
    "stubs",
    "neighbor",
    "model",
    "epoch",
    "lsn",
    "reason"
  ],
  "type": "object"
}
```

### Timer

```json
{
  "properties": {
    "due_ms": {
      "format": "uint64",
      "minimum": 0,
      "type": "integer"
    },
    "id": {
      "description": "Decimal string: the u64 does not fit a JSON number exactly.",
      "type": "string"
    },
    "name": {
      "type": "string"
    }
  },
  "required": [
    "id",
    "due_ms",
    "name"
  ],
  "type": "object"
}
```

### TimersResponse

```json
{
  "properties": {
    "timers": {
      "items": {
        "$ref": "#/components/schemas/Timer"
      },
      "type": "array"
    }
  },
  "required": [
    "timers"
  ],
  "type": "object"
}
```

### TokenCreateResponse

```json
{
  "properties": {
    "dry_run": {
      "type": "boolean"
    },
    "secret": {
      "description": "The bearer token. It is returned only here, once, and never stored;\nabsent for dry runs.",
      "type": [
        "string",
        "null"
      ]
    },
    "token": {
      "$ref": "#/components/schemas/TokenView"
    }
  },
  "required": [
    "dry_run",
    "token"
  ],
  "type": "object"
}
```

### TokenRevokeResponse

```json
{
  "properties": {
    "dry_run": {
      "type": "boolean"
    },
    "token": {
      "$ref": "#/components/schemas/TokenView"
    }
  },
  "required": [
    "dry_run",
    "token"
  ],
  "type": "object"
}
```

### TokenView

```json
{
  "properties": {
    "created_by": {
      "description": "The caller that created it.",
      "type": "string"
    },
    "created_wall_ms": {
      "format": "uint64",
      "minimum": 0,
      "type": "integer"
    },
    "name": {
      "type": "string"
    },
    "reason": {
      "type": "string"
    },
    "revoke_reason": {
      "type": [
        "string",
        "null"
      ]
    },
    "revoked": {
      "type": "boolean"
    },
    "revoked_by": {
      "type": [
        "string",
        "null"
      ]
    },
    "revoked_wall_ms": {
      "format": "uint64",
      "minimum": 0,
      "type": [
        "integer",
        "null"
      ]
    },
    "scopes": {
      "items": {
        "type": "string"
      },
      "type": "array"
    },
    "token_id": {
      "description": "How the token's actions are recorded: `token:<name>`.",
      "type": "string"
    }
  },
  "required": [
    "name",
    "token_id",
    "scopes",
    "created_wall_ms",
    "created_by",
    "reason",
    "revoked"
  ],
  "type": "object"
}
```

### TokensResponse

```json
{
  "properties": {
    "tokens": {
      "items": {
        "$ref": "#/components/schemas/TokenView"
      },
      "type": "array"
    }
  },
  "required": [
    "tokens"
  ],
  "type": "object"
}
```

### Topic

```json
{
  "description": "A `kronik explain` topic.",
  "properties": {
    "http_status": {
      "description": "Error codes only.",
      "type": "integer"
    },
    "kind": {
      "enum": [
        "concept",
        "guide",
        "error_code"
      ],
      "type": "string"
    },
    "milestone": {
      "type": "string"
    },
    "name": {
      "description": "A concept, a guide or an error code.",
      "type": "string"
    },
    "text": {
      "description": "Markdown.",
      "type": "string"
    },
    "title": {
      "type": "string"
    }
  },
  "required": [
    "name",
    "kind",
    "title",
    "milestone",
    "text"
  ],
  "type": "object"
}
```

### TopicList

```json
{
  "description": "`kronik explain --list`.",
  "properties": {
    "topics": {
      "items": {
        "$ref": "#/components/schemas/Topic"
      },
      "type": "array"
    }
  },
  "required": [
    "topics"
  ],
  "type": "object"
}
```

### TraceNode

```json
{
  "description": "One node of a causal tree (`GET /v1/turns/{id}/trace`).",
  "properties": {
    "actor": {
      "type": "string"
    },
    "children": {
      "items": {
        "$ref": "#/components/schemas/TraceNode"
      },
      "type": "array"
    },
    "input": {
      "$ref": "#/components/schemas/InputSummary"
    },
    "outcome": {
      "$ref": "#/components/schemas/Outcome"
    },
    "turn_id": {
      "type": "string"
    }
  },
  "required": [
    "turn_id",
    "actor",
    "input",
    "outcome",
    "children"
  ],
  "type": "object"
}
```

### TraceResponse

```json
{
  "properties": {
    "actor": {
      "type": "string"
    },
    "ancestors": {
      "description": "From the root input down to the turn's parent.",
      "items": {
        "$ref": "#/components/schemas/TurnSummary"
      },
      "type": "array"
    },
    "descendants": {
      "description": "What the turn caused, as a tree (at most 1000 turns).",
      "items": {
        "$ref": "#/components/schemas/TraceNode"
      },
      "type": "array"
    },
    "root": {
      "anyOf": [
        {
          "$ref": "#/components/schemas/TraceRoot"
        },
        {
          "type": "null"
        }
      ],
      "description": "The tree's root input (absent when it is outside the log)."
    },
    "truncated": {
      "type": "boolean"
    },
    "turn": {
      "$ref": "#/components/schemas/TurnSummary"
    }
  },
  "required": [
    "turn",
    "actor",
    "ancestors",
    "descendants",
    "truncated"
  ],
  "type": "object"
}
```

### TraceRoot

```json
{
  "properties": {
    "input": {
      "$ref": "#/components/schemas/InputSummary"
    },
    "lsn": {
      "format": "uint64",
      "minimum": 0,
      "type": "integer"
    },
    "root_id": {
      "type": "string"
    }
  },
  "required": [
    "lsn",
    "root_id",
    "input"
  ],
  "type": "object"
}
```

### TurnResponse

```json
{
  "properties": {
    "dry_run": {
      "type": "boolean"
    },
    "outcome": {
      "anyOf": [
        {
          "$ref": "#/components/schemas/Outcome"
        },
        {
          "type": "null"
        }
      ]
    },
    "reply": {
      "anyOf": [
        {
          "$ref": "#/components/schemas/Reply"
        },
        {
          "type": "null"
        }
      ]
    },
    "turn_id": {
      "description": "Absent for dry runs.",
      "type": [
        "string",
        "null"
      ]
    }
  },
  "required": [
    "dry_run"
  ],
  "type": "object"
}
```

### TurnSummary

```json
{
  "properties": {
    "code_hash": {
      "type": "string"
    },
    "effects": {
      "default": [],
      "items": {
        "$ref": "#/components/schemas/EffectSummary"
      },
      "type": "array"
    },
    "fuel_used": {
      "format": "uint64",
      "minimum": 0,
      "type": "integer"
    },
    "input": {
      "$ref": "#/components/schemas/InputSummary"
    },
    "logical_time_ms": {
      "format": "uint64",
      "minimum": 0,
      "type": "integer"
    },
    "lsn": {
      "format": "uint64",
      "minimum": 0,
      "type": "integer"
    },
    "messages": {
      "items": {
        "$ref": "#/components/schemas/MessageSummary"
      },
      "type": "array"
    },
    "outcome": {
      "$ref": "#/components/schemas/Outcome"
    },
    "sql_changes": {
      "format": "uint64",
      "minimum": 0,
      "type": "integer"
    },
    "turn_id": {
      "type": "string"
    },
    "writes": {
      "items": {
        "$ref": "#/components/schemas/WriteSummary"
      },
      "type": "array"
    }
  },
  "required": [
    "turn_id",
    "lsn",
    "logical_time_ms",
    "code_hash",
    "input",
    "outcome",
    "writes",
    "messages",
    "sql_changes",
    "fuel_used"
  ],
  "type": "object"
}
```

### UpgradeCheckOutput

```json
{
  "description": "What `kronik upgrade check --json` prints: the report, plus the diff\npath when one was written. `code` is set when the process exits 1.",
  "properties": {
    "checked_through_lsn": {
      "format": "uint64",
      "minimum": 0,
      "type": "integer"
    },
    "checked_wall_ms": {
      "format": "uint64",
      "minimum": 0,
      "type": "integer"
    },
    "code": {
      "description": "`ENGINE_UPGRADE_DIVERGED` when the diff is not empty.",
      "type": [
        "string",
        "null"
      ]
    },
    "diff_hash": {
      "type": "string"
    },
    "diff_path": {
      "description": "Set when a diverging diff was written.",
      "type": [
        "string",
        "null"
      ]
    },
    "dry_run": {
      "type": "boolean"
    },
    "fork_lsn": {
      "format": "uint64",
      "minimum": 0,
      "type": "integer"
    },
    "from_engine": {
      "type": "string"
    },
    "passed": {
      "type": "boolean"
    },
    "report_path": {
      "description": "Set when the report file was written.",
      "type": [
        "string",
        "null"
      ]
    },
    "root_inputs": {
      "format": "uint64",
      "minimum": 0,
      "type": "integer"
    },
    "schema": {
      "type": "string"
    },
    "to_engine": {
      "type": "string"
    },
    "turns": {
      "format": "uint64",
      "minimum": 0,
      "type": "integer"
    },
    "window_ms": {
      "format": "uint64",
      "minimum": 0,
      "type": "integer"
    }
  },
  "required": [
    "schema",
    "from_engine",
    "to_engine",
    "window_ms",
    "fork_lsn",
    "checked_through_lsn",
    "root_inputs",
    "turns",
    "diff_hash",
    "passed",
    "checked_wall_ms",
    "dry_run"
  ],
  "type": "object"
}
```

### WatchInfo

```json
{
  "description": "A watch of a deployment (M11).",
  "properties": {
    "created_ms": {
      "format": "uint64",
      "minimum": 0,
      "type": "integer"
    },
    "deployment_lsn": {
      "format": "uint64",
      "minimum": 0,
      "type": "integer"
    },
    "deployment_time_ms": {
      "description": "Logical time where the window after the deployment starts.",
      "format": "uint64",
      "minimum": 0,
      "type": "integer"
    },
    "epoch": {
      "description": "The watched deployment's epoch and the LSN of its record.",
      "format": "uint64",
      "minimum": 0,
      "type": "integer"
    },
    "error": {
      "$ref": "#/components/schemas/Error",
      "description": "When `failed`: why, as the error JSON."
    },
    "for_ms": {
      "format": "uint64",
      "minimum": 0,
      "type": "integer"
    },
    "id": {
      "description": "`w-` and 12 hex characters.",
      "type": "string"
    },
    "metrics": {
      "anyOf": [
        {
          "$ref": "#/components/schemas/GuardMetrics"
        },
        {
          "type": "null"
        }
      ],
      "description": "The metrics of the last evaluation (the CEL variable `guard`);\nnull before the first."
    },
    "reason": {
      "type": "string"
    },
    "status": {
      "description": "`watching`, `done` (the window passed), `rolled_back`, `superseded`\n(a later deployment of its kinds replaced the watched one; nothing\nacted), `stopped` or `failed`.",
      "type": "string"
    },
    "stopped": {
      "anyOf": [
        {
          "$ref": "#/components/schemas/WatchStopped"
        },
        {
          "type": "null"
        }
      ],
      "description": "When `stopped`: who stopped it and why."
    },
    "token_id": {
      "type": "string"
    },
    "triggered": {
      "description": "The guards that fired, in order. Each fires once; a guard that could\nnot be evaluated also alerts once, with a reason starting \"the\nguard could not be evaluated: \".",
      "items": {
        "$ref": "#/components/schemas/WatchTriggered"
      },
      "type": "array"
    }
  },
  "required": [
    "id",
    "epoch",
    "deployment_lsn",
    "for_ms",
    "deployment_time_ms",
    "status",
    "reason",
    "token_id",
    "created_ms",
    "triggered"
  ],
  "type": "object"
}
```

### WatchResponse

```json
{
  "properties": {
    "dry_run": {
      "type": "boolean"
    },
    "watch": {
      "$ref": "#/components/schemas/WatchInfo",
      "description": "In a dry run: the current metrics, and in `triggered` (with `lsn`\n0) the guards that would fire now."
    }
  },
  "required": [
    "dry_run",
    "watch"
  ],
  "type": "object"
}
```

### WatchStopped

```json
{
  "description": "`kronik watches stop`'s audit.",
  "properties": {
    "reason": {
      "type": "string"
    },
    "token_id": {
      "type": "string"
    },
    "wall_time_ms": {
      "format": "uint64",
      "minimum": 0,
      "type": "integer"
    }
  },
  "required": [
    "token_id",
    "reason",
    "wall_time_ms"
  ],
  "type": "object"
}
```

### WatchTriggered

```json
{
  "description": "A guard that fired: its `GuardTriggered` record.",
  "properties": {
    "action": {
      "description": "`alert` or `rollback`.",
      "type": "string"
    },
    "guard": {
      "type": "string"
    },
    "lsn": {
      "description": "The `GuardTriggered` record's LSN.",
      "format": "uint64",
      "minimum": 0,
      "type": "integer"
    },
    "outcome": {
      "description": "`alerted`, `rolled_back`, `rollback_refused_schema` or\n`rollback_failed`.",
      "type": "string"
    },
    "reason": {
      "type": "string"
    },
    "rollback_epoch": {
      "description": "The rollback deployment's epoch; 0 without one.",
      "format": "uint64",
      "minimum": 0,
      "type": "integer"
    }
  },
  "required": [
    "guard",
    "action",
    "outcome",
    "lsn",
    "rollback_epoch",
    "reason"
  ],
  "type": "object"
}
```

### WatchesResponse

```json
{
  "properties": {
    "watches": {
      "items": {
        "$ref": "#/components/schemas/WatchInfo"
      },
      "type": "array"
    }
  },
  "required": [
    "watches"
  ],
  "type": "object"
}
```

### WriteSummary

```json
{
  "properties": {
    "erased": {
      "description": "The value was sealed for a subject that has been erased since: it\nreads as `[erased]` (docs/design/m8-privacy.md §5). Omitted when\nfalse.",
      "type": "boolean"
    },
    "key": {
      "type": "string"
    },
    "op": {
      "type": "string"
    },
    "subject": {
      "description": "The value's subject; null for a caller without `pii:read`.",
      "type": [
        "string",
        "null"
      ]
    }
  },
  "required": [
    "op",
    "key"
  ],
  "type": "object"
}
```
