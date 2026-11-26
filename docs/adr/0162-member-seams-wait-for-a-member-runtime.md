# 0162. Member-only seams wait for a Member runtime

- **Status:** Accepted
- **Date:** 2026-11-26

## Context

The cluster track (M16–M19) is a design in this repository, not a runtime.
There is no Member frontend, MetaService, metadata host or ForwardApi peer to
produce member observations, metadata-source events or member login receipts,
and nothing installs the seams that would consume them. The 2026-11-22
over-engineering audit found four such sets; only their own tests construct
them:

- `Api::with_cluster_status` (#336), which no caller installs, so
  `Api.cluster_status` is always `None` and `GET /v1/cluster/status` always
  takes the non-member branch;
- the metadata-source event pipeline in `kronik-fleet`, `kronik-otel`,
  `kronik-sched` and `kronik-api` (#331), whose only constructors are in tests;
- `TokenStore::for_member` and the member-only metadata types and methods
  (#332), also constructed only by tests;
- the fleet enrollment/control hashes and `Webhook::open_registered` with
  `Host::Registered` (#334), read by no production dispatcher.

A test that builds the producer is not evidence that a runtime can. These
seams compile and are covered, but they advertise configuration points that
nothing in this repository configures, and the tests pin paths production
cannot reach. The public contracts already describe the future runtime:
`ClusterStatusResponse` has its member variant, and the metadata event schema
has its Member sources.

AGENTS.md requires a maintainer decision before the scope changes. The
maintainer decided, for #331, #332, #334 and #336 together, to delete the
Member-only code until a real producer exists, and to record that in one ADR.
This is it. Git keeps the deleted code; restoring a seam is a checkout, not a
rewrite.

## Decision

Delete the Member-only seams, and restore a seam only together with a real
Member producer:

- #336: remove `Api::with_cluster_status`, the `Api.cluster_status` field and
  the `ClusterStatusRead` alias. `GET /v1/cluster/status` answers the native
  `{"member": false}` directly.
- #331: remove the metadata-source event pipeline from `kronik-fleet`,
  `kronik-otel`, `kronik-sched` and `kronik-api`; `Events` keeps only the
  native source. The read side that only this pipeline consumed goes with it:
  `kronik-log`'s `MetadataAuditSource`, `MetadataAuditBatch` and
  `MetadataAuditRecord`, and the Mapper's typed native-adoption fact. The
  closed metadata audit-record schemas (`MetadataAuditGap`,
  `MetadataWebhookKeyChange`, `MetadataWebhookReplay` and their `kronik-proto`
  validators), `SourcePos::Metadata`, and the event schema's `metadata` source
  and `adoption` field stay: they are the format a Member must produce. The
  last commit with the pipeline is `58d82501`.
- #332: remove `TokenStore::for_member` and the member-only metadata types and
  methods; `TokenStore.inner` stops being an `Option`.
- #334: remove the enrollment and control hashes with their accessors, and
  `Webhook::open_registered` with `Host::Registered`.

The last commit that contains the cluster-status seam is `b8b9551b`
(2026-11-26), the parent of this change. The other three seams are still
present on that commit; because each lands as its own change, the last commit
that contains a seam is the parent of the change that removes it. Restore a
seam from that commit when the cluster track lands.

`GET /v1/cluster/status` keeps its public contract. The OpenAPI document,
`docs/reference/cluster-status.schema.json` and the member variant of the
response are unchanged, so a future Member does not need a client change. Only
the in-tree injection point goes.

The Member sections of the earlier ADRs describe the producer that will be
restored, not code in this repository. They apply again from the commit that
restores the producer, not before:

- ADR 0103: the physical member's `OidcLoginMetadata`/`ForwardApi` receipt, the
  native-to-member transition, `TokenStore::for_member`, and member session
  revocation.
- ADR 0105: the complete member/leader final-admission path, and the concrete
  Member and registered-source factories.
- ADR 0106: Member registration in the Member frontend, the
  `MetadataAuditSource`/`MetadataRuntime` metadata hosts, and metadata replay.
- ADR 0107: Member dispatch with its sealed handoff and ReadIndex, the
  history-only Meta26 cause, and member race acceptance.

## Alternatives

- **Keep each seam and comment where its producer will live.** There is no
  producer in this repository, and none is scheduled; a comment would name a
  design document rather than a caller. The tests would keep pinning paths
  production cannot reach, and readers would keep asking which of two
  cluster-status behaviors ships.
- **Delete only the cluster-status seam.** It is the smallest and the only one
  without a test constructing it, but the maintainer took one decision for all
  four. Leaving three would make this ADR partial and keep the larger
  unproduced paths.
- **Delete the member half of the public contract too.** That would be a
  compatibility change, not a seam deletion. The route, its scope and the
  schema are already published; a later Member can answer the member variant
  without clients changing.
- **Put a seam behind a default-off flag.** A flag still needs a producer to
  turn it on, and nothing in the workspace can provide one.

## Consequences

A native installation sees no API change: the route, its scope, the OpenAPI
document and the `{"member": false}` answer are the same. The removed Rust
items were public (`ClusterStatusRead`, and the same pattern in the other
crates), so an out-of-tree embedder can no longer inject those observations;
there is no in-tree caller, the workspace is `publish = false`, and v0.1 is
the native installation. The JSON Schema member variant remains the contract
a future Member must satisfy.

The tests that only constructed a deleted seam go with it. Tests that still
exercise native behavior stay. For #336 there was no test constructing the
source; a test now pins the native answer, so the route's behavior is covered
even without the branch.

Revisit when the cluster track (M16–M19) lands a Member frontend, MetaService
or metadata host in this repository. That change restores the seams from
`b8b9551b`, or from the parent of each later removal, and amends this ADR and
the schema if the public shape changed in the meantime. It does not grow a
second Member-only path beside them.
