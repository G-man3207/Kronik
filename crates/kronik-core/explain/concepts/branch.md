A branch is `main` or a fork (forks arrive with M3). A fork has its own log from its fork point, and every branch has its own materialized state, which is derived from the log (I4) and can always be rebuilt from it. Deployments, grants and limits (M2) and policy (M3) are records on a branch, so a branch's configuration is part of its history (I5).

See also: `fork`, `lsn`, `snapshot`.
