`kronik upgrade check` ran an identity replay with the same code hashes under the new binary's engine version (Kronik plus Wasmtime), and the behavior diff is not empty. The diff must be empty before a new binary is swapped in; fuel is not compared between engine versions.

Typical cause: a change in Kronik or Wasmtime that alters what guests observe, so existing code would behave differently under the new version.

To fix it, keep running the current binary, and report the diff together with both versions. Check a newer build again before switching:

    kronik upgrade check --window 6h

See also: `behavior-diff`, `ENGINE_VERSION_MISMATCH`.
