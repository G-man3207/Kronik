The foreign actor's sandbox is not running or does not answer. Kronik starts, monitors and restarts foreign actors with backoff, so this is often temporary.

Typical causes:

- The program in the sandbox crashed or is still starting.
- The image or its configuration is wrong, so the sandbox keeps failing to start.
- `foreign add`: the registry (or the layout directory) did not answer within `[foreign] pull_timeout`. Check that it is reachable, or raise `pull_timeout`, and add the actor again.
- Another daemon holds `[foreign] run_dir`, so this one runs no foreign actors.

To fix it, check the foreign actor's state and its logs:

    kronik foreign list
    kronik foreign logs payments

See also: `foreign-actor`.
