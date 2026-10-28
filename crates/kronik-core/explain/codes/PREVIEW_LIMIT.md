A daemon keeps at most 16 previews live at once. Each one holds a copy of production's state at its fork point in memory for its whole time to live, and anyone with its URL can send it requests, so the number is capped to keep the daemon's memory bounded. `kronik preview create` answers this code when 16 previews have not expired yet; nothing is created.

Delete a preview you no longer need, or wait until one expires (`[fork] preview_ttl`, 24 h by default; `--ttl` sets it per preview):

    kronik preview list
    kronik preview delete <id> --reason "..."

See also: `PREVIEW_NOT_FOUND`, `fork`.
