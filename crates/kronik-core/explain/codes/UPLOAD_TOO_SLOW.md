A request body that may become a blob (a kind whose code reads blobs) is
read as it arrives, with no whole-body timeout, so that a slow large upload
is not cut off while bytes keep arriving. Instead, once `[gateway]
upload_rate_grace` (30 s) has passed, the bytes that arrived in the last
`[gateway] upload_rate_window` (30 s) must average at least `[gateway]
upload_min_rate` (8 KiB/s) per second. A body slower than that is refused
with `408 UPLOAD_TOO_SLOW`, and nothing of it is kept. Without the check, a
client sending a byte just inside the idle timeout would hold its
connection, and the upload's part file, indefinitely.

Send the body faster. An operator who expects slower uploads can lower
`[gateway] upload_min_rate`, or turn the check off with `"0B"`.

See also: `blob`.
