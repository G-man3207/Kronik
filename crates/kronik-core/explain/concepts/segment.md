A segment is a log file. The active segment is written to. A segment is closed at 64 MiB or after 60 seconds; a closed segment is immutable, gets a footer index from actor to offset (M3) and can be shipped (M6). Every record in a segment sits in the envelope `[u32 len][u32 crc32c][u64 lsn][u8 kind][protobuf]`. A torn last record after a crash is truncated at startup; a corrupt record in the middle of a segment gives `STORAGE_CORRUPT`. Segments older than the retention window are deleted once a snapshot covers them (M6).

See also: `lsn`, `snapshot`, `STORAGE_CORRUPT`.
