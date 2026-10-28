Privacy mode is a switch that the operator controls; turning it on writes a `PrivacyMode` record. The format always supports it (I9): every value carries a subject tag even in the `off` mode, which is the default and costs nothing measurable. In the `on` mode, values written under a subject are sealed with that subject's key (XChaCha20-Poly1305). Erasing a subject deletes its key and makes its sealed values unreadable everywhere, and reseal seals history written while the mode was off. The operator decides whether the mode is used and is responsible for the legal basis, agreements and retention periods.

    kronik privacy mode on --reason "..."
    kronik privacy erase user:123 --reason "..."
    kronik privacy reseal

See also: `subject`, `sealed-value`, `SUBJECT_ERASED`.
