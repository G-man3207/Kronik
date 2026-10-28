Kronik cannot use the image of a foreign actor. Images are always pinned by digest, every blob is checked against its digest and size, and the layers must unpack safely into a root file system for this host's platform.

Typical causes:

- A registry reference without a digest: use `<registry>/<repo>@sha256:<digest>`. A local OCI layout, `oci-layout:<dir>`, may omit the digest when it holds exactly one image.
- The registry or the layout directory is unreachable, or the image is private (registry pulls are anonymous in v0.1; copy a private image into a local layout with `skopeo copy`).
- A blob does not match its digest or size, the image has no `linux` manifest for this architecture, or a layer has an unsupported media type, escapes the root file system or exceeds the unpack limits.

To fix it, check the reference and the image, then add the foreign actor again:

    skopeo inspect --raw docker://<registry>/<repo>@sha256:<digest>
    kronik foreign add <name> --image <ref>@sha256:<digest> --port <port> --reason "..." --dry-run

See also: `foreign-actor`.
