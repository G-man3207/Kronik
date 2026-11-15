The request body or the message is larger than the limit, so it was rejected before any turn ran. Messages and state values are limited to 1 MiB each by default, and the limits can be set per actor type; the gateway and the API also limit the size of requests. This code exists, rather than `BAD_REQUEST`, because the request is otherwise valid: only its size is the problem.

For an actor type whose code imports `kronik:actor/blobs` (M25, the SDKs' blob API), an HTTP request body may be larger than a message: a body above the type's blob threshold becomes a blob, up to the type's upload size (64 MiB by default). A larger body gets this code, at once when its `Content-Length` says so, and the hint names the limit:

    kronik limits set media --upload-size 1Gi --reason "albums take camera originals"

To fix it, send less data, or raise the actor type's limits with `kronik limits set` (M2) if larger messages are expected.
