The request body or the message is larger than the limit, so it was rejected before any turn ran. Messages and state values are limited to 1 MiB each by default, and the limits can be set per actor type; the gateway and the API also limit the size of requests. This code exists, rather than `BAD_REQUEST`, because the request is otherwise valid: only its size is the problem.

To fix it, send less data, or raise the actor type's limits with `kronik limits set` (M2) if larger messages are expected.
