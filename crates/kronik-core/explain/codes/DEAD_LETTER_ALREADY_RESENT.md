The dead letter has already been resent, or a resend of it is in progress. Resending creates a new root input, so a dead letter can be resent only once; a second resend would run the input twice. This code is separate from `DEAD_LETTER_NOT_FOUND` because the dead letter exists: the conflict is with its state.

To fix it, look at the dead letter's `resent_as` turn. If that turn failed as well, it is a dead letter of its own; resend that one instead:

    kronik dead-letters list

See also: `dead-letters`.
