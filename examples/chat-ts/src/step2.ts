// chat-ts-step2: the same rooms with a changed message format, for the M24
// acceptance (docs/design/m24-connections.md, section 18): `message` frames
// carry the text as `body` instead of `text`. Replaying a recorded session
// through it shows changed outgoing frames and nothing else. Built with
// `kronik build --entry src/step2.ts`.

import { actor } from "@kronik/sdk";
import { chat, type ChatMessage } from "./chat.ts";

export default actor(chat((m: ChatMessage) => ({ type: "message", seq: m.seq, user: m.user, body: m.text, ts: m.ts, id: m.id })));
