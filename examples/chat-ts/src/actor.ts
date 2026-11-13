// chat-ts: chat rooms over WebSocket and SSE (see chat.ts).

import { actor } from "@kronik/sdk";
import { chat, format } from "./chat.ts";

export default actor(chat(format));
