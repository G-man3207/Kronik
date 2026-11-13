// The page that GET /chat/{key} serves: a WebSocket client for trying a
// room by hand. Text from the room is shown with textContent, never as HTML.

export const page = `<!doctype html>
<html lang="en">
<meta charset="utf-8">
<title>Kronik chat</title>
<style>
  body { font: 15px/1.4 system-ui, sans-serif; margin: 2rem auto; max-width: 40rem; }
  #log { border: 1px solid #ccc; height: 22rem; overflow-y: auto; padding: .5rem; }
  #log p { margin: .2rem 0; } .me { font-weight: 600; } .info { color: #666; }
  form { display: flex; gap: .5rem; margin-top: .5rem; } #text { flex: 1; }
</style>
<h1>Room <span id="room"></span></h1>
<form id="join"><input id="user" placeholder="your name: a-z, 0-9, _ and -" required pattern="[a-z0-9_-]{1,32}"><button>Join</button></form>
<div id="log" aria-live="polite"></div>
<form id="say"><input id="text" placeholder="message, or /bot words to stream an answer" disabled><button disabled>Send</button></form>
<script>
const room = decodeURIComponent(location.pathname.split("/")[2] || "");
document.getElementById("room").textContent = room;
const log = (text, cls) => {
  const p = document.createElement("p");
  p.textContent = text;
  if (cls) p.className = cls;
  const box = document.getElementById("log");
  box.append(p);
  box.scrollTop = box.scrollHeight;
};
let ws, me, last = 0, retry = 500;
function connect() {
  const proto = location.protocol === "https:" ? "wss:" : "ws:";
  ws = new WebSocket(proto + "//" + location.host + "/chat/" + encodeURIComponent(room) + "/ws?user=" + encodeURIComponent(me));
  ws.onopen = () => { retry = 500; document.querySelectorAll("#say *").forEach((e) => (e.disabled = false)); };
  ws.onmessage = async (e) => {
    const m = JSON.parse(e.data);
    if (m.type === "welcome") {
      // Fetch what this client missed while it was away.
      if (last > 0 && m.last > last) {
        const r = await fetch("/chat/" + encodeURIComponent(room) + "/messages?after=" + last);
        for (const old of (await r.json()).messages) show(old);
      }
      log("joined as " + me + "; here: " + (m.members.join(", ") || "nobody else"), "info");
    } else if (m.type === "message") show(m);
    else if (m.type === "token") log("bot: " + m.text, "info");
    else if (m.type === "joined" || m.type === "left") log(m.user + " " + m.type, "info");
    else if (m.type === "error") log("error: " + m.error, "info");
  };
  ws.onclose = (e) => {
    document.querySelectorAll("#say *").forEach((el) => (el.disabled = true));
    log("disconnected (" + e.code + (e.reason ? " " + e.reason : "") + "); reconnecting", "info");
    setTimeout(connect, retry * (0.5 + Math.random()));
    retry = Math.min(retry * 2, 30000);
  };
}
function show(m) {
  if (m.seq <= last) return;
  last = m.seq;
  log(m.user + ": " + (m.text ?? m.body), m.user === me ? "me" : "");
}
document.getElementById("join").onsubmit = (e) => {
  e.preventDefault();
  me = document.getElementById("user").value;
  document.getElementById("join").hidden = true;
  connect();
};
document.getElementById("say").onsubmit = (e) => {
  e.preventDefault();
  const input = document.getElementById("text");
  const text = input.value.trim();
  if (!text) return;
  const id = crypto.randomUUID();
  ws.send(JSON.stringify(text.startsWith("/bot ") ? { type: "bot", prompt: text.slice(5), id } : { type: "say", text, id }));
  input.value = "";
};
</script>
</html>
`;
