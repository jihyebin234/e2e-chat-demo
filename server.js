import http from "node:http";
import { randomUUID } from "node:crypto";
import { readFile } from "node:fs/promises";
import { extname, join, normalize } from "node:path";
import { fileURLToPath } from "node:url";
import { WebSocketServer } from "ws";

const root = fileURLToPath(new URL("./public", import.meta.url));
const port = process.env.PORT || 3000;
const rooms = new Map();
const watchers = new Map();

const types = {
  ".html": "text/html; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".js": "text/javascript; charset=utf-8"
};

function send(ws, packet) {
  if (ws.readyState === ws.OPEN) {
    ws.send(JSON.stringify(packet));
  }
}

function roomPeers(roomId) {
  return Array.from(rooms.get(roomId)?.values() || []);
}

function roomWatchers(roomId) {
  return Array.from(watchers.get(roomId) || []);
}

function broadcast(roomId, packet, exceptId = null) {
  for (const peer of roomPeers(roomId)) {
    if (peer.id !== exceptId) {
      send(peer.ws, packet);
    }
  }
}

function broadcastObserved(roomId, packet) {
  broadcast(roomId, packet);
  for (const watcher of roomWatchers(roomId)) {
    send(watcher, packet);
  }
}

function leave(ws) {
  if (ws.watchRoomId) {
    const roomWatchers = watchers.get(ws.watchRoomId);
    roomWatchers?.delete(ws);
    if (roomWatchers?.size === 0) {
      watchers.delete(ws.watchRoomId);
    }
  }

  if (!ws.clientId || !ws.roomId) return;
  const room = rooms.get(ws.roomId);
  if (!room) return;

  const peer = room.get(ws.clientId);
  room.delete(ws.clientId);
  broadcast(ws.roomId, {
    type: "peer-left",
    peerId: ws.clientId,
    name: peer?.name || "익명"
  });

  if (room.size === 0) {
    rooms.delete(ws.roomId);
  }
}

const server = http.createServer(async (req, res) => {
  try {
    const rawPath = new URL(req.url || "/", `http://${req.headers.host}`).pathname;
    if (rawPath === "/healthz") {
      res.writeHead(200, { "Content-Type": "application/json; charset=utf-8" });
      res.end(JSON.stringify({ ok: true }));
      return;
    }

    const safePath = normalize(rawPath === "/" ? "/index.html" : rawPath).replace(/^(\.\.[/\\])+/, "");
    const filePath = join(root, safePath);
    const content = await readFile(filePath);
    res.writeHead(200, { "Content-Type": types[extname(filePath)] || "application/octet-stream" });
    res.end(content);
  } catch {
    res.writeHead(404, { "Content-Type": "text/plain; charset=utf-8" });
    res.end("Not found");
  }
});

const wss = new WebSocketServer({ server });

wss.on("connection", (ws) => {
  ws.on("message", (raw) => {
    let packet;
    try {
      packet = JSON.parse(raw.toString());
    } catch {
      send(ws, { type: "error", message: "JSON 형식이 아닙니다." });
      return;
    }

    if (packet.type === "join") {
      const roomId = String(packet.room || "demo").slice(0, 40);
      const name = String(packet.name || "익명").slice(0, 24);
      const publicKey = String(packet.publicKey || "");
      const id = randomUUID();

      if (!rooms.has(roomId)) rooms.set(roomId, new Map());
      ws.clientId = id;
      ws.roomId = roomId;
      rooms.get(roomId).set(id, { id, name, publicKey, ws });

      const peers = roomPeers(roomId)
        .filter((peer) => peer.id !== id)
        .map(({ id: peerId, name: peerName, publicKey: peerPublicKey }) => ({
          id: peerId,
          name: peerName,
          publicKey: peerPublicKey
        }));

      send(ws, { type: "joined", id, room: roomId, peers });
      broadcast(roomId, { type: "peer-joined", peer: { id, name, publicKey } }, id);
      return;
    }

    if (packet.type === "admin-watch") {
      const roomId = String(packet.room || "demo").slice(0, 40);
      ws.watchRoomId = roomId;
      if (!watchers.has(roomId)) watchers.set(roomId, new Set());
      watchers.get(roomId).add(ws);
      send(ws, {
        type: "admin-ready",
        room: roomId,
        peers: roomPeers(roomId).map(({ id, name }) => ({ id, name }))
      });
      return;
    }

    if (!ws.clientId || !ws.roomId) {
      send(ws, { type: "error", message: "먼저 방에 입장해야 합니다." });
      return;
    }

    if (packet.type === "encrypted-message") {
      const relay = {
        type: "encrypted-message",
        from: ws.clientId,
        to: packet.to,
        alg: packet.alg,
        keyId: packet.keyId,
        ciphertext: packet.ciphertext,
        iv: packet.iv,
        sentAt: Date.now()
      };

      const room = rooms.get(ws.roomId);
      const target = room?.get(packet.to);
      if (target) send(target.ws, relay);

      broadcastObserved(ws.roomId, {
        type: "server-observed",
        from: ws.clientId,
        to: packet.to,
        alg: packet.alg,
        keyId: packet.keyId,
        ciphertext: packet.ciphertext,
        iv: packet.iv,
        sentAt: relay.sentAt
      });
    }
  });

  ws.on("close", () => leave(ws));
  ws.on("error", () => leave(ws));
});

server.listen(port, () => {
  console.log(`E2E chat demo running at http://localhost:${port}`);
});
