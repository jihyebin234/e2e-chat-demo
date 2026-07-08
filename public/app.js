const $ = (selector) => document.querySelector(selector);

const socketStatus = $("#socketStatus");
const myId = $("#myId");
const nameInput = $("#nameInput");
const roomInput = $("#roomInput");
const joinBtn = $("#joinBtn");
const peerList = $("#peerList");
const messages = $("#messages");
const messageForm = $("#messageForm");
const messageInput = $("#messageInput");
const sendBtn = $("#sendBtn");
const serverLog = $("#serverLog");
const openSecondBtn = $("#openSecondBtn");

const ALGORITHM = "SwiftSeal-v1";
const encoder = new TextEncoder();
const decoder = new TextDecoder();

let socket;
let clientId;
let keyPair;
let exportedPublicKey;
const peers = new Map();

function toBase64(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = "";
  bytes.forEach((byte) => {
    binary += String.fromCharCode(byte);
  });
  return btoa(binary);
}

function fromBase64(value) {
  const binary = atob(value);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
}

async function createKeys() {
  keyPair = await crypto.subtle.generateKey(
    { name: "ECDH", namedCurve: "P-256" },
    true,
    ["deriveBits"]
  );
  const rawPublicKey = await crypto.subtle.exportKey("raw", keyPair.publicKey);
  exportedPublicKey = toBase64(rawPublicKey);
}

async function sha256Base64(text) {
  const digest = await crypto.subtle.digest("SHA-256", encoder.encode(text));
  return toBase64(digest);
}

function peerContext(peerPublicKey) {
  return [exportedPublicKey, peerPublicKey].sort().join(".");
}

function aadFor(packet) {
  return encoder.encode(`${ALGORITHM}|${packet.from}|${packet.to}|${packet.keyId}`);
}

async function importPeer(peer) {
  if (peers.has(peer.id)) return;

  const publicKey = await crypto.subtle.importKey(
    "raw",
    fromBase64(peer.publicKey),
    { name: "ECDH", namedCurve: "P-256" },
    false,
    []
  );

  const sharedBits = await crypto.subtle.deriveBits(
    { name: "ECDH", public: publicKey },
    keyPair.privateKey,
    256
  );
  const context = peerContext(peer.publicKey);
  const keyId = (await sha256Base64(`${ALGORITHM}:key-id:${context}`)).slice(0, 16);
  const hkdfKey = await crypto.subtle.importKey("raw", sharedBits, "HKDF", false, ["deriveKey"]);
  const salt = await crypto.subtle.digest("SHA-256", encoder.encode(`${ALGORITHM}:salt:${context}`));
  const aesKey = await crypto.subtle.deriveKey(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt,
      info: encoder.encode(`${ALGORITHM}:aes-gcm:${context}`)
    },
    hkdfKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );

  peers.set(peer.id, { ...peer, aesKey, keyId });
  renderPeers();
  updateComposer();
  addSystem(`${peer.name} 님과 ${ALGORITHM} 공유키를 만들었습니다. keyId=${keyId}`);
}

async function encryptForPeer(peer, text) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const packetMeta = {
    from: clientId,
    to: peer.id,
    keyId: peer.keyId
  };
  const encrypted = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv, additionalData: aadFor(packetMeta) },
    peer.aesKey,
    encoder.encode(text)
  );

  return {
    alg: ALGORITHM,
    keyId: peer.keyId,
    ciphertext: toBase64(encrypted),
    iv: toBase64(iv)
  };
}

async function decryptFromPeer(packet) {
  const peer = peers.get(packet.from);
  if (!peer) throw new Error("키가 없는 상대입니다.");
  if (packet.alg !== ALGORITHM || packet.keyId !== peer.keyId) {
    throw new Error("지원하지 않는 암호 프로토콜입니다.");
  }

  const decrypted = await crypto.subtle.decrypt(
    {
      name: "AES-GCM",
      iv: new Uint8Array(fromBase64(packet.iv)),
      additionalData: aadFor(packet)
    },
    peer.aesKey,
    fromBase64(packet.ciphertext)
  );

  return decoder.decode(decrypted);
}

function setConnected(connected) {
  socketStatus.textContent = connected ? "소켓 연결됨" : "연결 끊김";
  socketStatus.className = `pill ${connected ? "on" : "off"}`;
}

function updateComposer() {
  const ready = socket?.readyState === WebSocket.OPEN && peers.size > 0;
  messageInput.disabled = !ready;
  sendBtn.disabled = !ready;
}

function clearEmpty(container) {
  const empty = container.querySelector(".empty");
  if (empty) empty.remove();
}

function addSystem(text) {
  clearEmpty(messages);
  const item = document.createElement("div");
  item.className = "system";
  item.textContent = text;
  messages.append(item);
  messages.scrollTop = messages.scrollHeight;
}

function addMessage(text, mine, name) {
  clearEmpty(messages);
  const item = document.createElement("div");
  item.className = `message ${mine ? "mine" : ""}`;
  item.innerHTML = `<small>${name}</small>${escapeHtml(text)}`;
  messages.append(item);
  messages.scrollTop = messages.scrollHeight;
}

function addServerPacket(packet) {
  clearEmpty(serverLog);
  const item = document.createElement("div");
  item.className = "cipher";
  item.innerHTML = `
    <strong>${new Date(packet.sentAt).toLocaleTimeString()} 암호문 중계</strong>
    <pre>alg: ${packet.alg || "unknown"}
keyId: ${packet.keyId || "none"}
from: ${packet.from}
to: ${packet.to}
iv: ${packet.iv}
ciphertext: ${packet.ciphertext}</pre>
  `;
  serverLog.prepend(item);
}

function renderPeers() {
  peerList.innerHTML = "";
  if (peers.size === 0) {
    peerList.innerHTML = "<li>같은 방에 들어온 상대를 기다리는 중입니다.</li>";
    return;
  }

  for (const peer of peers.values()) {
    const li = document.createElement("li");
    li.textContent = `${peer.name} - ${ALGORITHM} / keyId ${peer.keyId}`;
    peerList.append(li);
  }
}

function escapeHtml(value) {
  return value.replace(/[&<>"']/g, (char) => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#039;"
  })[char]);
}

async function joinRoom() {
  joinBtn.disabled = true;
  joinBtn.textContent = "키 생성 중...";
  peers.clear();
  renderPeers();

  await createKeys();

  socket = new WebSocket(`${location.protocol === "https:" ? "wss" : "ws"}://${location.host}`);

  socket.addEventListener("open", () => {
    const name = nameInput.value.trim() || `사용자${Math.floor(Math.random() * 900 + 100)}`;
    const room = roomInput.value.trim() || "class-demo";

    socket.send(JSON.stringify({
      type: "join",
      name,
      room,
      publicKey: exportedPublicKey
    }));
  });

  socket.addEventListener("message", async (event) => {
    const packet = JSON.parse(event.data);

    if (packet.type === "joined") {
      clientId = packet.id;
      myId.textContent = `${nameInput.value.trim() || "익명"} / ${packet.room}`;
      setConnected(true);
      joinBtn.textContent = "입장 완료";
      addSystem("채팅방에 입장했습니다. 같은 방에 다른 브라우저를 연결해보세요.");
      for (const peer of packet.peers) {
        await importPeer(peer);
      }
      updateComposer();
    }

    if (packet.type === "peer-joined") {
      await importPeer(packet.peer);
    }

    if (packet.type === "peer-left") {
      peers.delete(packet.peerId);
      renderPeers();
      updateComposer();
      addSystem(`${packet.name} 님이 나갔습니다.`);
    }

    if (packet.type === "encrypted-message") {
      try {
        const text = await decryptFromPeer(packet);
        const peerName = peers.get(packet.from)?.name || "상대";
        addMessage(text, false, peerName);
      } catch {
        addSystem("메시지 복호화에 실패했습니다. 키 교환 상태를 확인하세요.");
      }
    }

    if (packet.type === "server-observed") {
      addServerPacket(packet);
    }

    if (packet.type === "error") {
      addSystem(packet.message);
    }
  });

  socket.addEventListener("close", () => {
    setConnected(false);
    updateComposer();
    joinBtn.disabled = false;
    joinBtn.textContent = "다시 입장";
  });
}

messageForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const text = messageInput.value.trim();
  if (!text || peers.size === 0) return;

  for (const peer of peers.values()) {
    const encrypted = await encryptForPeer(peer, text);
    socket.send(JSON.stringify({
      type: "encrypted-message",
      to: peer.id,
      ...encrypted
    }));
  }

  addMessage(text, true, "나");
  messageInput.value = "";
});

joinBtn.addEventListener("click", joinRoom);

openSecondBtn.addEventListener("click", () => {
  window.open(location.href, "_blank", "width=1100,height=850");
});

nameInput.value = `사용자${Math.floor(Math.random() * 900 + 100)}`;
renderPeers();
