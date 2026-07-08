const $ = (selector) => document.querySelector(selector);
const $$ = (selector) => Array.from(document.querySelectorAll(selector));

const socketStatus = $("#socketStatus");
const myId = $("#myId");
const nameInput = $("#nameInput");
const roomInput = $("#roomInput");
const joinBtn = $("#joinBtn");
const tamperBtn = $("#tamperBtn");
const inviteBtn = $("#inviteBtn");
const adminBtn = $("#adminBtn");
const presentBtn = $("#presentBtn");
const peerList = $("#peerList");
const messages = $("#messages");
const messageForm = $("#messageForm");
const messageInput = $("#messageInput");
const sendBtn = $("#sendBtn");
const serverLog = $("#serverLog");
const serverTitle = $("#serverTitle");
const openSecondBtn = $("#openSecondBtn");
const detailDialog = $("#detailDialog");
const detailBody = $("#detailBody");
const closeDetailBtn = $("#closeDetailBtn");

const ALGORITHM = "SwiftSeal-v1";
const encoder = new TextEncoder();
const decoder = new TextDecoder();
const params = new URLSearchParams(location.search);
const isAdminMode = params.get("admin") === "1";

let socket;
let clientId;
let keyPair;
let exportedPublicKey;
let activeRoom = params.get("room") || "class-demo";
let messageSeq = 0;
const peers = new Map();
const messageDetails = new Map();
const seenMessages = new Set();

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

function socketUrl() {
  return `${location.protocol === "https:" ? "wss" : "ws"}://${location.host}`;
}

function publicUrl(extra = {}) {
  const url = new URL(location.href);
  url.search = "";
  url.searchParams.set("room", roomInput.value.trim() || activeRoom);
  Object.entries(extra).forEach(([key, value]) => url.searchParams.set(key, value));
  return url.toString();
}

function setFlow(stepName) {
  const order = ["public-key", "shared-key", "encrypt", "relay", "decrypt"];
  const activeIndex = order.indexOf(stepName);
  $$(".flow-step").forEach((step) => {
    const index = order.indexOf(step.dataset.step);
    step.classList.toggle("active", index === activeIndex);
    step.classList.toggle("done", activeIndex >= 0 && index < activeIndex);
  });
}

function setConnected(connected) {
  socketStatus.textContent = connected ? "소켓 연결됨" : "연결 끊김";
  socketStatus.className = `pill ${connected ? "on" : "off"}`;
}

function updateComposer() {
  const joined = !isAdminMode && socket?.readyState === WebSocket.OPEN && Boolean(clientId);
  messageInput.disabled = !joined;
  sendBtn.disabled = !joined || peers.size === 0;
  tamperBtn.disabled = !joined || peers.size === 0;
}

function clearEmpty(container) {
  const empty = container.querySelector(".empty");
  if (empty) empty.remove();
}

function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, (char) => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#039;"
  })[char]);
}

function addSystem(text) {
  clearEmpty(messages);
  const item = document.createElement("div");
  item.className = "system";
  item.textContent = text;
  messages.append(item);
  messages.scrollTop = messages.scrollHeight;
}

function createDetail(detail) {
  const id = `msg-${messageSeq += 1}`;
  messageDetails.set(id, detail);
  return id;
}

function addMessage(text, mine, name, detail = null) {
  clearEmpty(messages);
  const item = document.createElement("button");
  item.type = "button";
  item.className = `message ${mine ? "mine" : ""}`;
  const time = new Date(detail?.sentAt || Date.now()).toLocaleTimeString();
  item.innerHTML = `<small>${escapeHtml(name)} · ${time}</small>${escapeHtml(text)}`;
  if (detail) {
    const id = createDetail({ ...detail, plain: text, speaker: name, direction: mine ? "보낸 메시지" : "받은 메시지" });
    item.dataset.detailId = id;
    item.title = "암호화 상세 보기";
  }
  messages.append(item);
  messages.scrollTop = messages.scrollHeight;
}

function openDetail(id) {
  const detail = messageDetails.get(id);
  if (!detail) return;
  const packet = detail.packet || {};
  detailBody.innerHTML = `
    <dl class="detail-grid">
      <dt>구분</dt><dd>${escapeHtml(detail.direction)}</dd>
      <dt>평문</dt><dd class="plain">${escapeHtml(detail.plain)}</dd>
      <dt>받는 사람</dt><dd>${escapeHtml(detail.toName || packet.to || "-")}</dd>
      <dt>암호화 시간</dt><dd>${new Date(detail.sentAt || Date.now()).toLocaleString()}</dd>
      <dt>알고리즘</dt><dd>${escapeHtml(packet.alg || ALGORITHM)}</dd>
      <dt>keyId</dt><dd>${escapeHtml(packet.keyId || "-")}</dd>
      <dt>IV</dt><dd class="mono">${escapeHtml(packet.iv || "-")}</dd>
      <dt>ciphertext</dt><dd class="mono">${escapeHtml(packet.ciphertext || "-")}</dd>
    </dl>
    <div class="detail-actions">
      <button type="button" data-copy="${escapeHtml(detail.plain)}">평문 복사</button>
      <button type="button" data-copy="${escapeHtml(packet.ciphertext || "")}">암호문 복사</button>
    </div>
  `;
  detailDialog.showModal();
}

function addServerPacket(packet) {
  clearEmpty(serverLog);
  const item = document.createElement("div");
  item.className = "cipher";
  item.innerHTML = `
    <strong>${new Date(packet.sentAt).toLocaleTimeString()} 서버 중계 로그</strong>
    <pre>plain: [서버에서는 볼 수 없음]
alg: ${packet.alg || "unknown"}
keyId: ${packet.keyId || "none"}
from: ${packet.from}
to: ${packet.to}
iv: ${packet.iv}
ciphertext: ${packet.ciphertext}</pre>
  `;
  serverLog.prepend(item);
  setFlow("relay");
}

function renderPeers() {
  peerList.innerHTML = "";
  if (isAdminMode) {
    peerList.innerHTML = "<li>관리자 모드 - 평문 복호화 키 없음</li>";
    return;
  }
  if (peers.size === 0) {
    peerList.innerHTML = "<li>대기 중 · 상대 접속 전</li>";
    return;
  }

  for (const peer of peers.values()) {
    const li = document.createElement("li");
    li.innerHTML = `
      <strong>${escapeHtml(peer.name)}</strong>
      <span>온라인 · 키 교환 완료</span>
      <small>${ALGORITHM} / keyId ${escapeHtml(peer.keyId)}</small>
    `;
    peerList.append(li);
  }
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
  for (const [id, existing] of peers.entries()) {
    if (existing.publicKey === peer.publicKey) {
      peers.delete(id);
    }
  }

  setFlow("public-key");
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

  peers.set(peer.id, { ...peer, aesKey, keyId, online: true });
  renderPeers();
  updateComposer();
  setFlow("shared-key");
  addSystem(`${peer.name} 님 온라인 · ${ALGORITHM} 키 교환 완료`);
}

async function encryptPacket(peer, text, from = clientId, to = peer.id) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const packetMeta = { from, to, keyId: peer.keyId };
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

function connectSocket() {
  socket?.close();
  socket = new WebSocket(socketUrl());

  socket.addEventListener("message", handleSocketMessage);
  socket.addEventListener("close", () => {
    setConnected(false);
    updateComposer();
    joinBtn.disabled = false;
    joinBtn.textContent = isAdminMode ? "관리자 모드 다시 연결" : "다시 입장";
  });

  return new Promise((resolve) => socket.addEventListener("open", resolve, { once: true }));
}

async function joinRoom() {
  activeRoom = roomInput.value.trim() || "class-demo";
  joinBtn.disabled = true;
  joinBtn.textContent = isAdminMode ? "관리자 연결 중..." : "키 생성 중...";
  peers.clear();
  renderPeers();

  await connectSocket();

  if (isAdminMode) {
    socket.send(JSON.stringify({ type: "admin-watch", room: activeRoom }));
    return;
  }

  await createKeys();
  setFlow("public-key");
  const name = nameInput.value.trim() || `사용자${Math.floor(Math.random() * 900 + 100)}`;
  socket.send(JSON.stringify({
    type: "join",
    name,
    room: activeRoom,
    publicKey: exportedPublicKey
  }));
}

async function handleSocketMessage(event) {
  const packet = JSON.parse(event.data);

  if (packet.type === "admin-ready") {
    myId.textContent = `관리자 모드 / ${packet.room}`;
    serverTitle.textContent = "서버 관리자 모드";
    setConnected(true);
    joinBtn.disabled = false;
    joinBtn.textContent = "관리자 감시 중";
    addSystem("관리자 모드입니다. 이 화면은 평문 복호화 키를 갖지 않습니다.");
    renderPeers();
  }

  if (packet.type === "joined") {
    clientId = packet.id;
    myId.textContent = `${nameInput.value.trim() || "익명"} / ${packet.room}`;
    setConnected(true);
    joinBtn.disabled = false;
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
    const peer = peers.get(packet.peerId);
    peers.delete(packet.peerId);
    renderPeers();
    updateComposer();
    addSystem(`${peer?.name || packet.name} 님 오프라인 · 연결 종료`);
  }

  if (packet.type === "encrypted-message") {
    const messageKey = `${packet.from}:${packet.to}:${packet.sentAt}:${packet.ciphertext}`;
    if (seenMessages.has(messageKey)) return;
    seenMessages.add(messageKey);

    try {
      const text = await decryptFromPeer(packet);
      const peerName = peers.get(packet.from)?.name || "상대";
      setFlow("decrypt");
      addMessage(text, false, peerName, {
        packet,
        sentAt: packet.sentAt,
        toName: "나"
      });
    } catch {
      addSystem("복호화 실패 · 키가 다르거나 암호문이 변조되었습니다.");
    }
  }

  if (packet.type === "server-observed") {
    addServerPacket(packet);
  }

  if (packet.type === "error") {
    addSystem(packet.message);
  }
}

messageForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const text = messageInput.value.trim();
  if (!text) return;
  if (peers.size === 0) {
    addSystem("상대가 아직 없습니다. 새 창이나 초대 링크로 같은 방에 한 명 더 입장하세요.");
    return;
  }

  const sentAt = Date.now();
  const detailPackets = [];
  const recipients = [];
  for (const peer of peers.values()) {
    const encrypted = await encryptPacket(peer, text);
    const packet = {
      type: "encrypted-message",
      to: peer.id,
      ...encrypted
    };
    detailPackets.push({ ...packet, from: clientId, sentAt, toName: peer.name });
    recipients.push(peer.name);
    setFlow("encrypt");
    socket.send(JSON.stringify(packet));
  }

  addMessage(text, true, "나", {
    packet: detailPackets[0],
    sentAt,
    toName: recipients.join(", ")
  });
  messageInput.value = "";
});

messages.addEventListener("click", (event) => {
  const message = event.target.closest(".message");
  if (message?.dataset.detailId) {
    openDetail(message.dataset.detailId);
  }
});

detailBody.addEventListener("click", async (event) => {
  const button = event.target.closest("[data-copy]");
  if (!button) return;
  await navigator.clipboard.writeText(button.dataset.copy);
  button.textContent = "복사 완료";
});

closeDetailBtn.addEventListener("click", () => detailDialog.close());
joinBtn.addEventListener("click", joinRoom);

inviteBtn.addEventListener("click", async () => {
  const url = publicUrl();
  await navigator.clipboard.writeText(url);
  inviteBtn.textContent = "링크 복사됨";
  setTimeout(() => { inviteBtn.textContent = "초대 링크"; }, 1400);
});

adminBtn.addEventListener("click", () => {
  window.open(publicUrl({ admin: "1" }), "_blank", "width=1180,height=860");
});

presentBtn.addEventListener("click", () => {
  document.body.classList.toggle("presentation");
  presentBtn.textContent = document.body.classList.contains("presentation") ? "일반 모드" : "발표 모드";
});

tamperBtn.addEventListener("click", async () => {
  const peer = peers.values().next().value;
  if (!peer) return;
  const fakePacket = await encryptPacket(peer, "위조된 메시지", peer.id, clientId);
  fakePacket.from = peer.id;
  fakePacket.to = clientId;
  fakePacket.ciphertext = `${fakePacket.ciphertext.slice(0, -1)}A`;
  try {
    await decryptFromPeer(fakePacket);
    addSystem("위조 데모 실패: 변조 메시지가 통과했습니다.");
  } catch {
    addSystem("위조 메시지 데모 성공 · AES-GCM 인증 태그 검증으로 복호화 실패");
  }
});

openSecondBtn.addEventListener("click", () => {
  window.open(publicUrl(), "_blank", "width=1100,height=850");
});

roomInput.value = activeRoom;
nameInput.value = isAdminMode ? "서버 관리자" : `사용자${Math.floor(Math.random() * 900 + 100)}`;
document.body.classList.toggle("admin-mode", isAdminMode);
if (params.get("present") === "1") document.body.classList.add("presentation");
if (isAdminMode) {
  messageInput.disabled = true;
  sendBtn.disabled = true;
  tamperBtn.disabled = true;
  joinBtn.textContent = "관리자 모드 시작";
  serverTitle.textContent = "서버 관리자 모드";
}
renderPeers();
setFlow("public-key");
