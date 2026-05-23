const ui = {
  demoButton: document.querySelector("#demoButton"),
  resetButton: document.querySelector("#resetButton"),
  revokeAliceButton: document.querySelector("#revokeAliceButton"),
  revokeBobButton: document.querySelector("#revokeBobButton"),
  simulationButton: document.querySelector("#simulationButton"),
  messageForm: document.querySelector("#messageForm"),
  senderSelect: document.querySelector("#senderSelect"),
  messageInput: document.querySelector("#messageInput"),
  toast: document.querySelector("#toast"),
  sessionId: document.querySelector("#sessionId"),
  sessionKey: document.querySelector("#sessionKey"),
  deliveredCount: document.querySelector("#deliveredCount"),
  blockedCount: document.querySelector("#blockedCount"),
  aliceCard: document.querySelector("#aliceCard"),
  bobCard: document.querySelector("#bobCard"),
  caCard: document.querySelector("#caCard"),
  phaseList: document.querySelector("#phaseList"),
  messageList: document.querySelector("#messageList"),
  stageList: document.querySelector("#stageList"),
  packetInspector: document.querySelector("#packetInspector"),
  logsGrid: document.querySelector("#logsGrid"),
  tracePanel: document.querySelector("#tracePanel"),
};

let currentState = null;
let selectedMessageId = null;

const escapeHtml = (value) =>
  String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");

const compactHex = (value, size = 88) => {
  const text = String(value ?? "");
  return text.length <= size ? text : `${text.slice(0, size)}...`;
};

const formatMs = (value) => `${Number(value || 0).toFixed(2)} ms`;
const getPostQuantum = (state) => state?.key_exchange?.post_quantum || null;

async function requestJson(path, options = {}) {
  const response = await fetch(path, {
    headers: { "Content-Type": "application/json" },
    ...options,
  });
  const contentType = response.headers.get("content-type") || "";
  const payload = contentType.includes("application/json")
    ? await response.json()
    : { error: await response.text() };
  if (!response.ok) {
    throw new Error(payload.error || `Request failed with ${response.status}`);
  }
  return payload;
}

async function postJson(path, body = {}) {
  return requestJson(path, {
    method: "POST",
    body: JSON.stringify(body),
  });
}

function setBusy(isBusy) {
  [
    ui.demoButton,
    ui.resetButton,
    ui.revokeAliceButton,
    ui.revokeBobButton,
    ui.simulationButton,
    ui.messageForm.querySelector("button"),
  ].filter(Boolean).forEach((button) => {
    button.disabled = isBusy;
  });
}

function showToast(message, isError = false) {
  ui.toast.textContent = message;
  ui.toast.classList.toggle("error", isError);
  if (message) {
    window.clearTimeout(showToast.timer);
    showToast.timer = window.setTimeout(() => {
      ui.toast.textContent = "";
      ui.toast.classList.remove("error");
    }, 3600);
  }
}

async function perform(action, successMessage) {
  setBusy(true);
  try {
    const state = await action();
    renderState(state);
    showToast(successMessage);
  } catch (error) {
    showToast(error.message, true);
  } finally {
    setBusy(false);
  }
}

function renderState(state) {
  currentState = state;
  const lastMessage = state.messages[state.messages.length - 1];
  const selectedExists = state.messages.some((message) => message.id === selectedMessageId);
  if (!selectedExists) {
    selectedMessageId = lastMessage?.id ?? null;
  }

  renderMetrics(state);
  renderEntities(state);
  renderPhases(state);
  renderMessages(state);
  renderInspector(state);
  renderLogs(state);
  renderTrace(state);
}

function renderMetrics(state) {
  ui.sessionId.textContent = state.session.id;
  ui.sessionKey.textContent = compactHex(state.key_exchange.session_key_hex, 24);
  ui.deliveredCount.textContent = state.metrics.delivered_messages;
  ui.blockedCount.textContent = state.metrics.blocked_messages;
}

function renderEntities(state) {
  const postQuantum = getPostQuantum(state);
  ui.aliceCard.innerHTML = renderPeerCard("Alice", state.certificates.Alice);
  ui.bobCard.innerHTML = renderPeerCard("Bob", state.certificates.Bob);
  ui.caCard.innerHTML = `
    <div class="entity-top">
      <div>
        <p class="eyebrow">Trust anchor</p>
        <h2>TrustNet CA</h2>
      </div>
      <span class="pill ok">online</span>
    </div>
    <p>Issues certificates, validates sender identity, and maintains revocation state.</p>
    <div class="facts">
      ${renderFact("Algorithm", "Paillier PKI")}
      ${renderFact("Key exchange", `${state.key_exchange.ciphertext_count} ciphertexts`)}
      ${renderFact("Post-Q KEM", postQuantum ? `${postQuantum.ciphertext_bytes} bytes` : "restart server to load")}
      ${renderFact("Agreement", state.key_exchange.alice_key_matches_bob ? "session keys match" : "mismatch")}
    </div>
  `;
}

function renderPeerCard(name, cert) {
  const validClass = cert.valid ? "ok" : "warn";
  const status = cert.valid ? "valid" : cert.reason;
  return `
    <div class="entity-top">
      <div>
        <p class="eyebrow">Peer node</p>
        <h2>${escapeHtml(name)}</h2>
      </div>
      <span class="pill ${validClass}">${escapeHtml(status)}</span>
    </div>
    <p>Owns a Paillier key pair, receives a CA certificate, and uses the shared session key for RC4 and Blowfish.</p>
    <div class="facts">
      ${renderFact("Serial", cert.serial)}
      ${renderFact("Public n", cert.public_key_n)}
      ${renderFact("Signature", cert.signature)}
    </div>
  `;
}

function renderFact(label, value) {
  return `
    <div class="fact">
      <span>${escapeHtml(label)}</span>
      <strong>${escapeHtml(value)}</strong>
    </div>
  `;
}

function renderPhases(state) {
  const selected = getSelectedMessage(state);
  const setupCards = state.setup_phases.map((phase, index) => {
    const facts = Object.entries(phase.facts || {})
      .map(([key, value]) => `<code>${escapeHtml(key)}: ${escapeHtml(value)}</code>`)
      .join("");
    return `
      <article class="phase-card">
        <div class="phase-index">${index + 1}</div>
        <div>
          <h3>${escapeHtml(phase.title)}</h3>
          <p>${escapeHtml(phase.summary)} Completed in ${formatMs(phase.elapsed_ms)}.</p>
          <div class="phase-facts">${facts}</div>
        </div>
      </article>
    `;
  });

  const transferCards = selected
    ? selected.stages.map((stage, index) => `
        <article class="phase-card">
          <div class="phase-index">${state.setup_phases.length + index + 1}</div>
          <div>
            <h3>${escapeHtml(stage.label)}</h3>
            <p>${escapeHtml(stage.detail)}</p>
            <div class="phase-facts">
              <code>state: ${escapeHtml(stage.state)}</code>
              <code>message: #${selected.id}</code>
            </div>
          </div>
        </article>
      `)
    : [
        `<div class="empty-state">Send a message to append the RC4 transfer and Blowfish storage stages.</div>`,
      ];

  ui.phaseList.innerHTML = [...setupCards, ...transferCards].join("");
}

function renderMessages(state) {
  if (!state.messages.length) {
    ui.messageList.innerHTML = `<div class="empty-state">No messages yet. Send one to create a packet.</div>`;
    return;
  }

  ui.messageList.innerHTML = state.messages
    .slice()
    .reverse()
    .map((message) => {
      const active = message.id === selectedMessageId ? "active" : "";
      const pillClass = message.status === "delivered" ? "ok" : "warn";
      return `
        <button class="message-card ${active}" type="button" data-id="${message.id}">
          <div class="message-meta">
            <h3>#${message.id} ${escapeHtml(message.direction)}</h3>
            <span class="pill ${pillClass}">${escapeHtml(message.status)}</span>
          </div>
          <p>${escapeHtml(message.plaintext)}</p>
        </button>
      `;
    })
    .join("");

  ui.messageList.querySelectorAll(".message-card").forEach((button) => {
    button.addEventListener("click", () => {
      selectedMessageId = Number(button.dataset.id);
      renderState(currentState);
    });
  });
}

function renderInspector(state) {
  const selected = getSelectedMessage(state);
  const postQuantum = getPostQuantum(state);
  if (!selected) {
    ui.stageList.innerHTML = "";
    ui.packetInspector.innerHTML = `<div class="empty-state">Select or send a message to inspect the packet.</div>`;
    return;
  }

  ui.stageList.innerHTML = selected.stages
    .map((stage) => `
      <article class="stage-card ${escapeHtml(stage.state)}">
        <h3>${escapeHtml(stage.label)}</h3>
        <p>${escapeHtml(stage.detail)}</p>
      </article>
    `)
    .join("");

  const rows = [
    ["Direction", selected.direction],
    ["Plaintext", selected.plaintext],
    ["Decrypted", selected.decrypted || "not available"],
    ["Certificate", `${selected.certificate.reason} (serial ${selected.certificate.serial})`],
    ["Session key", compactHex(selected.session_key, 96)],
    ["Hybrid exchange", state.key_exchange.algorithm || "Paillier"],
    ["PQ secret", postQuantum ? `${postQuantum.shared_secret_preview}...` : "not present in current server state"],
    ["IV", selected.packet?.iv || "blocked before RC4"],
    ["RC4 ciphertext", compactHex(selected.packet?.ciphertext || "blocked before packet creation", 140)],
    ["Cipher bytes", selected.packet?.ciphertext_bytes ?? 0],
    ["Blowfish owner", selected.at_rest?.owner || "not stored"],
    ["Blowfish ciphertext", compactHex(selected.at_rest?.ciphertext || "not stored", 140)],
    [
      "Timing",
      `send ${formatMs(selected.timing.send_ms)} / receive ${formatMs(selected.timing.receive_ms)}`,
    ],
  ];

  ui.packetInspector.innerHTML = rows
    .map(([label, value]) => `
      <div class="inspector-row">
        <span>${escapeHtml(label)}</span>
        <code>${escapeHtml(value)}</code>
      </div>
    `)
    .join("");
}

function renderLogs(state) {
  ui.logsGrid.innerHTML = ["Alice", "Bob"]
    .map((name) => {
      const log = state.logs[name];
      const entries = log.count
        ? log.decrypted
            .map((plaintext, index) => `
              <div class="log-entry">
                <strong>${index + 1}. decrypted:</strong> ${escapeHtml(plaintext)}<br />
                <strong>encrypted:</strong> ${escapeHtml(compactHex(log.encrypted_preview[index], 116))}
              </div>
            `)
            .join("")
        : `<div class="empty-state">No stored messages for ${escapeHtml(name)}.</div>`;

      return `
        <article class="log-card">
          <h3>${escapeHtml(name)} log (${log.count})</h3>
          ${entries}
        </article>
      `;
    })
    .join("");
}

// function renderTrace(state) {
//   const trace = state.trace
//     .map((item) => {
//       const lines = item.lines.length
//         ? item.lines.map((line) => `  ${line}`).join("\n")
//         : "  no terminal output captured";
//       return `[${item.kind}] ${item.title} (${formatMs(item.elapsed_ms)})\n${lines}`;
//     })
//     .join("\n\n");
//   ui.tracePanel.textContent = trace || "No trace captured yet.";
// }
function renderTrace(state) {
  const selected = getSelectedMessage(state);

  if (!selected || !selected.trace || !selected.trace.length) {
    ui.tracePanel.textContent = "No trace captured for this message.";
    return;
  }

  const trace = selected.trace
    .map((item) => {
      const lines = item.lines?.length
        ? item.lines.map((line) => `  ${line}`).join("\n")
        : "  no terminal output captured";

      return `[${item.kind}] ${item.title} (${formatMs(item.elapsed_ms)})\n${lines}`;
    })
    .join("\n\n");

  ui.tracePanel.textContent = trace;
}

function getSelectedMessage(state) {
  return state.messages.find((message) => message.id === selectedMessageId) || null;
}

ui.demoButton.addEventListener("click", () => {
  selectedMessageId = null;
  perform(() => postJson("/api/demo"), "Sample flow replayed");
});

ui.resetButton.addEventListener("click", () => {
  selectedMessageId = null;
  perform(() => postJson("/api/reset"), "Lab reset");
});

ui.revokeAliceButton.addEventListener("click", () => {
  perform(() => postJson("/api/revoke", { peer: "Alice" }), "Alice certificate revoked");
});

ui.revokeBobButton.addEventListener("click", () => {
  perform(() => postJson("/api/revoke", { peer: "Bob" }), "Bob certificate revoked");
});

if (ui.simulationButton) {
  ui.simulationButton.addEventListener("click", async () => {
    setBusy(true);
    try {
      const result = await postJson("/api/simulation-demo");
      ui.tracePanel.textContent = result.output;
      showToast("Multi-party localhost simulation complete");
    } catch (error) {
      showToast(error.message, true);
    } finally {
      setBusy(false);
    }
  });
}

ui.messageForm.addEventListener("submit", (event) => {
  event.preventDefault();
  const sender = ui.senderSelect.value;
  const message = ui.messageInput.value.trim();
  perform(
    () => postJson("/api/send", { from: sender, message }),
    `${sender}'s message processed`
  ).then(() => {
    if (message) {
      ui.messageInput.value = "";
    }
  });
});

perform(() => requestJson("/api/state"), "Lab ready");
