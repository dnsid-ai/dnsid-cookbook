const form = document.getElementById("generateForm");
const promptInput = document.getElementById("prompt");
const styleInput = document.getElementById("style");
const sizeInput = document.getElementById("size");
const button = document.getElementById("generateButton");
const statusEl = document.getElementById("status");
const imageEl = document.getElementById("outputImage");
const emptyState = document.getElementById("emptyState");
const metadataEl = document.getElementById("metadata");
const warningEl = document.getElementById("warning");
const modeBadge = document.getElementById("modeBadge");
const localUiWarning = "Local-test fallback: this browser path calls local Bedrock directly; use Gateway mode for DNSid + AgentCore proof.";
let currentWarning = localUiWarning;
let currentAuthMode = modeBadge.textContent;

const metadataLabels = [
  ["model_id", "Model"],
  ["model_region", "Region"],
  ["artifact_id", "Artifact"],
  ["remote_artifact_id", "Gateway artifact"],
  ["artifact_url", "Artifact URL"],
  ["mime_type", "MIME"],
  ["width", "Width"],
  ["height", "Height"],
  ["request_id", "Bedrock request"],
  ["correlation_id", "Correlation"],
  ["audit_id", "Audit"],
  ["dnsid_sub", "DNSid subject"],
  ["dnsid_issuer", "DNSid issuer"],
  ["gateway_request_id", "Gateway request"],
  ["auth_mode", "Auth mode"],
];

function setStatus(message, isError = false) {
  statusEl.textContent = message;
  statusEl.classList.toggle("error", isError);
}

function clearImage() {
  imageEl.hidden = true;
  imageEl.style.display = "none";
  imageEl.removeAttribute("src");
  emptyState.hidden = false;
}

function setMode(data) {
  if (data?.auth_mode) {
    currentAuthMode = data.auth_mode;
    modeBadge.textContent = currentAuthMode;
  }
  currentWarning = data?.warning || currentWarning || localUiWarning;
  warningEl.textContent = currentWarning;
}

function renderMetadata(data) {
  metadataEl.replaceChildren();
  for (const [key, label] of metadataLabels) {
    const term = document.createElement("dt");
    term.textContent = label;
    const detail = document.createElement("dd");
    detail.textContent = data[key] ?? "";
    metadataEl.append(term, detail);
  }
}

function renderSuccess(data) {
  imageEl.hidden = false;
  imageEl.style.display = "";
  imageEl.src = data.artifact_url;
  emptyState.hidden = true;
  setMode(data);
  renderMetadata(data);
  setStatus("Image generated");
}

function renderError(data) {
  clearImage();
  metadataEl.replaceChildren();
  const message = data?.error?.message || "Generation failed.";
  setMode(data);
  setStatus(message, true);
}

async function loadHealth() {
  try {
    const response = await fetch("/api/health", { headers: { "Accept": "application/json" } });
    const data = await response.json();
    if (response.ok && data.ok) {
      setMode(data);
    }
  } catch (error) {
    setMode({ warning: localUiWarning });
  }
}

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  if (!promptInput.value.trim()) {
    renderError({
      error: { message: "Prompt is required." },
      auth_mode: currentAuthMode,
      warning: currentWarning,
    });
    return;
  }
  button.disabled = true;
  setStatus("Generating");
  try {
    const response = await fetch("/api/generate", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        prompt: promptInput.value,
        style: styleInput.value,
        size: sizeInput.value,
      }),
    });
    const data = await response.json();
    if (!response.ok || !data.ok) {
      renderError(data);
      return;
    }
    renderSuccess(data);
  } catch (error) {
    renderError({
      error: { message: error instanceof Error ? error.message : "Request failed." },
    });
  } finally {
    button.disabled = false;
  }
});

loadHealth();
