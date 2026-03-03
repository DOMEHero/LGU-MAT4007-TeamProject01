const $ = (id) => document.getElementById(id);

const DEMO_VALUES = {
  plaintext:
    "Gather ye rosebuds while ye may,\n   Old Time is still a-flying;\nAnd this same flower that smiles today\n   Tomorrow will be dying.",
  keyHex: "4d45749a26c79ea5a52a2dade16903beaf99f652481907b7305f3315101488e0",
  ivHex: "b203e94afcc0acff4472b99f14664a50",
};

let demoRunning = false;
let lastEncryptedIvHex = "";
let statusTimer = null;
let secretsVisible = false;

function setStatus(message, isError = false) {
  const el = $("status");
  el.textContent = message;
  el.className = isError ? "status error visible" : "status ok visible";

  if (statusTimer) {
    window.clearTimeout(statusTimer);
  }

  statusTimer = window.setTimeout(
    () => {
      el.classList.remove("visible");
    },
    isError ? 6000 : 3200,
  );
}

function parseErrorPayload(data) {
  if (!data) {
    return "Request failed";
  }
  if (typeof data === "string") {
    return data;
  }
  return data.detail || JSON.stringify(data);
}

async function parseErrorResponse(response) {
  const contentType = response.headers.get("content-type") || "";
  if (contentType.includes("application/json")) {
    const data = await response.json();
    return parseErrorPayload(data);
  }
  const text = await response.text();
  return text || "Request failed";
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function randomInt(min, max) {
  return Math.floor(Math.random() * (max - min + 1)) + min;
}

async function typeLikeHuman(element, text, minDelay = 16, maxDelay = 52) {
  element.focus();
  element.value = "";
  element.dispatchEvent(new Event("input", { bubbles: true }));
  await sleep(randomInt(120, 200));

  for (const char of text) {
    element.value += char;
    element.dispatchEvent(new Event("input", { bubbles: true }));

    let pause = randomInt(minDelay, maxDelay);
    if (".,!?;:".includes(char)) {
      pause += randomInt(70, 170);
    }
    await sleep(pause);
  }

  element.dispatchEvent(new Event("change", { bubbles: true }));
  await sleep(randomInt(140, 260));
}

async function submitEncryptText() {
  setStatus("Encrypting text...");
  $("out-ciphertext").value = "";
  $("out-tag").value = "";

  const enteredIv = $("enc-iv").value.trim();
  const payload = {
    plaintext: $("enc-plaintext").value,
    key_hex: $("enc-key").value.trim(),
    iv_hex: enteredIv || null,
    errors: "strict",
  };

  const res = await fetch("/api/encrypt", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });

  if (!res.ok) {
    throw new Error(await parseErrorResponse(res));
  }

  const data = await res.json();
  lastEncryptedIvHex = data.iv_hex;
  if (!enteredIv) {
    $("enc-iv").value = data.iv_hex;
  }
  $("out-ciphertext").value = data.ciphertext_hex;
  $("out-tag").value = data.tag_hex;
  setStatus("Text encryption complete.");
}

async function submitDecryptText() {
  setStatus("Decrypting text...");

  const payload = {
    ciphertext_hex: $("dec-ciphertext").value.trim(),
    key_hex: $("dec-key").value.trim(),
    iv_hex: $("dec-iv").value.trim(),
    tag_hex: $("dec-tag").value.trim(),
    errors: "strict",
  };

  const res = await fetch("/api/decrypt", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });

  if (!res.ok) {
    throw new Error(await parseErrorResponse(res));
  }

  const data = await res.json();
  $("out-plaintext").value = data.plaintext;
  setStatus("Text decryption complete.");
}

async function runTypingDemo() {
  if (demoRunning) {
    return;
  }

  const button = $("run-demo-btn");
  demoRunning = true;
  if (button) {
    button.disabled = true;
  }

  try {
    setStatus("Demo: typing encryption inputs...");

    lastEncryptedIvHex = "";
    $("out-ciphertext").value = "";
    $("out-tag").value = "";
    $("out-plaintext").value = "";

    await typeLikeHuman($("enc-plaintext"), DEMO_VALUES.plaintext, 22, 54);
    await typeLikeHuman($("enc-key"), DEMO_VALUES.keyHex, 8, 26);
    await typeLikeHuman($("enc-iv"), DEMO_VALUES.ivHex, 8, 26);

    await submitEncryptText();
    await sleep(350);

    const producedCiphertext = $("out-ciphertext").value.trim();
    const producedIv = lastEncryptedIvHex || $("enc-iv").value.trim();
    const producedTag = $("out-tag").value.trim();

    setStatus("Demo: typing decryption ciphertext/key/iv/tag...");
    await typeLikeHuman($("dec-ciphertext"), producedCiphertext, 1, 8);
    await typeLikeHuman($("dec-key"), DEMO_VALUES.keyHex, 8, 26);
    await typeLikeHuman($("dec-iv"), producedIv, 8, 26);
    await typeLikeHuman($("dec-tag"), producedTag, 8, 26);

    await submitDecryptText();
    setStatus("Demo complete: text typed, encrypted, and decrypted.");
  } catch (err) {
    setStatus(err.message || "Demo failed", true);
  } finally {
    demoRunning = false;
    if (button) {
      button.disabled = false;
    }
  }
}

function bindSecretToggles() {
  const toggleButtons = document.querySelectorAll(".toggle-secret");
  const secretInputs = document.querySelectorAll(".secret-field input");

  const setSecretsVisible = (visible) => {
    secretInputs.forEach((input) => {
      input.type = visible ? "text" : "password";
    });

    toggleButtons.forEach((button) => {
      button.textContent = visible ? "Hide" : "Show";
      button.setAttribute("aria-pressed", visible ? "true" : "false");
    });

    secretsVisible = visible;
  };

  setSecretsVisible(false);

  toggleButtons.forEach((button) => {
    button.addEventListener("click", () => {
      setSecretsVisible(!secretsVisible);
    });
  });
}

$("encrypt-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  try {
    await submitEncryptText();
  } catch (err) {
    setStatus(err.message, true);
  }
});

$("decrypt-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  try {
    await submitDecryptText();
  } catch (err) {
    setStatus(err.message, true);
  }
});

const demoButton = $("run-demo-btn");
if (demoButton) {
  demoButton.addEventListener("click", () => {
    void runTypingDemo();
  });
}

bindSecretToggles();
