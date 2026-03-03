const $ = (id) => document.getElementById(id);

const FALLBACK_ENGLISH_VERSES = [
  "Gather ye rosebuds while ye may,\n   Old Time is still a-flying;\nAnd this same flower that smiles today\n   Tomorrow will be dying.",
  "Shall I compare thee to a summer's day?\nThou art more lovely and more temperate.",
  "Hope is the thing with feathers\nThat perches in the soul,\nAnd sings the tune without the words,\nAnd never stops at all.",
];

const FALLBACK_CHINESE_VERSES = [
  "海上生明月，天涯共此时。",
  "但愿人长久，千里共婵娟。",
  "落霞与孤鹜齐飞，秋水共长天一色。",
];

function randomFallbackPlaintext() {
  const allVerses = [...FALLBACK_ENGLISH_VERSES, ...FALLBACK_CHINESE_VERSES];
  return allVerses[randomInt(0, allVerses.length - 1)];
}

function randomHex(byteLength) {
  const bytes = new Uint8Array(byteLength);
  if (window.crypto?.getRandomValues) {
    window.crypto.getRandomValues(bytes);
  } else {
    for (let i = 0; i < bytes.length; i += 1) {
      bytes[i] = randomInt(0, 255);
    }
  }
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

function normalizeDemoVerse(text, maxChars = 260) {
  const normalized = String(text || "").replace(/\r\n/g, "\n").trim();
  if (!normalized) {
    return "";
  }
  if (normalized.length <= maxChars) {
    return normalized;
  }
  return `${normalized.slice(0, maxChars).trimEnd()}...`;
}

async function fetchJsonWithTimeout(url, timeoutMs = 4500) {
  const controller = new AbortController();
  const timer = window.setTimeout(() => {
    controller.abort();
  }, timeoutMs);

  try {
    const response = await fetch(url, {
      signal: controller.signal,
      cache: "no-store",
    });
    if (!response.ok) {
      throw new Error(`HTTP ${response.status}`);
    }
    return await response.json();
  } finally {
    window.clearTimeout(timer);
  }
}

async function fetchEnglishVerseOnline() {
  const data = await fetchJsonWithTimeout("https://poetrydb.org/random", 5000);
  const poem = Array.isArray(data) ? data[0] : null;
  if (!poem || !Array.isArray(poem.lines) || poem.lines.length === 0) {
    throw new Error("Invalid English verse payload");
  }
  return normalizeDemoVerse(poem.lines.slice(0, 4).join("\n"));
}

async function fetchChineseVerseOnline() {
  const data = await fetchJsonWithTimeout("https://v1.jinrishici.com/all.json", 5000);
  const content = typeof data?.content === "string" ? data.content.trim() : "";
  const origin = typeof data?.origin === "string" ? data.origin.trim() : "";
  if (!content) {
    throw new Error("Invalid Chinese verse payload");
  }
  return normalizeDemoVerse(origin ? `${content}\n——《${origin}》` : content);
}

async function randomDemoPlaintextFromOnline() {
  const fetchers = [fetchEnglishVerseOnline, fetchChineseVerseOnline];
  if (Math.random() < 0.5) {
    fetchers.reverse();
  }

  for (const fetcher of fetchers) {
    try {
      const verse = await fetcher();
      if (verse) {
        return verse;
      }
    } catch (_) {
      // Try the other source, then fall back to local verse list.
    }
  }

  return randomFallbackPlaintext();
}

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

function clearAllDemoFields() {
  const ids = [
    "enc-plaintext",
    "enc-key",
    "enc-iv",
    "out-ciphertext",
    "out-tag",
    "dec-ciphertext",
    "dec-key",
    "dec-iv",
    "dec-tag",
    "out-plaintext",
  ];

  ids.forEach((id) => {
    const el = $(id);
    if (el) {
      el.value = "";
    }
  });
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
    clearAllDemoFields();
    lastEncryptedIvHex = "";

    setStatus("Demo: fetching a random verse online...");
    const demoPlaintext = await randomDemoPlaintextFromOnline();
    const demoKeyHex = randomHex(32);
    const demoIvHex = randomHex(16);

    setStatus("Demo: typing encryption inputs...");

    await typeLikeHuman($("enc-plaintext"), demoPlaintext, 22, 54);
    await typeLikeHuman($("enc-key"), demoKeyHex, 8, 26);
    await typeLikeHuman($("enc-iv"), demoIvHex, 8, 26);

    await submitEncryptText();
    await sleep(350);

    const producedCiphertext = $("out-ciphertext").value.trim();
    const producedIv = lastEncryptedIvHex || $("enc-iv").value.trim();
    const producedTag = $("out-tag").value.trim();

    setStatus("Demo: typing decryption ciphertext/key/iv/tag...");
    await typeLikeHuman($("dec-ciphertext"), producedCiphertext, 1, 8);
    await typeLikeHuman($("dec-key"), demoKeyHex, 8, 26);
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
