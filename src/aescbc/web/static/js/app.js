const $ = (id) => document.getElementById(id);

function setStatus(message, isError = false) {
  const el = $("status");
  el.textContent = message;
  el.className = isError ? "status error" : "status ok";
}

function copyEncryptOutputsToDecryptForm() {
  $("dec-ciphertext").value = $("out-ciphertext").value;
  $("dec-iv").value = $("out-iv").value;
  $("dec-tag").value = $("out-tag").value;
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

function getFilenameFromDisposition(contentDisposition, fallback) {
  if (!contentDisposition) {
    return fallback;
  }

  const match = contentDisposition.match(/filename="?([^";]+)"?/i);
  if (!match) {
    return fallback;
  }

  return match[1] || fallback;
}

function downloadBlob(blob, filename) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

function readMetadataHeader(response) {
  const metadataRaw = response.headers.get("X-AESCBC-Metadata");
  if (!metadataRaw) {
    return null;
  }

  try {
    return JSON.parse(metadataRaw);
  } catch {
    return null;
  }
}

$("encrypt-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  setStatus("Encrypting text...");

  const payload = {
    plaintext: $("enc-plaintext").value,
    key_hex: $("enc-key").value.trim(),
    iv_hex: $("enc-iv").value.trim() || null,
    errors: "strict",
  };

  try {
    const res = await fetch("/api/encrypt", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });

    if (!res.ok) {
      throw new Error(await parseErrorResponse(res));
    }

    const data = await res.json();
    $("out-iv").value = data.iv_hex;
    $("out-ciphertext").value = data.ciphertext_hex;
    $("out-tag").value = data.tag_hex;
    copyEncryptOutputsToDecryptForm();
    setStatus("Text encryption complete.");
  } catch (err) {
    setStatus(err.message, true);
  }
});

$("decrypt-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  setStatus("Decrypting text...");

  const payload = {
    ciphertext_hex: $("dec-ciphertext").value.trim(),
    key_hex: $("dec-key").value.trim(),
    iv_hex: $("dec-iv").value.trim(),
    tag_hex: $("dec-tag").value.trim(),
    errors: "strict",
  };

  try {
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
  } catch (err) {
    setStatus(err.message, true);
  }
});

$("file-encrypt-form").addEventListener("submit", async (event) => {
  event.preventDefault();

  const fileInput = $("file-enc-input");
  if (!fileInput.files || fileInput.files.length === 0) {
    setStatus("Please choose a file to encrypt.", true);
    return;
  }

  setStatus("Encrypting file...");

  const form = new FormData();
  form.append("file", fileInput.files[0]);
  form.append("key_hex", $("file-enc-key").value.trim());

  const ivHex = $("file-enc-iv").value.trim();
  if (ivHex) {
    form.append("iv_hex", ivHex);
  }

  try {
    const res = await fetch("/api/file/encrypt", {
      method: "POST",
      body: form,
    });

    if (!res.ok) {
      throw new Error(await parseErrorResponse(res));
    }

    const blob = await res.blob();
    const filename = getFilenameFromDisposition(
      res.headers.get("content-disposition"),
      `${fileInput.files[0].name}.enc`,
    );
    downloadBlob(blob, filename);

    const metadata = readMetadataHeader(res);
    $("file-enc-meta").value = metadata
      ? JSON.stringify(metadata, null, 2)
      : "No metadata provided";

    setStatus("File encrypted and downloaded.");
  } catch (err) {
    setStatus(err.message, true);
  }
});

$("file-decrypt-form").addEventListener("submit", async (event) => {
  event.preventDefault();

  const fileInput = $("file-dec-input");
  if (!fileInput.files || fileInput.files.length === 0) {
    setStatus("Please choose an encrypted file to decrypt.", true);
    return;
  }

  setStatus("Decrypting file...");

  const form = new FormData();
  form.append("file", fileInput.files[0]);
  form.append("key_hex", $("file-dec-key").value.trim());

  try {
    const res = await fetch("/api/file/decrypt", {
      method: "POST",
      body: form,
    });

    if (!res.ok) {
      throw new Error(await parseErrorResponse(res));
    }

    const blob = await res.blob();
    const fallback = fileInput.files[0].name.endsWith(".enc")
      ? fileInput.files[0].name.slice(0, -4)
      : `${fileInput.files[0].name}.decrypted`;

    const filename = getFilenameFromDisposition(
      res.headers.get("content-disposition"),
      fallback,
    );
    downloadBlob(blob, filename);

    const metadata = readMetadataHeader(res);
    $("file-dec-meta").value = metadata
      ? JSON.stringify(metadata, null, 2)
      : "No metadata provided";

    setStatus("File decrypted and downloaded.");
  } catch (err) {
    setStatus(err.message, true);
  }
});
