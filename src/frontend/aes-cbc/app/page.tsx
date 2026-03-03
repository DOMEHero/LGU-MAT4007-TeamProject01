"use client";

import { useState } from "react";

const API_BASE = "http://localhost:8000/api";


//api helper functions
async function aesCbcEncrypt(
  plaintext: string,
  keyHex: string,
  ivHex: string
): Promise<{ ciphertext_hex: string; iv_hex: string; tag_hex: string }> {
  const res = await fetch(`${API_BASE}/encrypt`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ plaintext, key_hex: keyHex, iv_hex: ivHex || undefined }),
  });
  if (!res.ok) {
    const err = await res.json();
    throw new Error(err.detail || "Encryption failed");
  }
  return res.json();
}

async function aesCbcDecrypt(
  ciphertextHex: string,
  keyHex: string,
  ivHex: string,
  tagHex: string
): Promise<string> {
  const res = await fetch(`${API_BASE}/decrypt`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      ciphertext_hex: ciphertextHex,
      key_hex: keyHex,
      iv_hex: ivHex,
      tag_hex: tagHex,
    }),
  });
  if (!res.ok) {
    const err = await res.json();
    throw new Error(err.detail || "Decryption failed");
  }
  const data = await res.json();
  return data.plaintext;
}

//components
export default function Home() {
  // Encrypt panel
  const [encPlaintext, setEncPlaintext] = useState("");
  const [encKey, setEncKey] = useState("");
  const [encIV, setEncIV] = useState("");
  const [encResult, setEncResult] = useState<{
    ciphertext_hex: string;
    iv_hex: string;
    tag_hex: string;
  } | null>(null);
  const [encError, setEncError] = useState("");
  const [encLoading, setEncLoading] = useState(false);

  // Decrypt panel
  const [decCiphertext, setDecCiphertext] = useState("");
  const [decKey, setDecKey] = useState("");
  const [decIV, setDecIV] = useState("");
  const [decTag, setDecTag] = useState("");
  const [decOutput, setDecOutput] = useState("");
  const [decError, setDecError] = useState("");
  const [decLoading, setDecLoading] = useState(false);

  // Carried-over flag so we can show a visual indicator
  const [carried, setCarried] = useState(false);

  const handleEncrypt = async () => {
    setEncError("");
    setEncResult(null);
    setCarried(false);
    setEncLoading(true);
    try {
      const result = await aesCbcEncrypt(encPlaintext, encKey, encIV);
      setEncResult(result);
    } catch (e: any) {
      setEncError(e.message);
    } finally {
      setEncLoading(false);
    }
  };

  const handleSendToDecrypt = () => {
    if (!encResult) return;
    setDecCiphertext(encResult.ciphertext_hex);
    setDecIV(encResult.iv_hex);
    setDecTag(encResult.tag_hex);
    setDecKey(encKey);
    setDecOutput("");
    setDecError("");
    setCarried(true);
  };

  const handleDecrypt = async () => {
    setDecError("");
    setDecOutput("");
    setDecLoading(true);
    try {
      const result = await aesCbcDecrypt(decCiphertext, decKey, decIV, decTag);
      setDecOutput(result);
    } catch (e: any) {
      setDecError(e.message);
    } finally {
      setDecLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-zinc-50 dark:bg-black px-8 py-16">
      <div className="max-w-6xl mx-auto mb-12 text-center">
        <h1 className="text-4xl font-bold tracking-tight text-black dark:text-zinc-50">
          AES-CBC Encryption &amp; Decryption Demo
        </h1>
        <p className="mt-3 text-zinc-500 dark:text-zinc-400 text-sm">
          CBC mode with HMAC-SHA256 authentication
        </p>
      </div>

      <div className="max-w-6xl mx-auto grid grid-cols-1 md:grid-cols-2 gap-10">

        {/*ENCRYPT PANEL*/}
        <div className="bg-white dark:bg-zinc-900 p-8 rounded-2xl shadow-md flex flex-col gap-4">
          <h2 className="text-2xl font-semibold text-black dark:text-zinc-50">Encrypt</h2>

          <textarea
            value={encPlaintext}
            onChange={(e) => setEncPlaintext(e.target.value)}
            placeholder="Enter plaintext..."
            rows={4}
            className="w-full p-4 rounded-lg border bg-zinc-50 dark:bg-zinc-800 dark:text-zinc-50 resize-none"
          />
          <input
            value={encKey}
            onChange={(e) => setEncKey(e.target.value)}
            placeholder="Key (hex, 32 / 48 / 64 chars)..."
            className="w-full p-3 rounded-lg border bg-zinc-50 dark:bg-zinc-800 dark:text-zinc-50"
          />
          <input
            value={encIV}
            onChange={(e) => setEncIV(e.target.value)}
            placeholder="IV (hex, optional — auto-generated if empty)..."
            className="w-full p-3 rounded-lg border bg-zinc-50 dark:bg-zinc-800 dark:text-zinc-50"
          />

          <button
            onClick={handleEncrypt}
            disabled={encLoading || !encPlaintext || !encKey}
            className="w-full bg-black text-white py-3 rounded-lg hover:opacity-80 transition disabled:opacity-40"
          >
            {encLoading ? "Encrypting…" : "Encrypt"}
          </button>

          {/*Output area*/}
          <div className="p-4 bg-zinc-100 dark:bg-zinc-800 rounded-lg text-sm break-all space-y-2 min-h-[80px]">
            {encError && <span className="text-red-500">{encError}</span>}
            {encResult && !encError && (
              <>
                <div>
                  <span className="text-zinc-400 text-xs uppercase tracking-wide">Ciphertext</span>
                  <p className="text-black dark:text-zinc-100 mt-0.5">{encResult.ciphertext_hex}</p>
                </div>
                <div>
                  <span className="text-zinc-400 text-xs uppercase tracking-wide">IV used</span>
                  <p className="text-black dark:text-zinc-100 mt-0.5">{encResult.iv_hex}</p>
                </div>
                <div>
                  <span className="text-zinc-400 text-xs uppercase tracking-wide">HMAC Tag</span>
                  <p className="text-black dark:text-zinc-100 mt-0.5">{encResult.tag_hex}</p>
                </div>
              </>
            )}
            {!encResult && !encError && (
              <span className="text-zinc-400">Output will appear here…</span>
            )}
          </div>

          {/*Send to Decrypt button, only shows after a successful encryption*/}
          {encResult && (
            <button
              onClick={handleSendToDecrypt}
              className="w-full border-2 border-black dark:border-zinc-400 text-black dark:text-zinc-200 py-3 rounded-lg hover:bg-zinc-100 dark:hover:bg-zinc-800 transition font-medium"
            >
              → Send to Decrypt
            </button>
          )}
        </div>

        {/*DECRYPT PANEL*/}
        <div className="bg-white dark:bg-zinc-900 p-8 rounded-2xl shadow-md flex flex-col gap-4">
          <div className="flex items-center justify-between">
            <h2 className="text-2xl font-semibold text-black dark:text-zinc-50">Decrypt</h2>
            {/* Visual badge when fields were auto-filled */}
            {carried && (
              <span className="text-xs bg-green-100 dark:bg-green-900 text-green-700 dark:text-green-300 px-2 py-1 rounded-full">
                ✓ Auto-filled
              </span>
            )}
          </div>

          <textarea
            value={decCiphertext}
            onChange={(e) => { setDecCiphertext(e.target.value); setCarried(false); }}
            placeholder="Ciphertext (hex)..."
            rows={4}
            className="w-full p-4 rounded-lg border bg-zinc-50 dark:bg-zinc-800 dark:text-zinc-50 resize-none"
          />
          <input
            value={decKey}
            onChange={(e) => { setDecKey(e.target.value); setCarried(false); }}
            placeholder="Key (hex)..."
            className="w-full p-3 rounded-lg border bg-zinc-50 dark:bg-zinc-800 dark:text-zinc-50"
          />
          <input
            value={decIV}
            onChange={(e) => { setDecIV(e.target.value); setCarried(false); }}
            placeholder="IV (hex)..."
            className="w-full p-3 rounded-lg border bg-zinc-50 dark:bg-zinc-800 dark:text-zinc-50"
          />
          {/* Tag field */}
          <input
            value={decTag}
            onChange={(e) => { setDecTag(e.target.value); setCarried(false); }}
            placeholder="HMAC Tag (hex)..."
            className="w-full p-3 rounded-lg border bg-zinc-50 dark:bg-zinc-800 dark:text-zinc-50"
          />

          <button
            onClick={handleDecrypt}
            disabled={decLoading || !decCiphertext || !decKey || !decIV || !decTag}
            className="w-full bg-black text-white py-3 rounded-lg hover:opacity-80 transition disabled:opacity-40"
          >
            {decLoading ? "Decrypting…" : "Decrypt"}
          </button>

          <div className="p-4 bg-zinc-100 dark:bg-zinc-800 rounded-lg text-sm break-all min-h-[80px]">
            {decError && <span className="text-red-500">{decError}</span>}
            {decOutput && !decError && (
              <div>
                <span className="text-zinc-400 text-xs uppercase tracking-wide">Plaintext</span>
                <p className="text-black dark:text-zinc-100 mt-0.5">{decOutput}</p>
              </div>
            )}
            {!decOutput && !decError && (
              <span className="text-zinc-400">Plaintext output will appear here…</span>
            )}
          </div>
        </div>

      </div>
    </div>
  );
}
