export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    // Support both the frontend API route and the legacy root JSON endpoint.
    // /?secret=... returns JSON; / without a secret serves the frontend.
    if (url.pathname === "/api/totp" || (url.pathname === "/" && url.searchParams.has("secret"))) {
      if (request.method === "OPTIONS") {
        return new Response(null, {
          status: 204,
          headers: {
            "Access-Control-Allow-Origin": url.origin,
            "Access-Control-Allow-Methods": "GET, OPTIONS",
            "Access-Control-Allow-Headers": "Content-Type",
            "Access-Control-Max-Age": "86400",
            "Vary": "Origin"
          }
        });
      }

      if (request.method !== "GET") {
        return json({ error: "Method not allowed." }, 405, { Allow: "GET, OPTIONS" });
      }

      const secret = url.searchParams.get("secret");
      if (!secret) return json({ error: "Missing secret query parameter." }, 400);

      try {
        const cleanSecret = secret.replace(/\s+/g, "").toUpperCase();
        const otp = await generateTOTP(cleanSecret);
        return json({ otp }, 200, {
          "Cache-Control": "no-store, no-cache, must-revalidate",
          "Pragma": "no-cache"
        });
      } catch {
        return json({ error: "Invalid Base32 secret key provided." }, 400);
      }
    }

    // All non-API paths (including /) are served from the bundled static frontend.
    return env.ASSETS.fetch(request);
  }
};

function json(data, status, extraHeaders = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store",
      ...extraHeaders
    }
  });
}

// Native Base32 and TOTP implementation (SHA-1, six digits, 30-second period).
function base32ToBytes(base32) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  const cleaned = base32.replace(/=+$/, "").toUpperCase();
  if (!cleaned || !/^[A-Z2-7]+$/.test(cleaned)) {
    throw new Error("Invalid Base32 secret");
  }
  let bits = "";
  for (const char of cleaned) bits += alphabet.indexOf(char).toString(2).padStart(5, "0");
  const bytes = [];
  for (let i = 0; i + 8 <= bits.length; i += 8) bytes.push(parseInt(bits.slice(i, i + 8), 2));
  if (!bytes.length) throw new Error("Secret is too short");
  return new Uint8Array(bytes);
}

function intToBytes(num) {
  const bytes = new Uint8Array(8);
  for (let i = 7; i >= 0; i--) {
    bytes[i] = num & 0xff;
    num = Math.floor(num / 256);
  }
  return bytes;
}

async function generateTOTP(secret) {
  const keyBytes = base32ToBytes(secret);
  const timeStep = Math.floor(Date.now() / 1000 / 30);
  const key = await crypto.subtle.importKey(
    "raw", keyBytes, { name: "HMAC", hash: "SHA-1" }, false, ["sign"]
  );
  const signature = new Uint8Array(
    await crypto.subtle.sign("HMAC", key, intToBytes(timeStep))
  );
  const offset = signature[signature.length - 1] & 0x0f;
  const binary =
    ((signature[offset] & 0x7f) << 24) |
    ((signature[offset + 1] & 0xff) << 16) |
    ((signature[offset + 2] & 0xff) << 8) |
    (signature[offset + 3] & 0xff);
  return String(binary % 1000000).padStart(6, "0");
}
