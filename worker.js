const ALLOWED_ORIGIN = "https://vmtotp.vaqzmobiz.com";

export default {
  async fetch(request) {
    const origin = request.headers.get("Origin");
    const corsHeaders = {
      "Access-Control-Allow-Origin": ALLOWED_ORIGIN,
      "Access-Control-Allow-Methods": "GET, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type",
      "Access-Control-Max-Age": "86400",
      "Vary": "Origin"
    };

    if (request.method === "OPTIONS") {
      return new Response(null, {
        status: 204,
        headers: origin === ALLOWED_ORIGIN ? corsHeaders : { "Vary": "Origin" }
      });
    }

    if (origin && origin !== ALLOWED_ORIGIN) {
      return json({ error: "Origin not allowed." }, 403, { "Vary": "Origin" });
    }

    if (request.method !== "GET") {
      return json({ error: "Method not allowed." }, 405, corsHeaders);
    }

    const url = new URL(request.url);
    const secret = url.searchParams.get("secret");

    if (!secret) {
      return json({ error: "Missing secret query parameter." }, 400, corsHeaders);
    }

    try {
      const cleanSecret = secret.replace(/\\s+/g, "").toUpperCase();
      const token = await generateTOTP(cleanSecret);
      return json({ otp: token }, 200, {
        ...corsHeaders,
        "Cache-Control": "no-store, no-cache, must-revalidate",
        "Pragma": "no-cache"
      });
    } catch {
      return json({ error: "Invalid Base32 secret key provided." }, 400, corsHeaders);
    }
  }
};

function json(data, status, headers = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json; charset=utf-8", ...headers }
  });
}

// Native Base32 and TOTP implementation (SHA-1, 6 digits, 30-second period).
function base32ToBytes(base32) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  const cleaned = base32.replace(/=+$/, "").toUpperCase();
  if (!cleaned || !/^[A-Z2-7]+$/.test(cleaned)) {
    throw new Error("Invalid Base32 secret");
  }

  let bits = "";
  for (const char of cleaned) {
    bits += alphabet.indexOf(char).toString(2).padStart(5, "0");
  }

  const bytes = [];
  for (let i = 0; i + 8 <= bits.length; i += 8) {
    bytes.push(parseInt(bits.slice(i, i + 8), 2));
  }
  if (bytes.length === 0) throw new Error("Secret is too short");
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
