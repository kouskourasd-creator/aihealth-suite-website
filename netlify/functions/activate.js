// Netlify Function: activate.js
// Verifies a Gumroad license key, generates a machine-locked AIHS key, and emails it via Resend.
//
// Required environment variables (set in Netlify Dashboard → Site settings → Environment variables):
//   AIHS_LICENSE_SECRET   — must match the SECRET in src/license.ts
//   GUMROAD_PRODUCT_ID    — the Gumroad product permalink (e.g. "aihs" or the full product_id)
//   RESEND_API_KEY        — your Resend.com API key

const crypto = require("crypto");

const ALLOWED_ORIGINS = ["https://aihealthsuite.org", "https://www.aihealthsuite.org"];

function corsHeaders(origin) {
  const allowed = ALLOWED_ORIGINS.includes(origin) ? origin : ALLOWED_ORIGINS[0];
  return {
    "Access-Control-Allow-Origin": allowed,
    "Access-Control-Allow-Methods": "POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type",
  };
}

function sha256hex(str) {
  return crypto.createHash("sha256").update(str, "utf8").digest("hex");
}

function generateAIHSKey(machineId, secret) {
  const hash = sha256hex(machineId + secret);
  const hex = hash.substring(0, 20).toUpperCase();
  return `AIHS-${hex.substring(0, 4)}-${hex.substring(4, 8)}-${hex.substring(8, 12)}-${hex.substring(12, 16)}-${hex.substring(16, 20)}`;
}

async function verifyGumroadLicense(licenseKey, productId) {
  const body = new URLSearchParams({
    product_id: productId,
    license_key: licenseKey.trim(),
    increment_uses_count: "false",
  });

  const res = await fetch("https://api.gumroad.com/v2/licenses/verify", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: body.toString(),
  });

  if (!res.ok) {
    return { success: false, error: "gumroad_api_error" };
  }

  const data = await res.json();
  return data;
}

async function sendActivationEmail(resendKey, toEmail, toName, machineId, aihsKey) {
  const body = JSON.stringify({
    from: "AI Health Suite <noreply@aihealthsuite.org>",
    to: [toEmail],
    subject: "AI Health Suite — License Key / Κλειδί Άδειας Χρήσης",
    html: `
      <div style="font-family:Arial,sans-serif;max-width:600px;margin:0 auto;padding:24px;">
        <h2 style="color:#0ea5e9;">AI Health Suite — License Activation</h2>
        <p>Dear ${toName || toEmail},</p>
        <p>Your license has been activated successfully. Here is your license key:</p>
        <div style="background:#f0f9ff;border:2px solid #0ea5e9;border-radius:8px;padding:16px;margin:24px 0;text-align:center;">
          <code style="font-size:20px;font-weight:bold;letter-spacing:2px;color:#0369a1;">${aihsKey}</code>
        </div>
        <p><strong>Machine ID:</strong> <code style="background:#f1f5f9;padding:2px 6px;border-radius:4px;">${machineId}</code></p>
        <p style="color:#64748b;font-size:14px;">This key is locked to your machine. To activate: open AI Health Suite → Settings → License → enter the key above.</p>
        <hr style="border:none;border-top:1px solid #e2e8f0;margin:24px 0;" />
        <p style="color:#64748b;font-size:13px;">
          <strong>Ελληνικά:</strong> Το κλειδί σας έχει ενεργοποιηθεί επιτυχώς.<br>
          Άνοιξε το AI Health Suite → Ρυθμίσεις → Άδεια → εισάγετε το παραπάνω κλειδί.
        </p>
        <p style="color:#94a3b8;font-size:12px;margin-top:32px;">AI Health Suite · aihealthsuite.org</p>
      </div>
    `,
  });

  const res = await fetch("https://api.resend.com/emails", {
    method: "POST",
    headers: {
      "Authorization": `Bearer ${resendKey}`,
      "Content-Type": "application/json",
    },
    body,
  });

  return res.ok;
}

exports.handler = async function (event, context) {
  const origin = event.headers.origin || event.headers.Origin || "";
  const headers = corsHeaders(origin);

  // Handle CORS preflight
  if (event.httpMethod === "OPTIONS") {
    return { statusCode: 204, headers, body: "" };
  }

  if (event.httpMethod !== "POST") {
    return { statusCode: 405, headers, body: JSON.stringify({ error: "Method not allowed" }) };
  }

  // Parse body
  let body;
  try {
    body = JSON.parse(event.body || "{}");
  } catch {
    return { statusCode: 400, headers, body: JSON.stringify({ error: "Invalid JSON" }) };
  }

  const { gumroadKey, machineId } = body;

  // Validate inputs
  if (!gumroadKey || typeof gumroadKey !== "string") {
    return { statusCode: 400, headers, body: JSON.stringify({ error: "missing_gumroad_key" }) };
  }
  if (!machineId || typeof machineId !== "string") {
    return { statusCode: 400, headers, body: JSON.stringify({ error: "missing_machine_id" }) };
  }
  // Machine ID must look like AIHS-XXXX-XXXX-XXXX-XXXX
  if (!/^AIHS-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}$/i.test(machineId.trim())) {
    return { statusCode: 400, headers, body: JSON.stringify({ error: "invalid_machine_id" }) };
  }

  const secret = process.env.AIHS_LICENSE_SECRET;
  const productId = process.env.GUMROAD_PRODUCT_ID;
  const resendKey = process.env.RESEND_API_KEY;

  if (!secret || !productId || !resendKey) {
    console.error("Missing environment variables");
    return { statusCode: 500, headers, body: JSON.stringify({ error: "server_misconfigured" }) };
  }

  // Verify with Gumroad
  const gumroad = await verifyGumroadLicense(gumroadKey, productId);

  if (!gumroad.success) {
    return {
      statusCode: 400,
      headers,
      body: JSON.stringify({ error: "invalid_license_key", detail: gumroad.message }),
    };
  }

  const purchase = gumroad.purchase;
  if (!purchase) {
    return { statusCode: 400, headers, body: JSON.stringify({ error: "no_purchase_data" }) };
  }

  // Check if refunded or chargedback
  if (purchase.refunded || purchase.chargebacked) {
    return { statusCode: 403, headers, body: JSON.stringify({ error: "license_refunded" }) };
  }

  const cleanMachineId = machineId.trim().toUpperCase();
  const aihsKey = generateAIHSKey(cleanMachineId, secret);

  const buyerEmail = purchase.email || purchase.seller_id;
  const buyerName = purchase.full_name || purchase.email || "";

  // Send activation email
  let emailSent = false;
  if (buyerEmail && buyerEmail.includes("@")) {
    emailSent = await sendActivationEmail(resendKey, buyerEmail, buyerName, cleanMachineId, aihsKey);
  }

  return {
    statusCode: 200,
    headers,
    body: JSON.stringify({
      ok: true,
      licenseKey: aihsKey,
      email: buyerEmail || null,
      emailSent,
    }),
  };
};
