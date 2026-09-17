import express from "express";
import crypto from "node:crypto";
import { createClient } from "@supabase/supabase-js";

const app = express();
const PORT = Number(process.env.PORT || 10000);

const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;
const SEPAY_WEBHOOK_SECRET = process.env.SEPAY_WEBHOOK_SECRET;

const BANK_ACCOUNT = process.env.BANK_ACCOUNT || "9369549277";
const BANK_NAME = process.env.BANK_NAME || "Vietcombank";
const BANK_OWNER = process.env.BANK_OWNER || "NGUYEN TAN LOC";

const supabase =
  SUPABASE_URL && SUPABASE_SERVICE_ROLE_KEY
    ? createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, {
        auth: { autoRefreshToken: false, persistSession: false }
      })
    : null;

app.get("/health", (_req, res) => {
  res.json({ ok: true, service: "LOC STAR backend" });
});

// SePay HMAC webhook.
// Raw body is required for correct signature verification.
app.post(
  "/api/webhook/sepay",
  express.raw({ type: "application/json" }),
  async (req, res) => {
    try {
      if (!SEPAY_WEBHOOK_SECRET) {
        return res.status(500).json({
          success: false,
          message: "Webhook secret is not configured"
        });
      }

      const signature = String(req.get("X-SePay-Signature") || "");
      const timestamp = Number(req.get("X-SePay-Timestamp") || 0);
      const body = Buffer.isBuffer(req.body) ? req.body : Buffer.from("");

      if (
        !timestamp ||
        Math.abs(Math.floor(Date.now() / 1000) - timestamp) > 300
      ) {
        return res
          .status(401)
          .json({ success: false, message: "Request expired" });
      }

      const expected =
        "sha256=" +
        crypto
          .createHmac("sha256", SEPAY_WEBHOOK_SECRET)
          .update(`${timestamp}.${body.toString("utf8")}`)
          .digest("hex");

      const a = Buffer.from(expected);
      const b = Buffer.from(signature);

      if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
        return res
          .status(401)
          .json({ success: false, message: "Invalid signature" });
      }

      const payload = JSON.parse(body.toString("utf8"));

      if (String(payload.transferType || "").toLowerCase() !== "in") {
        return res.status(200).json({ success: true, ignored: true });
      }

      const amount = Number(payload.transferAmount || 0);
      const transactionId = String(
        payload.id || payload.referenceCode || ""
      );
      const content = String(payload.content || "").trim();

      if (
        !transactionId ||
        !Number.isFinite(amount) ||
        amount <= 0
      ) {
        return res.status(400).json({
          success: false,
          message: "Invalid transaction data"
        });
      }

      if (!supabase) {
        return res.status(500).json({
          success: false,
          message: "Database is not configured"
        });
      }

      // Unique transaction_id prevents the same bank transaction
      // from being credited twice.
      const { error: insertError } = await supabase
        .from("bank_transactions")
        .insert({
          transaction_id: transactionId,
          gateway: String(payload.gateway || BANK_NAME),
          account_number: String(payload.accountNumber || ""),
          transaction_date: payload.transactionDate || null,
          amount,
          content,
          reference_code: String(payload.referenceCode || ""),
          raw_payload: payload,
          status: "received"
        });

      if (insertError) {
        if (insertError.code === "23505") {
          return res.status(200).json({
            success: true,
            duplicate: true
          });
        }

        console.error(insertError);
        return res.status(500).json({
          success: false,
          message: "Database insert failed"
        });
      }

      // IMPORTANT:
      // Money is intentionally NOT credited yet.
      // The next stage will securely match the unique deposit code
      // in the transfer content to the correct user and perform
      // an atomic balance + ledger update.
      return res.status(200).json({
        success: true,
        received: true
      });
    } catch (err) {
      console.error(err);
      return res.status(500).json({
        success: false,
        message: "Webhook processing failed"
      });
    }
  }
);

app.use(express.json());

app.get("/api/config/public", (_req, res) => {
  res.json({
    bankName: BANK_NAME,
    accountNumber: BANK_ACCOUNT,
    accountOwner: BANK_OWNER
  });
});

app.listen(PORT, "0.0.0.0", () => {
  console.log(`LOC STAR backend listening on port ${PORT}`);
});
