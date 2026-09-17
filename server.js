import express from "express";
import crypto from "node:crypto";
import { createClient } from "@supabase/supabase-js";

const app = express();
const PORT = Number(process.env.PORT || 10000);

const SUPABASE_URL = process.env.SUPABASE_URL;

// Chấp nhận cả 2 tên biến môi trường
const SUPABASE_SERVICE_ROLE_KEY =
  process.env.SUPABASE_SERVICE_ROLE_KEY ||
  process.env.SUPABASE_SECRET_KEY;

const SEPAY_WEBHOOK_SECRET = process.env.SEPAY_WEBHOOK_SECRET;

const BANK_ACCOUNT = process.env.BANK_ACCOUNT || "9369549277";
const BANK_NAME = process.env.BANK_NAME || "Vietcombank";
const BANK_OWNER = process.env.BANK_OWNER || "NGUYEN TAN LOC";

const supabase =
  SUPABASE_URL && SUPABASE_SERVICE_ROLE_KEY
    ? createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, {
        auth: {
          autoRefreshToken: false,
          persistSession: false
        }
      })
    : null;

// ==============================
// HEALTH CHECK
// ==============================
app.get("/health", (_req, res) => {
  res.json({
    ok: true,
    service: "LOC STAR backend"
  });
});

// ==============================
// PUBLIC CONFIG
// ==============================
app.get("/api/config/public", (_req, res) => {
  res.json({
    bankName: BANK_NAME,
    accountNumber: BANK_ACCOUNT,
    accountOwner: BANK_OWNER
  });
});

// ==============================
// SEPAY WEBHOOK
// ==============================
// Raw body bắt buộc để kiểm tra HMAC chính xác.
app.post(
  "/api/webhook/sepay",
  express.raw({ type: "application/json" }),
  async (req, res) => {
    try {
      // Kiểm tra cấu hình
      if (!SEPAY_WEBHOOK_SECRET) {
        return res.status(500).json({
          success: false,
          message: "Webhook secret is not configured"
        });
      }

      if (!supabase) {
        return res.status(500).json({
          success: false,
          message: "Database is not configured"
        });
      }

      // ==============================
      // ĐỌC HEADER SEPAY
      // ==============================
      const signature = String(
        req.get("X-SePay-Signature") || ""
      );

      const timestamp = Number(
        req.get("X-SePay-Timestamp") || 0
      );

      const body = Buffer.isBuffer(req.body)
        ? req.body
        : Buffer.from("");

      // ==============================
      // KIỂM TRA TIMESTAMP
      // ==============================
      if (
        !timestamp ||
        Math.abs(
          Math.floor(Date.now() / 1000) - timestamp
        ) > 300
      ) {
        return res.status(401).json({
          success: false,
          message: "Request expired"
        });
      }

      // ==============================
      // KIỂM TRA HMAC
      // ==============================
      const expected =
        "sha256=" +
        crypto
          .createHmac(
            "sha256",
            SEPAY_WEBHOOK_SECRET
          )
          .update(
            `${timestamp}.${body.toString("utf8")}`
          )
          .digest("hex");

      const a = Buffer.from(expected);
      const b = Buffer.from(signature);

      if (
        a.length !== b.length ||
        !crypto.timingSafeEqual(a, b)
      ) {
        return res.status(401).json({
          success: false,
          message: "Invalid signature"
        });
      }

      // ==============================
      // ĐỌC PAYLOAD
      // ==============================
      const payload = JSON.parse(
        body.toString("utf8")
      );

      // Chỉ xử lý tiền vào
      if (
        String(payload.transferType || "").toLowerCase() !==
        "in"
      ) {
        return res.status(200).json({
          success: true,
          ignored: true
        });
      }

      const amount = Number(
        payload.transferAmount || 0
      );

      const transactionId = String(
        payload.id ||
          payload.referenceCode ||
          ""
      ).trim();

      const content = String(
        payload.content || ""
      ).trim();

      const incomingAccount = String(
        payload.accountNumber || ""
      ).replace(/\D/g, "");

      const expectedAccount = String(
        BANK_ACCOUNT
      ).replace(/\D/g, "");

      // ==============================
      // KIỂM TRA DỮ LIỆU GIAO DỊCH
      // ==============================
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

      // Nếu SePay gửi accountNumber thì kiểm tra
      if (
        incomingAccount &&
        expectedAccount &&
        incomingAccount !== expectedAccount
      ) {
        return res.status(400).json({
          success: false,
          message: "Wrong bank account"
        });
      }

      // ==============================
      // LƯU GIAO DỊCH VÀO SUPABASE
      // ==============================
      const { error: insertError } =
        await supabase
          .from("bank_transactions")
          .insert({
            transaction_id: transactionId,
            gateway: String(
              payload.gateway || BANK_NAME
            ),
            account_number: String(
              payload.accountNumber || ""
            ),
            transaction_date:
              payload.transactionDate || null,
            amount,
            content,
            reference_code: String(
              payload.referenceCode || ""
            ),
            raw_payload: payload,
            status: "received"
          });

      // ==============================
      // GIAO DỊCH ĐÃ TỒN TẠI
      // ==============================
      if (insertError) {
        if (insertError.code === "23505") {
          // Giao dịch đã có trong database.
          // Vẫn gọi RPC để xử lý lại nếu trước đó
          // chưa tìm được người dùng.
          const {
            data: processResult,
            error: processError
          } = await supabase.rpc(
            "process_bank_transaction",
            {
              p_transaction_id: transactionId
            }
          );

          if (processError) {
            console.error(
              "RPC duplicate processing error:",
              processError
            );

            return res.status(500).json({
              success: false,
              message:
                "Transaction processing failed"
            });
          }

          return res.status(200).json({
            success: true,
            duplicate: true,
            result: processResult
          });
        }

        console.error(
          "Database insert error:",
          insertError
        );

        return res.status(500).json({
          success: false,
          message: "Database insert failed"
        });
      }

      // ==============================
      // TỰ ĐỘNG XỬ LÝ GIAO DỊCH
      // ==============================
      const {
        data: processResult,
        error: processError
      } = await supabase.rpc(
        "process_bank_transaction",
        {
          p_transaction_id: transactionId
        }
      );

      if (processError) {
        console.error(
          "RPC processing error:",
          processError
        );

        // Trả 500 để SePay có thể gửi lại
        return res.status(500).json({
          success: false,
          message:
            "Transaction processing failed"
        });
      }

      // ==============================
      // TRẢ KẾT QUẢ
      // ==============================
      return res.status(200).json({
        success: true,
        received: true,
        result: processResult
      });

    } catch (err) {
      console.error(
        "Webhook processing error:",
        err
      );

      return res.status(500).json({
        success: false,
        message: "Webhook processing failed"
      });
    }
  }
);

// ==============================
// JSON API
// ==============================
app.use(express.json());

// ==============================
// START SERVER
// ==============================
app.listen(PORT, "0.0.0.0", () => {
  console.log(
    `LOC STAR backend listening on port ${PORT}`
  );
});
