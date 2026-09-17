import express from "express";
import crypto from "node:crypto";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import cors from "cors";
import { createClient } from "@supabase/supabase-js";

const app = express();

app.use(cors({
  origin: "https://locstar-shop.onrender.com"
}));

const PORT = Number(process.env.PORT || 10000);

const SUPABASE_URL = process.env.SUPABASE_URL;

const SUPABASE_SERVICE_ROLE_KEY =
  process.env.SUPABASE_SERVICE_ROLE_KEY ||
  process.env.SUPABASE_SECRET_KEY;

const SEPAY_WEBHOOK_SECRET =
  process.env.SEPAY_WEBHOOK_SECRET;

const JWT_SECRET =
  process.env.JWT_SECRET;

const BANK_ACCOUNT =
  process.env.BANK_ACCOUNT || "9369549277";

const BANK_NAME =
  process.env.BANK_NAME || "Vietcombank";

const BANK_OWNER =
  process.env.BANK_OWNER || "NGUYEN TAN LOC";

const supabase =
  SUPABASE_URL && SUPABASE_SERVICE_ROLE_KEY
    ? createClient(
        SUPABASE_URL,
        SUPABASE_SERVICE_ROLE_KEY,
        {
          auth: {
            autoRefreshToken: false,
            persistSession: false
          }
        }
      )
    : null;


// ========================================
// HEALTH CHECK
// ========================================

app.get("/health", (_req, res) => {
  res.json({
    ok: true,
    service: "LOC STAR backend"
  });
});


// ========================================
// PUBLIC CONFIG
// ========================================

app.get("/api/config/public", (_req, res) => {
  res.json({
    bankName: BANK_NAME,
    accountNumber: BANK_ACCOUNT,
    accountOwner: BANK_OWNER
  });
});


// ========================================
// SEPAY WEBHOOK
// ========================================
// QUAN TRỌNG:
// Webhook phải dùng express.raw()
// để kiểm tra chữ ký HMAC chính xác.

app.post(
  "/api/webhook/sepay",
  express.raw({
    type: "application/json"
  }),
  async (req, res) => {

    try {

      if (!SEPAY_WEBHOOK_SECRET) {
        return res.status(500).json({
          success: false,
          message:
            "Webhook secret is not configured"
        });
      }

      if (!supabase) {
        return res.status(500).json({
          success: false,
          message:
            "Database is not configured"
        });
      }


      // ----------------------------
      // Đọc header SePay
      // ----------------------------

      const signature = String(
        req.get(
          "X-SePay-Signature"
        ) || ""
      );

      const timestamp = Number(
        req.get(
          "X-SePay-Timestamp"
        ) || 0
      );

      const body =
        Buffer.isBuffer(req.body)
          ? req.body
          : Buffer.from("");


      // ----------------------------
      // Kiểm tra timestamp
      // ----------------------------

      if (
        !timestamp ||
        Math.abs(
          Math.floor(Date.now() / 1000) -
            timestamp
        ) > 300
      ) {
        return res.status(401).json({
          success: false,
          message:
            "Request expired"
        });
      }


      // ----------------------------
      // Kiểm tra HMAC
      // ----------------------------

      const expected =
        "sha256=" +
        crypto
          .createHmac(
            "sha256",
            SEPAY_WEBHOOK_SECRET
          )
          .update(
            `${timestamp}.${body.toString(
              "utf8"
            )}`
          )
          .digest("hex");


      const a =
        Buffer.from(expected);

      const b =
        Buffer.from(signature);


      if (
        a.length !== b.length ||
        !crypto.timingSafeEqual(
          a,
          b
        )
      ) {
        return res.status(401).json({
          success: false,
          message:
            "Invalid signature"
        });
      }


      // ----------------------------
      // Đọc payload
      // ----------------------------

      const payload =
        JSON.parse(
          body.toString("utf8")
        );


      // Chỉ xử lý tiền vào
      if (
        String(
          payload.transferType || ""
        ).toLowerCase() !== "in"
      ) {
        return res.status(200).json({
          success: true,
          ignored: true
        });
      }


      const amount = Number(
        payload.transferAmount || 0
      );


      const transactionId =
        String(
          payload.id ||
            payload.referenceCode ||
            ""
        ).trim();


      const content =
        String(
          payload.content || ""
        ).trim();


      const incomingAccount =
        String(
          payload.accountNumber || ""
        ).replace(/\D/g, "");


      const expectedAccount =
        String(BANK_ACCOUNT)
          .replace(/\D/g, "");


      // ----------------------------
      // Kiểm tra giao dịch
      // ----------------------------

      if (
        !transactionId ||
        !Number.isFinite(amount) ||
        amount <= 0
      ) {
        return res.status(400).json({
          success: false,
          message:
            "Invalid transaction data"
        });
      }


      // Kiểm tra đúng tài khoản ngân hàng
      if (
        incomingAccount &&
        expectedAccount &&
        incomingAccount !==
          expectedAccount
      ) {
        return res.status(400).json({
          success: false,
          message:
            "Wrong bank account"
        });
      }


      // ----------------------------
      // Lưu giao dịch
      // ----------------------------

      const {
        error: insertError
      } = await supabase
        .from("bank_transactions")
        .insert({
          transaction_id:
            transactionId,

          gateway:
            String(
              payload.gateway ||
                BANK_NAME
            ),

          account_number:
            String(
              payload.accountNumber ||
                ""
            ),

          transaction_date:
            payload.transactionDate ||
            null,

          amount,

          content,

          reference_code:
            String(
              payload.referenceCode ||
                ""
            ),

          raw_payload:
            payload,

          status:
            "received"
        });


      // ----------------------------
      // Giao dịch đã tồn tại
      // ----------------------------

      if (insertError) {

        if (
          insertError.code ===
          "23505"
        ) {

          const {
            data: processResult,
            error: processError
          } =
            await supabase.rpc(
              "process_bank_transaction",
              {
                p_transaction_id:
                  transactionId
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
            result:
              processResult
          });
        }


        console.error(
          "Database insert error:",
          insertError
        );


        return res.status(500).json({
          success: false,
          message:
            "Database insert failed"
        });
      }


      // ----------------------------
      // Tự động cộng tiền
      // ----------------------------

      const {
        data: processResult,
        error: processError
      } =
        await supabase.rpc(
          "process_bank_transaction",
          {
            p_transaction_id:
              transactionId
          }
        );


      if (processError) {

        console.error(
          "RPC processing error:",
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
        received: true,
        result:
          processResult
      });


    } catch (err) {

      console.error(
        "Webhook processing error:",
        err
      );


      return res.status(500).json({
        success: false,
        message:
          "Webhook processing failed"
      });
    }
  }
);


// ========================================
// JSON API
// ========================================
// Đặt SAU webhook để không phá express.raw()

app.use(express.json());


// ========================================
// ĐĂNG KÝ TÀI KHOẢN
// ========================================

app.post(
  "/api/auth/register",
  async (req, res) => {

    try {

      if (!supabase) {
        return res.status(500).json({
          success: false,
          message:
            "Database is not configured"
        });
      }


      const username =
        String(
          req.body?.username || ""
        ).trim();


      const email =
        String(
          req.body?.email || ""
        ).trim().toLowerCase();


      const password =
        String(
          req.body?.password || ""
        );


      // ----------------------------
      // Kiểm tra dữ liệu
      // ----------------------------

      if (
        !username ||
        !email ||
        !password
      ) {
        return res.status(400).json({
          success: false,
          message:
            "Vui lòng nhập đầy đủ thông tin"
        });
      }


      if (username.length < 3) {
        return res.status(400).json({
          success: false,
          message:
            "Tên tài khoản phải có ít nhất 3 ký tự"
        });
      }


      if (username.length > 30) {
        return res.status(400).json({
          success: false,
          message:
            "Tên tài khoản tối đa 30 ký tự"
        });
      }


      if (password.length < 6) {
        return res.status(400).json({
          success: false,
          message:
            "Mật khẩu phải có ít nhất 6 ký tự"
        });
      }


      if (
        !/^[a-zA-Z0-9_.-]+$/.test(
          username
        )
      ) {
        return res.status(400).json({
          success: false,
          message:
            "Tên tài khoản chỉ được dùng chữ, số, dấu chấm, gạch ngang hoặc gạch dưới"
        });
      }


      // ----------------------------
      // Kiểm tra username
      // ----------------------------

      const {
        data: existingUsername,
        error: usernameError
      } =
        await supabase
          .from("app_users")
          .select("id")
          .eq(
            "username",
            username
          )
          .maybeSingle();


      if (usernameError) {

        console.error(
          usernameError
        );

        return res.status(500).json({
          success: false,
          message:
            "Không thể kiểm tra tài khoản"
        });
      }


      if (existingUsername) {
        return res.status(409).json({
          success: false,
          message:
            "Tên tài khoản đã tồn tại"
        });
      }


      // ----------------------------
      // Kiểm tra email
      // ----------------------------

      const {
        data: existingEmail,
        error: emailError
      } =
        await supabase
          .from("app_users")
          .select("id")
          .ilike(
            "email",
            email
          )
          .maybeSingle();


      if (emailError) {

        console.error(
          emailError
        );

        return res.status(500).json({
          success: false,
          message:
            "Không thể kiểm tra email"
        });
      }


      if (existingEmail) {
        return res.status(409).json({
          success: false,
          message:
            "Email đã được sử dụng"
        });
      }


      // ----------------------------
      // Tạo mã nạp tiền
      // ----------------------------

      let depositCode = "";


      for (
        let i = 0;
        i < 10;
        i++
      ) {

        const randomPart =
          crypto
            .randomBytes(4)
            .toString("hex")
            .toUpperCase();


        depositCode =
          `LS${randomPart}`;


        const {
          data: existingCode,
          error: codeError
        } =
          await supabase
            .from("app_users")
            .select("id")
            .eq(
              "deposit_code",
              depositCode
            )
            .maybeSingle();


        if (codeError) {

          console.error(
            codeError
          );

          return res.status(500).json({
            success: false,
            message:
              "Không thể tạo mã nạp tiền"
          });
        }


        if (!existingCode) {
          break;
        }


        depositCode = "";
      }


      if (!depositCode) {
        return res.status(500).json({
          success: false,
          message:
            "Không thể tạo mã nạp tiền"
        });
      }


      // ----------------------------
      // Mã hóa mật khẩu
      // ----------------------------

      const passwordHash =
        await bcrypt.hash(
          password,
          12
        );


      // ----------------------------
      // Tạo tài khoản
      // ----------------------------

      const {
        data: newUser,
        error: insertError
      } =
        await supabase
          .from("app_users")
          .insert({
            username,
            email,
            password_hash:
              passwordHash,
            full_name: "",
            balance: 0,
            deposit_code:
              depositCode
          })
          .select(
            "id, username, email, balance, deposit_code"
          )
          .single();


      if (insertError) {

        console.error(
          insertError
        );


        if (
          insertError.code ===
          "23505"
        ) {
          return res.status(409).json({
            success: false,
            message:
              "Tên tài khoản hoặc email đã tồn tại"
          });
        }


        return res.status(500).json({
          success: false,
          message:
            "Không thể tạo tài khoản"
        });
      }


      return res.status(201).json({
        success: true,
        message:
          "Đăng ký tài khoản thành công",

        user: {
          id: newUser.id,
          username:
            newUser.username,
          email:
            newUser.email,
          balance:
            Number(
              newUser.balance
            ),
          depositCode:
            newUser.deposit_code
        }
      });


    } catch (err) {

      console.error(
        "Register error:",
        err
      );


      return res.status(500).json({
        success: false,
        message:
          "Đăng ký tài khoản thất bại"
      });
    }
  }
);


// ========================================
// ĐĂNG NHẬP
// ========================================

app.post(
  "/api/auth/login",
  async (req, res) => {

    try {

      if (!supabase) {
        return res.status(500).json({
          success: false,
          message:
            "Database is not configured"
        });
      }


      if (!JWT_SECRET) {
        return res.status(500).json({
          success: false,
          message:
            "JWT secret is not configured"
        });
      }


      const username =
        String(
          req.body?.username || ""
        ).trim();


      const password =
        String(
          req.body?.password || ""
        );


      if (
        !username ||
        !password
      ) {
        return res.status(400).json({
          success: false,
          message:
            "Vui lòng nhập đầy đủ thông tin"
        });
      }


      // ----------------------------
      // Tìm tài khoản
      // ----------------------------

      const {
        data: user,
        error: userError
      } =
        await supabase
          .from("app_users")
          .select(
            "id, username, email, password_hash, balance, deposit_code"
          )
          .eq(
            "username",
            username
          )
          .maybeSingle();


      if (userError) {

        console.error(
          userError
        );

        return res.status(500).json({
          success: false,
          message:
            "Không thể kiểm tra tài khoản"
        });
      }


      if (!user) {
        return res.status(401).json({
          success: false,
          message:
            "Tên tài khoản hoặc mật khẩu không đúng"
        });
      }


      // ----------------------------
      // Kiểm tra mật khẩu
      // ----------------------------

      const passwordCorrect =
        await bcrypt.compare(
          password,
          user.password_hash
        );


      if (!passwordCorrect) {
        return res.status(401).json({
          success: false,
          message:
            "Tên tài khoản hoặc mật khẩu không đúng"
        });
      }


      // ----------------------------
      // Tạo JWT
      // ----------------------------

      const token =
        jwt.sign(
          {
            userId: user.id,
            username:
              user.username
          },
          JWT_SECRET,
          {
            expiresIn:
              "7d"
          }
        );


      // ----------------------------
      // Trả kết quả
      // ----------------------------

      return res.status(200).json({

        success: true,

        message:
          "Đăng nhập thành công",

        token,

        user: {
          id: user.id,
          username:
            user.username,
          email:
            user.email,
          balance:
            Number(
              user.balance
            ),
          depositCode:
            user.deposit_code
        }

      });


    } catch (err) {

      console.error(
        "Login error:",
        err
      );


      return res.status(500).json({
        success: false,
        message:
          "Đăng nhập thất bại"
      });
    }
  }
);


// ========================================
// START SERVER
// ========================================

app.listen(
  PORT,
  "0.0.0.0",
  () => {
    console.log(
      `LOC STAR backend listening on port ${PORT}`
    );
  }
);
