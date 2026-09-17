LOC STAR BACKEND STARTER

Mục đích:
- Tạo Web Service Node/Express trên Render.
- Có endpoint /api/webhook/sepay.
- Xác thực SePay bằng HMAC-SHA256.
- Lưu giao dịch ngân hàng và chống giao dịch trùng.
- Chuẩn bị database cho tài khoản, số dư và lịch sử.

BẢN NÀY CHƯA TỰ CỘNG TIỀN.
Không bật webhook Live để cộng tiền trước khi phần ghép mã nạp
với tài khoản và cập nhật số dư atomic được hoàn thiện.

Render:
Runtime: Node
Build Command: npm install
Start Command: npm start
Health check: /health

Environment variables:
SUPABASE_URL
SUPABASE_SERVICE_ROLE_KEY
SEPAY_WEBHOOK_SECRET
BANK_ACCOUNT=9369549277
BANK_NAME=Vietcombank
BANK_OWNER=NGUYEN TAN LOC

KHÔNG commit file .env hoặc secret vào GitHub.
