# IDOR Lab — penjelasan & real case

Lab Flask yang memodelkan **Insecure Direct Object Reference (IDOR)** — kategori paling
sering ditemukan di program Bug Bounty besar. Server mempercayai **id dari input**
(URL path, query, body) tanpa memverifikasi kepemilikan terhadap sesi pemakai.

- Port: `http://127.0.0.1:5097`
- Sesi aktif: `attacker` (id 3, role user). Korban: `victim` (id 2). Target: `admin` (id 1, *flag*).
- Flag: `IDOR-LAB{Flag_IDOR_Horizontal_Vertical_Bypass_2217}`

## Skenario
1. **Horizontal IDOR** — `GET /api/v1/profile/2`. Tidak ada `owner == session` → PII user lain bocor.
2. **Vertical IDOR / privilege escalation** — `GET /api/v1/admin/users` tanpa cek role → semua user + secret + flag.
3. **Mass-IDOR (export/object array)** — `POST /api/v1/export` menerima `user_ids[]` bebas → borong seluruh dokumen (mass object reference).
4. **IDOR → ATO** — update profil tidak memaksa `user_id` dari sesi; attacker mengubah email victim lalu reset password → full account takeover.

## Mengapa RENTAN
- Approval lain: `uid`/`user_id`/`ids[]` dipakai **langsung tanpa binding ke sesi**.
- Tidak ada object-level authorization check (server hanya cek "login?" — bukan "pemilik?").

## Fix (FIXED mode)
- **Object ownership**: `uid == session.user_id` utk semua akses/update.
- **Role check** sebelum endpoint sensitif (admin-only).
- Export dibatasi ke data sesi sendiri + limit hasil.
- Id dari body tidak dipercaya: ambil identitas dari sesi/cookie.

## Cara jalankan
```
python -m app.main         # dari folder lab — port 5097 (attacker otomatis login)
```
### Docker
```bash
docker compose up -d --build
```
Payload & cheat-sheet: `payloads/README.md`, `docs/idor-cheatsheet.md`.