# IDOR Lab

Lab Flask yang memodelkan **4 bentuk IDOR (Broken Object Level Authorization)** — kategory
#1 paling banyak ketemu dan dibayar di Bug Bounty: **horizontal** (baca profil user lain),
**vertical** (endpoint admin tanpa role check), **mass-IDOR** (export array id sembarang),
dan **IDOR → Account Takeover** (ganti email korban via `user_id` di body). Tiap skenario
toggle **RENTAN / FIXED** + endpoint curl manual.

## 🧨 4 Skenario

| # | Endpoint | Efek eksploit |
|---|----------|---------------|
| 1 | `GET /api/v1/profile/2` | Horizontal IDOR → PII victim (email, phone, password) bocor |
| 2 | `GET /api/v1/admin/users` | Vertical → semua user + secret admin + flag |
| 3 | `POST /api/v1/export` `{"user_ids":[1,2,3]}` | Mass-IDOR → borong seluruh dokumen |
| 4 | `POST /api/v1/profile/update` `{"user_id":2,"email":attacker}` | IDOR → email korban dicuri → ATO |

Sesi attacker (id 3). Flag: `IDOR-LAB{Flag_IDOR_Horizontal_Vertical_Bypass_2217}` (di admin).

## 🚀 Menjalankan
### Docker (rekomendasi)
```bash
docker compose up -d --build      # buka http://127.0.0.1:5097
docker compose down               # stop
docker compose down -v            # stop + reset
```
### Lokal
```bash
pip install -r requirements.txt
python -m app.main
```

## 🧭 Cara main
- Dashboard → **Jalankan Exploit** → toggle **FIXED** → ulangi.
- Eksplorasi manual via curl (lihat `payloads/README.md`).
- Cheat-sheet audit (deteksi, checklist object-level auth): `docs/idor-cheatsheet.md`.

## Isi repo
```
app/          Flask: endpoint IDOR (RENTAN/FIXED) + PoC
docs/         penjelasan + idor-cheatsheet.md
payloads/     set exploit curl
templates, static/   UI neon
```

## ⚠️ Warning
- Lab edukasi lokal/Docker saja — jangan di-deploy publik. Semua data & flag dummy.