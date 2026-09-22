# IDOR — cheat-sheet audit cepat

## Deteksi (paling umum di BBP)
1. Login dua akun (A & B). Ambil object milik B, akses pakai sesi A.
2. Ganti parameter object: `id`, `uid`, `user_id`, `profile_id`, `order_id`, `invoice`, `uuid`, `token`, referensi di body/JSON/GraphQL query.
3. Perhatian endpoint : `/users/<id>`, `/download/<file>`, `/export`, `/billing`, `/pdf/<id>`, GraphQL `(id: ...)`.

## Variasi yang sering menghasilkan payout tinggi
- Horizontal (data user lain) — PII/transaksi → impact high.
- Vertical (endpoint admin dipanggil user biasa).
- Mass-assignment / batch: `ids[]`, `{"records":[...]}`.
- IDOR **pada aksi tulis** (update email/password, transfer, refund) → ATO.
- IDOR via referensi tidak langsung: `?userId=`, `cotask`, share-link merujuk id.
- IDOR pada file/PDF/export yang mencantumkan data orang lain.
- UUID v1/predictable, atau id numerik sequential yang mudah ditebak.

## Checklist object-level auth (per endpoint)
- [ ] Apakah endpoint men-take id dari input TANPA binding ke sesi?
- [ ] Apakah role division sudah diterapkan (admin vs user)?
- [ ] Apakah response membuang field sensitif untuk akun lain?
- [ ] Apakah aksi **tulis** (update/delete/transfer) memvalidasi ownership?

## Mitigasi yang benar
- Object-level authorization di tiap endpoint (bukan hanya login check).
- Pengambilan identitas dari sesi / cookie, jangan dari body.
- Solusi modern: data entitas di-scope ke tenant/user (mis. `WHERE id=? AND user_id=?`).
- Limit & rate-limit export/batch + audit log.

## Referensi
- OWASP: IDOR / Broken Object Level Authorization (BOLA) di OWASP API Top-10.
- Bug bounty: IDOR adalah kategori #1 di hampir semua program besar (Meta, Shopify, DoD).