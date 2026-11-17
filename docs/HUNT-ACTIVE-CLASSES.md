# HUNT — Active Classes Playbook (agent guidance)

Panduan untuk AGENT (LLM) saat menguji kelas kerentanan yang **tidak
bisa** dijadikan tool deterministik: butuh state, kredensial, timing,
atau penilaian konteks. Pola kerjanya: agent membaca playbook ini +
contoh di bawah, menalar pada target BERIZIN, dan menghasilkan bukti —
temuan tetap wajib lewat kontrak `findings.json` + `verify_gate`
("no proof, no report" tetap berlaku).

## Aturan wajib (tidak bisa dinegosiasikan)

1. Hanya target berizin (milik sendiri / written permission / lab).
2. **Default LAB** — semua probe state-changing wajib `--lab / LAB=1`
   (pattern fail-closed `rate_limit_validator`); tier0 orchestrator
   tidak pernah menjalankan kelas ini.
3. NEVER-LIST tetap: DoS, persistence/backdoor, worm, ransomware-sim,
   mass exfiltration — ditolak di flag apapun.
4. Bounded: jumlah request minimal, satu payload benign, hentikan saat
   endpoint mati.
5. Buktikan dulu, laporkan kemudian: temuan tanpa PoC reproducible =
   tetap LEAD, bukan klaim.

## 1. File Upload (RCE/XSS via upload) — lab-only

Yang dicari: validasi server-side lemah (extension/MIME/magic bytes),
path simpan yang dieksekusi, nama file tak dirandom.

Contoh progresi (urut benign → agresif):
```http
POST /upload HTTP/1.1
Content-Type: multipart/form-data; boundary=sec

--sec
Content-Disposition: form-data; name="f"; filename="notes.txt"
Content-Type: text/plain

benign-content-0192837
--sec--
```
Lalu ganti: `notes.php` / `notes.svg` (payload `<svg onload=...>`) /
`notes.phtml`; coba double-extension `notes.jpg.php`; coba content-type
spoof (gambar dgn isi PHP). **Bukti**: file yang diupload bisa diakses
dan DIEKSEKUSI/dirender (ambil URL + respons). Inventori statik pakai
`skills/upload_surface_check.py` (read-only).

## 2. Race Condition (double-spend / limit bypass) — lab-only

Yang dicari: operasi yang harusnya atomic tapi dicek-then-act (saldo,
redeem code, vote, transfer limit).

Pola: kirim N request IDENTIK hampir bersamaan (thread pool 10-20,
satu payload, endpoint yang sama). Bandingkan hasil agregat:
`saldo -N` tapi `balance terpakai 1x` = bukti.
```python
# pola: kirim bersamaan (bukan berurutan) — N kecil, lab saja
from concurrent.futures import ThreadPoolExecutor
with ThreadPoolExecutor(20) as ex:
    results = list(ex.map(lambda _: http_post_identical(), range(20)))
```
**Bukti**: respons yang menyatakan sukses > 1x untuk objek yang
harusnya sekali. Endpoint harus milik akun TEST, bukan user lain.

## 3. MFA / 2FA bypass — lab-only, akun test sendiri

7 pola umum: MFA tak dipaksa di endpoint sensitif; OTP bruteforce
(tanpa rate limit); response-tampering (`"success": false` di-request
body ulang dgn true); skip-flow (langsung POST step-3 URL); OTP statis/
ter-prediksi; reset-password langsung logout MFA; remember-device
token dapat direuse lintas akun. **Bukti**: alur lengkap
login → bypass → akses data, direkam request-by-request.

## 4. Account Takeover / Forgot-password — lab-only

Pola: reset link memakai Host header (lihat `host_header_abuse_check`
→ lanjut manual dgn canary host di email test); token tak expire / tak
terikat user (test: token user A dipakai untuk user B); enumerasi
(response "email terkirim" vs "email tidak ada"); OTP lemah.
`docs/disclosed` style: selalu uji pakai 2 akun test (attacker/victim).

## 5. Business Logic — LLM-guided (tidak bisa otomatis)

Metode: (1) pahami alur normal dulu (beli → bayar → terima);
(2) daftar invariant yang HARUSNYA benar (jumlah = harga × qty; total
>= 0; currency konsisten; role di server); (3) uji tiap invariant
dengan pelanggaran benign (qty -1, harga 0, tukar urutan step, replay
step dengan parameter akun lain). **Bukti**: transaksi yang melanggar
invariant, direkam lengkap.

## 6. Captcha / Rate limit — ukur, bukan serang

`skills/rate_limit_validator.py` (active-probe, --lab): ukur apakah
limit ada (429/lockout/delay). Captcha bypass klien-side = analis
manual (captcha di-check server? token dipakai ulang? parameter
diteruskan?).

## 7. XXE / LDAP injection — probe differensial otomatis

`skills/xxe_probe_check.py` dan `skills/ldap_probe_check.py`
(active-probe, --lab): differensial benign vs payload tunggal → LEAD.
Ekstraksi penuh (file read, attribute dump) = jalur exploit-tier.

## Penutup

Setiap temuan dari playbook ini masuk `findings.json` seperti skill
lain: severity dari dampak terbukti, confidence jujur, `lab_only: true`
untuk yang hanya direproduksi di lab. Tool deterministik tetap lapis
pertama — playbook ini adalah lapisan penalaran di atasnya, bukan
pengganti.
