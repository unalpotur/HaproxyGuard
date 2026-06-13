# HAProxy Guard — Eksik Analizi

> Tarih: 2026-06-12
> Test Durumu: 130 passed, 0 failed

## Genel Durum

Proje **oldukça olgun** durumda. Roadmap'teki 10 fazın 9'u tamamlanmış, backend'de 130 test geçiyor, frontend bileşenleri stub değil gerçek implementasyon. Ancak aşağıdaki eksikler tespit edildi.

---

## 🔴 Kritik Eksikler

### 1. `LICENSE` dosyası yok

README Apache 2.0 diyor ama kök dizinde `LICENSE` dosyası bulunmuyor. Açık kaynak projesi için zorunlu.

**Yapılacak:** Kök dizine Apache 2.0 `LICENSE` dosyası ekle.

---

### 2. CI/CD pipeline tamamen yok

GitHub Actions, GitLab CI veya herhangi bir CI konfigürasyonu yok. PR check, otomatik test, Docker image build/push pipeline'ı kurulmamış.

**Yapılacak:**
- `.github/workflows/ci.yml` oluştur
- PR açıldığında: backend test + frontend build
- `main` branch'e push'ta: Docker image build + push

---

### 3. WebSocket endpoint'inde authentication yok

`/api/ws/metrics` endpoint'i herkese açık. RBAC sistemi varken WebSocket'e auth eklenmemiş.

```python
# backend/app/main.py:525 — hiçbir auth kontrolü yok
@app.websocket("/api/ws/metrics")
async def metrics_ws(ws: WebSocket) -> None:
```

**Yapılacak:**
- WebSocket bağlantısında `token` query param veya `Authorization` header ile auth ekle
- En azından `viewer` rolü kontrolü yap

---

### 4. API kendisi için rate limiting yok

Güvenlik merkezi HAProxy için rate limiting üretiyor ama FastAPI'nin kendisinde brute-force ve DoS koruması yok.

**Yapılacak:**
- `slowapi` veya `fastapi-limiter` ekle
- IP başına istek limiti koy (örn. 100 req/dk)
- Admin endpoint'leri için daha sıkı limit

---

## 🟡 Orta Önemli Eksikler

### 5. `docs/` dizini boş

Roadmap'te `docs/` var ama içi tamamen boş.

**Yapılacak:**
- API dokümantasyonu (FastAPI'nin auto-generated `/docs`'u zaten var, ek olarak mimari ve deployment guide)
- Mimari diyagramı (Mermaid veya resim)
- Deployment guide (production checklist)

---

### 6. `.env.example` dosyası yok

README environment variable'ları belgeliyor ama örnek `.env` dosyası yok.

**Yapılacak:**
- Kök dizine `.env.example` oluştur
- Tüm environment variable'ları yorumlarıyla birlikte ekle:

```
ANTHROPIC_API_KEY=  # AI asistan için (opsiyonel)
HG_ADMIN_KEY=       # Admin kullanıcısı oluşturur (opsiyonel)
HAPROXY_STATS_ADDR= # Metrics için stats socket adresi
HG_WEB_PORT=8080
HG_API_PORT=8000
```

---

### 7. Frontend'de `AlertsPanel`'e `logs` prop'u geçilmiyor

`App.tsx`'te `AlertsPanel` sadece `config` alıyor, log analizi özelliği UI'da kullanılamaz durumda.

```tsx
// App.tsx:135 — logs prop eksik
<AlertsPanel config={config} />
// Oysa AlertsPanel: function AlertsPanel({ config, logs }: { config: string; logs?: string })
```

**Yapılacak:**
- App.tsx'e bir `logs` state'i ekle (textarea)
- AlertsPanel'e `logs={logs}` prop'unu geç

---

### 8. Structured logging yok

Backend'de Python `logging` modülü yerine ya `print` ya da Pydantic model dump kullanılıyor. Production için uygun değil.

**Yapılacak:**
- `logging` modülü ile structured JSON logger kur
- Request/response loglaması ekle (middleware)
- Log seviyelerini environment variable ile kontrol et (`LOG_LEVEL`)

---

### 9. Versions ve Audit endpoint'lerinde pagination eksik

`/api/versions` liste dönerken `limit` parametresi yok. Audit için `limit` var ama `offset` yok. Çok kayıtlı durumda performans problemi.

**Yapılacak:**
- `/api/versions` ve `/api/audit` endpoint'lerine `offset` parametresi ekle
- Response'a `total` count ekle

---

### 10. Frontend testleri yok

Backend'de 130 test varken frontend'de hiç test yok.

**Yapılacak:**
- Vitest + React Testing Library kur
- En azından `api.ts` fonksiyonları ve ana bileşenlerin render testlerini ekle

---

## 🟢 İyileştirme Önerileri

### 11. `.gitignore` eksiklikleri

Mevcut `.gitignore` temel seviyede. Eksik olanlar:
- `haproxy_guard.db` (SQLite DB dosyası)
- `.vscode/`, `*.swp`, `*.swo` gibi IDE/editör dosyaları

**Yapılacak:** `.gitignore`'a eksik kalıpları ekle.

---

### 12. Phase 7.5 Log Analizi sadece access log destekliyor

`assistant/logs.py` sadece HAProxy HTTP log formatını (`option httplog`) parse ediyor. Syslog entegrasyonu, error log analizi, atak pattern çıkarımı yok.

**Yapılacak:**
- Syslog format desteği ekle
- HTTP status kodlarına göre anomali skorlaması
- Tekrarlayan IP'lerden gelen istek pattern'i analizi

---

### 13. Dark mode / tema desteği yok

`App.css` mevcut ama sadece light tema. Modern bir UI için dark mode beklenir.

**Yapılacak:**
- CSS custom properties ile tema değişkenleri tanımla
- `prefers-color-scheme` media query veya toggle switch ekle

---

### 14. `scripts/haproxy_guard_agent.py` için test yok

Agent script'i test edilmemiş. `haproxy -c` validation, heartbeat, config apply akışı test edilmeli.

**Yapılacak:**
- `test_agent.py`'ye `decide()`, `validate()`, `config_hash()` için unit test ekle
- Mock heartbeat endpoint ile integration test

---

### 15. Environment variable doğrulaması yok

`DATABASE_URL`, `HG_ADMIN_KEY`, `HAPROXY_STATS_ADDR` gibi değişkenlerin geçersiz değerleri sessizce kabul ediliyor.

**Yapılacak:**
- Startup'ta kritik env var'ları doğrula
- Hatalı değerler için anlamlı hata mesajı vererek uygulamayı durdur

---

### 16. Docker imajlarında healthcheck eksiklikleri

`api` servisi için healthcheck var ama `web` (nginx) servisi için yok.

**Yapılacak:**
- `web` servisine healthcheck ekle (`curl localhost:80` veya benzeri)
- `api` healthcheck'ine DB bağlantı kontrolü ekle

---

## Özet Tablo

| # | Eksik | Önem | Tahmini Efor |
|---|-------|------|-------------|
| 1 | LICENSE dosyası | 🔴 Kritik | 5 dk |
| 2 | CI/CD pipeline | 🔴 Kritik | 2-4 saat |
| 3 | WS auth | 🔴 Kritik | 30 dk |
| 4 | API rate limiting | 🔴 Kritik | 1-2 saat |
| 5 | docs/ boş | 🟡 Orta | 2-4 saat |
| 6 | .env.example | 🟡 Orta | 10 dk |
| 7 | AlertsPanel logs prop | 🟡 Orta | 15 dk |
| 8 | Structured logging | 🟡 Orta | 1-2 saat |
| 9 | Pagination | 🟡 Orta | 1 saat |
| 10 | Frontend testleri | 🟡 Orta | 3-6 saat |
| 11 | .gitignore eksikleri | 🟢 Düşük | 5 dk |
| 12 | Log analizi derinliği | 🟢 Düşük | 3-5 saat |
| 13 | Dark mode | 🟢 Düşük | 2-4 saat |
| 14 | Agent testleri | 🟢 Düşük | 1-2 saat |
| 15 | Env var doğrulama | 🟢 Düşük | 30 dk |
| 16 | Docker healthcheck | 🟢 Düşük | 15 dk |

---

## Önerilen Uygulama Sırası

1. **LICENSE dosyası** (5 dk)
2. **`.env.example`** (10 dk)
3. **`.gitignore` eksikleri** (5 dk)
4. **AlertsPanel logs prop** (15 dk)
5. **WS auth** (30 dk)
6. **API rate limiting** (1-2 saat)
7. **Env var doğrulama** (30 dk)
8. **Docker healthcheck** (15 dk)
9. **Structured logging** (1-2 saat)
10. **Pagination** (1 saat)
11. **CI/CD pipeline** (2-4 saat)
12. **docs/** (2-4 saat)
13. Diğer iyileştirmeler
