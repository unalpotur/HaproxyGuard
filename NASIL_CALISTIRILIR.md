# HAProxy Guard — Nasıl Çalıştırılır

## Ön Gereksinimler

| Araç | Minimum Sürüm | Kontrol |
|------|-------------|---------|
| Docker | 24+ | `docker --version` |
| Docker Compose | v2+ | `docker compose version` |
| Python | 3.11+ | `python3 --version` |
| Node.js | 20+ | `node --version` |

---

## Senaryo 1: Docker Compose ile Tam Kurulum (Önerilen)

En kolay yol. Her şey tek komutla ayağa kalkar — PostgreSQL, API, nginx + React UI.

```bash
# Proje dizinine git
cd HaproxyGuard

# Opsiyonel: Admin kullanıcısı oluşturmak için .env dosyası hazırla
echo "HG_ADMIN_KEY=my-secret-admin-key" > .env

# Tüm servisleri build et ve başlat (postgres + api + web)
docker compose up --build -d

# Logları izle
docker compose logs -f

# Durumu kontrol et
docker compose ps
```

Açılan adresler:

| Servis | Adres |
|--------|-------|
| **Web UI** | http://localhost:8080 |
| **API (doğrudan)** | http://localhost:8000 |
| **API dökümantasyonu** | http://localhost:8000/docs |

### Durdurmak / Temizlemek

```bash
docker compose down          # Konteynerleri durdur
docker compose down -v       # + Veritabanı verisini de sil
```

### Admin RBAC Aktif Etmek

```bash
# .env dosyasına HG_ADMIN_KEY ekleyip yeniden başlat:
echo "HG_ADMIN_KEY=my-secret-admin-key" > .env
docker compose down && docker compose up --build -d
```

Artık tüm API isteklerinde `X-API-Key: my-secret-admin-key` header'ı gerekir.
UI'da admin kullanıcısı ekleyip viewer/operator rolleri oluşturabilirsin.

### AI Assistant Aktif Etmek

```bash
# .env dosyasına Anthropic API key ekle:
echo "ANTHROPIC_API_KEY=sk-ant-..." >> .env
docker compose down && docker compose up -d
```

API key yoksa assistant heuristic modda çalışır (temel analiz yapar).

---

## Senaryo 2: Development Modu (Hot Reload)

Backend ve frontend'i ayrı ayrı çalıştır. Kod değişiklikleri anında yansır.

### 2a — Backend (FastAPI)

```bash
cd HaproxyGuard/backend

# Sanal ortam kur (ilk defa)
python3 -m venv .venv
.venv/bin/pip install -e ".[dev]"

# Alternatif: Sadece güncelleme
.venv/bin/pip install -e ".[dev]"

# Veritabanı migration
.venv/bin/alembic upgrade head

# Başlat (http://localhost:8000)
.venv/bin/uvicorn app.main:app --reload --port 8000
```

Varsayılan olarak SQLite kullanır (`backend/haproxy_guard.db`).
PostgreSQL ile çalışmak için:

```bash
DATABASE_URL="postgresql+asyncpg://guard:guard@localhost:5432/haproxyguard" \
  .venv/bin/uvicorn app.main:app --reload
```

### 2b — Frontend (React + Vite)

```bash
cd HaproxyGuard/frontend

# Bağımlılıkları kur (ilk defa)
npm install

# Dev sunucuyu başlat (http://localhost:5173)
npm run dev
```

Frontend otomatik olarak `/api` isteklerini `localhost:8000`'e yönlendirir.
Alternatif API adresi için: `HG_API_URL=http://başka-host:8000 npm run dev`

### 2c — Testler

```bash
cd HaproxyGuard/backend

# Tüm testleri çalıştır
.venv/bin/pytest -v

# Sadece belirli bir modül
.venv/bin/pytest tests/test_analyzer.py -v
```

---

## Senaryo 3: Canlı Dashboard + Dev HAProxy

Gerçek HAProxy metriklerini canlı görmek için:

```bash
# 1. Dev HAProxy + echo backends başlat
cd HaproxyGuard
docker compose --profile dev up -d haproxy echo1 echo2

# 2. Biraz trafik üret
curl http://localhost:18080/
curl http://localhost:18080/
curl http://localhost:18080/

# 3. Backend'i stats socket'e bağlı başlat
cd backend
HAPROXY_STATS_ADDR=127.0.0.1:9999 .venv/bin/uvicorn app.main:app --reload
```

Frontend'de **Dashboard** sekmesine git — canlı metrikleri, bağlantı sayılarını,
hata oranlarını ve 60 saniyelik sparkline grafikleri göreceksin.

---

## Senaryo 4: HAProxy'yi Docker ile Yönetme

Production HAProxy'sini Docker container olarak çalıştırıp Guard üzerinden yönet:

### 4a — HAProxy konteynerini başlat

```bash
cd HaproxyGuard

# Config dosyasını oluştur (yoksa)
sudo mkdir -p /etc/haproxy
sudo tee /etc/haproxy/haproxy.cfg << 'EOF'
global
    log stdout format raw local0
    stats socket ipv4@0.0.0.0:9999 level admin
    stats timeout 30s

defaults
    mode http
    timeout connect 5s
    timeout client 30s
    timeout server 30s

frontend web
    bind *:80
    default_backend app

backend app
    server app1 10.0.0.1:8080 check
EOF

# Production profilinde HAProxy başlat
HG_HAPROXY_HTTP=8080 HG_HAPROXY_STATS=9999 \
  docker compose --profile prod up -d haproxy-prod
```

### 4b — Agent kurulumu

```bash
# Agent dosyalarını kopyala
sudo mkdir -p /opt/haproxy-guard
sudo cp scripts/haproxy_guard_agent.py /opt/haproxy-guard/
sudo cp scripts/haproxy-guard-agent.env.example /etc/haproxy-guard-agent.env

# Konfigürasyonu düzenle
sudo nano /etc/haproxy-guard-agent.env
```

`.env` içeriği (Docker modu):

```ini
GUARD_URL=http://localhost:8000
NODE_ID=node_xxxxxxxxxx          # Guard UI → Cluster → Enroll'tan al
NODE_TOKEN=xxxxxxxxxx            # Enrollment sırasında bir kere gösterilir

MANAGE_MODE=docker
CONTAINER_NAME=haproxy-prod
CONTAINER_CFG_PATH=/usr/local/etc/haproxy/haproxy.cfg
HAPROXY_CFG=/etc/haproxy/haproxy.cfg
```

Systemd servisi olarak çalıştır:

```bash
sudo cp scripts/haproxy-guard-agent.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now haproxy-guard-agent
sudo journalctl -u haproxy-guard-agent -f   # logları izle
```

Veya direkt komut satırından test et:

```bash
cd HaproxyGuard
sudo python3 scripts/haproxy_guard_agent.py
```

### 4c — Deploy akışı

```
Guard UI (Cluster → Deploy)  →  control plane'e "desired config" kaydedilir
         Agent heartbeat      →  control plane "desired_config" ile yanıtlar
         Agent: haproxy -c     →  validation başarılı mı?
         Agent: yaz + reload   →  docker cp + docker kill -s HUP
         Sonraki heartbeat     →  control plane deployment'ı "applied" işaretler
```

---

## Hızlı Referans

```bash
# Tüm platform (production benzeri)
docker compose up --build -d

# Geliştirme (hot reload)
cd backend && .venv/bin/uvicorn app.main:app --reload
cd frontend && npm run dev

# Dev HAProxy ile canlı dashboard testi
docker compose --profile dev up -d haproxy echo1 echo2
HAPROXY_STATS_ADDR=127.0.0.1:9999 .venv/bin/uvicorn app.main:app --reload

# Backend testleri
cd backend && .venv/bin/pytest -v

# Production HAProxy yönetimi
docker compose --profile prod up -d haproxy-prod
sudo python3 scripts/haproxy_guard_agent.py
```

## Sorun Giderme

| Sorun | Çözüm |
|-------|-------|
| `docker compose up` başarısız | `docker compose build --no-cache` ile temiz build |
| Backend PostgreSQL'e bağlanamıyor | `docker compose ps` ile db servisinin healthy olduğunu kontrol et |
| Frontend boş sayfa gösteriyor | `docker compose logs web` - nginx config'i kontrol et |
| `HAPROXY_STATS_ADDR` bağlantı hatası | Stats socket'in IP:port olarak erişilebilir olduğunu kontrol et |
| Dashboard "disconnected" | Backend'in `HAPROXY_STATS_ADDR` ile başlatıldığından emin ol |
| Agent heartbeat hatası | GUARD_URL, NODE_ID, NODE_TOKEN doğruluğunu kontrol et |
| WS auth hatası (`401`) | RBAC aktifse `?token=...` query param'ı ile bağlan |
| Rate limit (429) | Auth endpoint'leri 5/dk, genel 200/dk — bekle ve tekrar dene |
