# HAProxy Guard Roadmap

## Phase 0 – Monorepo Foundation
Structure:
- backend/
- frontend/
- docs/
- examples/
- docker/
- scripts/
- tests/

### Codex Prompt
Create a production-ready monorepo structure for HAProxy Guard with FastAPI, React, PostgreSQL, Alembic, Docker and CI.

---

## Phase 1 – HAProxy Parser

Goal:
Parse HAProxy configuration into structured JSON.

### Claude Prompt
Design a complete HAProxy configuration parser in Python supporting HAProxy 2.x and 3.x.

---

## Phase 2 – Topology Visualization

Goal:
Visualize Frontends, ACLs, Backends and Servers using React Flow.

### Codex Prompt
Create a React Flow based topology visualization from parser JSON.

---

## Phase 3 – Dashboard

Goal:
Collect metrics from Runtime API and Stats Socket.

### Claude Prompt
Design a metrics collection service with WebSocket streaming and historical storage.

---

## Phase 4 – Configuration Analyzer

Rules:
- Unused backend
- Duplicate bind
- Missing health checks
- Weak TLS
- Dead routes

### Claude Prompt
Create 100 configuration analysis rules with severity, detection logic and fixes.

---

## Phase 5 – Auto Fix Engine

Goal:
Generate safe patches and rollback support.

### Codex Prompt
Implement a patch engine with dry-run mode and rollback support.

---

## Phase 6 – SSL Manager

Features:
- X509 parsing
- Expiration alerts
- Cipher analysis

### Claude Prompt
Design an SSL management module for deployment and monitoring.

---

## Phase 7 – Security Center

Features:
- DDoS protection
- Rate limiting
- Geo blocking
- Admin protection

### Claude Prompt
Design a complete HAProxy security center with presets.

---

## Phase 8 – AI Assistant

Inputs:
- Configurations
- Logs
- Runtime metrics

Outputs:
- Root cause analysis
- Risk scores
- Recommended fixes

### Claude Prompt
Design an AI-powered troubleshooting assistant for HAProxy.

---

## Phase 9 – Multi-Node Cluster

Goal:
Manage hundreds of HAProxy instances from one dashboard.

### Codex Prompt
Design a scalable agent architecture with secure communication and remote deployment.

---

## Geliştirme Önerileri (Claude — 2026-06-11)

### Mimari / Süreç
- **Parser'ı bağımsız bir Python paketi olarak tasarla** (`haproxy-guard-parser`): hem API hem CLI hem de gelecekteki agent'lar aynı paketi kullanır; PyPI'da ayrıca yayınlanabilir.
- **Round-trip garantisi**: parser her direktifi ham haliyle (`raw`) saklasın ki Auto Fix Engine config'i yeniden üretirken yorumlar ve bilinmeyen direktifler kaybolmasın. (İlk implementasyonda uygulandı.)
- **`haproxy -c` ile entegrasyon testi**: validation pipeline'da kendi parser'ımıza güvenmek yerine gerçek HAProxy binary'siyle (Docker imajı üzerinden) doğrulama yap.
- **Audit log + RBAC'i erken ekle**: config değiştiren bir araçta kim-ne-zaman-neyi değiştirdi kaydı sonradan eklenmesi en zor özelliktir. Phase 5'ten önce temelini at.

### Eksik Fazlar
- **Phase 5.5 – Config Versioning & Diff**: her apply öncesi git tabanlı sürümleme; UI'da diff görünümü; tek tıkla eski sürüme dönüş. Rollback'in doğal altyapısı.
- **Phase 7.5 – Log Analizi**: HAProxy access loglarını (syslog/dosya) parse edip hata oranı, yavaş istek ve saldırı paterni çıkarımı — Phase 8 AI asistanının en değerli girdisi.
- **Phase 9.5 – Alerting**: sertifika süresi, backend down, hata oranı eşiği için Slack/e-posta/webhook bildirimleri.

### Teknik Detaylar
- Runtime API (stats socket) erişimi için **read-only / read-write ayrımı** yap; dashboard'un salt-okur sokete bağlanması yeterli.
- Analyzer kurallarını **veri + fonksiyon olarak kayıtlı (registry) tasarla** ki topluluk kural ekleyebilsin (ilk implementasyonda `@rule` dekoratörüyle uygulandı).
- AI asistanı için config'leri modele gönderirken **sertifika yolları ve auth satırlarını maskeleyen bir sanitizer** ekle.
