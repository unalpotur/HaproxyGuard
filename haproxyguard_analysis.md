# HAProxy Guard — Proje Analizi

## Genel Bakış

**HAProxy Guard**, HAProxy konfigürasyonlarını yönetmek, görselleştirmek, analiz etmek ve güvence altına almak için geliştirilmiş açık kaynaklı bir web platformudur. Proje, **monorepo** mimarisinde organize edilmiş olup oldukça kapsamlı bir özellik seti sunmaktadır.

---

## Teknoloji Stack

| Katman | Teknoloji |
|---|---|
| **Backend** | FastAPI, Python 3.11+, Pydantic v2 |
| **Frontend** | React + TypeScript, Vite |
| **Stil** | Tailwind CSS |
| **Veritabanı** | PostgreSQL (henüz aktif değil, yorumda) |
| **Deployment** | Docker, Docker Compose, Nginx |
| **AI** | Anthropic API (opsiyonel) |
| **Test** | pytest, pytest-asyncio, httpx |

---

## Proje Yapısı

```
HaproxyGuard/
├── backend/
│   ├── app/
│   │   ├── main.py            # FastAPI uygulaması (515 satır, tüm endpointler)
│   │   ├── parser/            # HAProxy cfg → JSON parser
│   │   ├── analyzer/          # Kural tabanlı analiz motoru
│   │   ├── autofix/           # Otomatik düzeltme + rollback
│   │   ├── sslmgr/            # SSL sertifika yönetimi
│   │   ├── security/          # DDoS, rate-limit, geo-block
│   │   ├── assistant/         # AI destekli asistan
│   │   ├── cluster/           # Multi-node agent yönetimi
│   │   ├── alerts/            # Alerting sistemi
│   │   ├── authz/             # RBAC + Audit log
│   │   ├── versions/          # Config versiyonlama & diff
│   │   └── metrics/           # Stats socket + WebSocket streaming
│   └── tests/                 # 14 test dosyası
├── frontend/
│   └── src/
│       ├── App.tsx            # Ana uygulama (10 tab)
│       ├── Dashboard.tsx      # Gerçek zamanlı metrik dashboard
│       ├── TopologyView.tsx   # Topoloji görselleştirme
│       ├── FindingsPanel.tsx  # Analiz bulguları
│       ├── FixBar.tsx         # Otomatik düzeltme UI
│       ├── SslPanel.tsx       # SSL yönetimi
│       ├── SecurityPanel.tsx  # Güvenlik merkezi
│       ├── AssistantPanel.tsx # AI asistan
│       ├── ClusterPanel.tsx   # Cluster yönetimi
│       ├── AlertsPanel.tsx    # Alert sistemi
│       ├── AuditPanel.tsx     # Audit log
│       └── VersionsPanel.tsx  # Versiyon yönetimi
└── docker/
    ├── backend.Dockerfile
    ├── frontend.Dockerfile
    ├── nginx.conf
    └── dev-haproxy.cfg
```

---

## Backend API Endpointleri

### Core
| Endpoint | Açıklama |
|---|---|
| `GET /api/health` | Sağlık kontrolü |
| `GET /api/local-config` | Sunucudaki haproxy.cfg'yi oku |
| `POST /api/parse` | Config → JSON parse |
| `POST /api/analyze` | Kural tabanlı analiz |
| `POST /api/topology` | React Flow için graph verisi |

### Auto Fix Engine
| Endpoint | Açıklama |
|---|---|
| `POST /api/fix/preview` | Dry-run düzeltme önizleme |
| `POST /api/fix/apply` | Düzeltmeyi uygula + rollback noktası |
| `POST /api/fix/rollback` | Önceki versiyona dön |

### SSL Manager
| Endpoint | Açıklama |
|---|---|
| `POST /api/ssl/analyze-cert` | PEM bundle analizi |
| `POST /api/ssl/scan` | Config'deki sertifika taraması |

### Security Center
| Endpoint | Açıklama |
|---|---|
| `GET /api/security/catalog` | Kontroller ve preset listesi |
| `POST /api/security/generate` | Hardening snippet üret |
| `POST /api/security/posture` | Mevcut güvenlik durumu analizi |

### AI Assistant
| Endpoint | Açıklama |
|---|---|
| `GET /api/assistant/status` | LLM kullanılabilirliği |
| `POST /api/assistant/analyze` | Root cause analiz + risk skoru |

### Config Versioning
| Endpoint | Açıklama |
|---|---|
| `GET /api/versions` | Versiyon listesi |
| `POST /api/versions` | Versiyon kaydet |
| `GET /api/versions/diff` | İki versiyon arası diff |
| `GET /api/versions/{id}` | Versiyon detayı |
| `POST /api/versions/{id}/restore` | Versiyona geri dön |

### RBAC & Audit
| Endpoint | Açıklama |
|---|---|
| `GET /api/auth/whoami` | Mevcut kullanıcı |
| `GET/POST/DELETE /api/auth/principals` | Kullanıcı yönetimi |
| `GET /api/audit` | Audit log |

### Alerting
| Endpoint | Açıklama |
|---|---|
| `POST /api/alerts/evaluate` | Alert değerlendirme |
| `POST /api/alerts/dispatch` | Alert gönder |
| `GET/POST/DELETE /api/alerts/channels` | Kanal yönetimi |

### Multi-Node Cluster
| Endpoint | Açıklama |
|---|---|
| `POST /api/cluster/nodes` | Node kayıt |
| `GET /api/cluster/nodes` | Node listesi |
| `GET /api/cluster/overview` | Cluster genel bakış |
| `POST /api/cluster/deploy` | Config deploy |
| `POST /api/cluster/nodes/{id}/rollback` | Node rollback |
| `POST /api/agent/{id}/heartbeat` | Agent heartbeat |

### Metrics
| Endpoint | Açıklama |
|---|---|
| `GET /api/metrics/snapshot` | Anlık metrik |
| `GET /api/metrics/history` | Metrik geçmişi |
| `GET /api/metrics/info` | HAProxy bilgisi |
| `WS /api/ws/metrics` | Gerçek zamanlı WebSocket akışı |

---

## Mevcut Durum (Phase Tamamlanma)

| Phase | Konu | Durum |
|---|---|---|
| 0 | Monorepo Foundation | ✅ Tamamlandı |
| 1 | HAProxy Parser | ✅ Tamamlandı |
| 2 | Topology View | ✅ Tamamlandı |
| 3 | Dashboard (Metrics) | ✅ Tamamlandı |
| 4 | Configuration Analyzer | ✅ Tamamlandı |
| 5 | Auto Fix Engine | ✅ Tamamlandı |
| 5.5 | Config Versioning & Diff | ✅ Tamamlandı |
| 6 | SSL Manager | ✅ Tamamlandı |
| 7 | Security Center | ✅ Tamamlandı |
| 7.5 | Log Analizi | ❓ Belirsiz (alerts modülüyle kısmen?) |
| 8 | AI Assistant | ✅ Tamamlandı (Anthropic API) |
| 9 | Multi-Node Cluster | ✅ Tamamlandı |
| 9.5 | Alerting | ✅ Tamamlandı |

---

## Dikkat Çeken Güçlü Yönler

1. **Kapsamlı test coverage** — 14 ayrı test dosyası (parser, analyzer, autofix, cluster, ssl, security, authz, alerts, versions, metrics, api, agent, assistant)
2. **RBAC sistemi** — 3 rol (viewer/operator/admin), token tabanlı kimlik doğrulama, audit log
3. **Rollback desteği** — Hem fix engine hem de cluster deploylar için
4. **WebSocket streaming** — Dashboard için gerçek zamanlı metrik akışı
5. **Multi-node agent mimarisi** — HAProxy cluster'larını merkezi yönetme
6. **AI entegrasyonu** — Anthropic API opsiyonel; yoksa heuristik mod
7. **Docker'da haproxy binary** — `haproxy -c` validation gerçek binary üzerinden

---

## Dikkat Çeken Zayıf Yönler / Eksikler

1. **PostgreSQL henüz entegre değil** — `docker-compose.yml`'de yorum satırında; tüm veriler in-memory. Uygulama restart'ta tüm versiyon/audit/cluster kaydı siliniyor.
2. **Log Analizi (Phase 7.5)** — HAProxy access loglarının parse edilmesi/analizi yok veya eksik.
3. **Frontend tasarım** — App.css mevcut ama görsel zenginlik (dark mode, animasyon vs.) yeterli olmayabilir.
4. **Güvenlik yüzeyi** — `HG_LOCAL_CONFIG` ile dosya okuma var; path traversal koruması var ama env'den geldiği için prod'da dikkat.
5. **Rate limiting yok** — API'nin kendisi için rate limiting mekanizması yok.
6. **Config şifreleme yok** — Sertifika yolları/auth satırları sanitize için roadmap'te var ama implement edilmemiş olabilir.

---

## Hızlı Başlangıç Özeti

```bash
# Tüm platformu başlat
docker compose up --build
# UI: http://localhost:8080
# API: http://localhost:8000

# Dev modu (HAProxy + echo backends)
docker compose --profile dev up -d haproxy echo1 echo2
HAPROXY_STATS_ADDR=127.0.0.1:9999 uvicorn app.main:app --reload

# Backend testleri
cd backend && .venv/bin/pytest
```
