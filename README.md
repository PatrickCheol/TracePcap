<h1 align="center">TracePcap</h1>

## PatrickCheol 포크 안내

이 저장소는 [NotYuSheng/TracePcap](https://github.com/NotYuSheng/TracePcap)을 기반으로
패킷 상세 분석과 한국어 AI 분석을 추가한 [PatrickCheol/TracePcap](https://github.com/PatrickCheol/TracePcap) 포크입니다.
원본의 범용 PCAP 분석 기능을 유지하면서 **5G NAS 비트 분석**, **실제 패킷 근거를 사용하는 Story/Q&A**,
**ChatGPT OAuth 로그인**, **Apple Silicon 빌드**를 확장했습니다.
원본 저작권 표시와 [MIT 라이선스](LICENSE)를 유지합니다. 아래 영문 소개와 원본 문서 링크도 보존했습니다.

### 이 포크에서 추가·수정한 기능

| 기능 | 동작 |
|---|---|
| **개별 패킷 상세 분석** | `Conversations → 대화 선택 → Packets → 패킷 클릭`으로 원본 프레임을 TShark로 디코딩합니다. 프로토콜 트리·필드 검색·실제 프레임 번호·전체 캡처 바이트를 확인할 수 있습니다. |
| **5G NAS 비트 분석** | 보안 헤더·등록 유형·보안 알고리즘 등의 디코딩 값, 바이트 위치와 길이, 원시 비트, 제공된 비트 마스크를 연결합니다. NAS가 중첩된 NGAP 경로를 자동으로 펼치며, 모든 깊이에 들여쓰기·연결선과 가로 스크롤을 유지합니다. |
| **새 패킷 근거를 사용하는 AI** | Story 생성과 후속 질문에서 원본 캡처의 디코딩 필드를 조회합니다. SUCI 질문에는 식별자 컨테이너·MCC/MNC·보호 방식 등 관련 필드를 우선 제공하고, 패킷 번호·필드 경로·원시 값에 근거해 답변하도록 합니다. 기존 Story에 없던 필드도 후속 질문에서 조회할 수 있습니다. |
| **분석 범위 표시** | Q&A의 `Packet evidence`에서 선택 범위, 디코딩한 프레임·필드 수, 생략된 필드·미검색 프레임·경고와 사용 모델을 확인할 수 있습니다. 부분 분석을 전체 캡처 분석으로 표시하지 않습니다. |
| **한국어 Story/Q&A** | 새로 생성하는 본문·제목·핵심 이벤트·추천 질문과 후속 답변을 한국어로 작성하도록 설정했습니다. 프로토콜명·필드명·주소·원시 값은 보존합니다. 기존 영문 Story는 재생성하면 적용되며, UI 전체 번역은 포함하지 않습니다. |
| **API 키 없는 ChatGPT 로그인** | 공식 Codex app-server를 사용하는 선택적 OAuth 브리지를 추가했습니다. 기본 모델은 `gpt-6-astra`, 추론 강도는 `high`이며 환경변수로 바꿀 수 있습니다. |
| **M3 / ARM64 Docker 빌드** | x64 전용 nDPI 패키지 설치 대신 nDPI를 소스에서 빌드해 Apple Silicon의 ARM64 환경에서도 실행할 수 있도록 수정했습니다. |
| **Story 화면 안정성** | Story 로드 전후 Hook 순서 오류와 집계의 `null` 처리 오류를 수정했습니다. 측정되지 않은 값은 `N/A`로, 실제 측정값 0은 0으로 구분합니다. |

### 빠른 실행 — ChatGPT OAuth

Docker와 Docker Compose를 준비한 뒤 실행합니다.

```bash
git clone https://github.com/PatrickCheol/TracePcap.git
cd TracePcap
cp .env.example .env
docker compose -f docker-compose.yml -f docker-compose.chatgpt.yml up -d --build
```

1. [ChatGPT 연결 페이지](http://localhost:8787)에서 **ChatGPT로 로그인**을 누르고 공식 인증 페이지에서 코드를 입력합니다.
2. [TracePcap](http://localhost)에서 PCAP을 업로드합니다. 포트를 변경했다면 `NGINX_PORT`에 설정한 주소를 사용합니다.
3. 패킷 상세는 **Conversations**, 한국어 분석과 후속 질문은 **Story**에서 확인합니다.

모델을 변경하려면 `.env`에 설정하고 같은 Compose 명령으로 브리지와 백엔드를 다시 생성합니다.
사용 가능한 모델과 한도는 로그인 계정에서 지원하는 범위를 따릅니다.

```dotenv
CHATGPT_MODEL=gpt-6-astra
CHATGPT_REASONING_EFFORT=high
```

```bash
docker compose -f docker-compose.yml -f docker-compose.chatgpt.yml up -d --force-recreate codex-bridge backend
```

로그인 정보는 전용 Docker 볼륨 `chatgpt_auth`에 저장합니다.
패킷 상세 디코딩은 로컬에서 실행되며 AI 로그인이 필요하지 않습니다.
**Story/Q&A 등 AI 기능을 실행하면 선택된 디코딩 필드·원시 필드 바이트·대화 및 탐지 결과가 설정된 LLM으로 전송됩니다.**
ChatGPT OAuth 구성에서는 OpenAI로 전송되므로 인터넷 연결이 필요합니다.
로컬 LLM 구성과 자세한 설정은 아래 영문 안내 및 [ChatGPT 설정 문서](CHATGPT_SETUP.md)를 참고하세요.

### 패킷 해석 범위

암호화된 NAS 본문을 읽으려면 적절한 키와 보안 문맥이 필요합니다. 이 포크가 이를 자동 복호화하거나
NAS MAC의 유효성을 검증하는 것은 아닙니다. 원본 프레임·재조립 데이터·생성 필드를 구분하고,
정확한 마스크나 바이트 순서가 없는 필드의 비트 위치를 추정하지 않습니다.

AI 패킷 근거는 질문과 관련된 범위를 선택해 제공합니다. 현재 예산은 최대 24프레임·400필드·64,000자이며,
후보 검색은 처음 100,000프레임으로 제한됩니다. **선택 범위의 분석 완료는 전체 캡처의 모든 필드를 분석했다는 뜻이 아닙니다.**
실제 제공 범위와 생략 여부는 결과의 메타데이터로 확인할 수 있습니다.
구체적인 동작은 [패킷 상세 분석 문서](docs/features/packet-details.rst), 재현용 합성 캡처는
[테스트 픽스처 안내](test-fixtures/packet-inspector/README.md)를 참고하세요.

---

<p align="center">
  <strong>Self-hosted PCAP analysis tool for black-box network traffic forensics — reconstruct devices, topology, sessions, and threats from captured packets alone, with no prior knowledge of the network.</strong>
</p>

<p align="center">
  <a href="#features">Features</a> •
  <a href="#quick-start">Quick Start</a> •
  <a href="#usage">Usage</a> •
  <a href="#documentation">Documentation</a>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Spring_Boot-6DB33F?style=flat&logo=springboot&logoColor=white" alt="Spring Boot"/>
  <img src="https://img.shields.io/badge/React-61DAFB?style=flat&logo=react&logoColor=black" alt="React"/>
  <img src="https://img.shields.io/badge/PostgreSQL-4169E1?style=flat&logo=postgresql&logoColor=white" alt="PostgreSQL"/>
  <img src="https://img.shields.io/badge/Docker-2496ED?style=flat&logo=docker&logoColor=white" alt="Docker"/>
  <img src="https://img.shields.io/badge/MinIO-C72E49?style=flat&logo=minio&logoColor=white" alt="MinIO"/>
  <img src="https://img.shields.io/badge/Java-21-007396?style=flat&logo=openjdk&logoColor=white" alt="Java 21"/>
</p>

---

**TracePcap** is a self-hosted PCAP analysis workbench for **black-box network analysis** — situations where you work from the **traffic itself**, with no documentation or prior knowledge of the network. Upload one or more packet captures and TracePcap characterises devices, maps topology, reconstructs sessions, detects threats, tracks changes over time, and generates AI-powered narratives — all derived purely from observed traffic. With a local inference server, it runs fully **offline / air-gapped** and keeps packet data on your own infrastructure. The optional ChatGPT login mode described below uses online inference.

This makes it well-suited for:

- **Network audits and third-party assessments** — handed a PCAP with no documentation; build the picture from scratch
- **Incident response & network forensics** — incomplete records; reconstruct what happened from packet evidence
- **Penetration test reconnaissance** — map an unknown or scarcely-documented network from captured traffic
- **Research and education** — explore any capture without needing context about the environment

<div align="center">

![TracePcap Demo](https://raw.githubusercontent.com/NotYuSheng/TracePcap/main/sample-files/TracePcap-Demo.gif)

</div>

## Features

TracePcap's capabilities fall into five pillars. Each links to its full page in the [documentation](https://notyusheng.github.io/TracePcap).

### 🔎 Discover — build an inventory from nothing

| Capability | What it does |
|---|---|
| **Network Visualization** | Interactive topology using Sigma.js (WebGL) + graphology with ForceAtlas2 / ELK layouts, a rich filter panel (IP, port, device type, protocol, risk), fullscreen toggle, and clickable node detail panels |
| **Device Classification** | Automatic device-type inference (Router, Server, IoT, Mobile, Laptop/Desktop) from traffic behaviour and manufacturer data |
| **Subnet Detection & Labelling** | Infer subnet structure from traffic patterns or define CIDRs manually; group observed IPs by subnet across all snapshots |
| **MAC Manufacturer Lookup** | Wireshark OUI database integration for vendor identification from MAC addresses |
| **Node Role Annotation** | Annotate any IP/device with a role label (e.g. "SCADA Controller", "Historian"); AI-suggested from traffic signals, human-confirmable |

### 🔬 Inspect — see exactly what crossed the wire

| Capability | What it does |
|---|---|
| **Conversation Tracking** | Paginated conversation list with advanced filtering (IP, port, protocol, app, risk, custom rules, device type, country, payload pattern), multi-column sorting, column picker, and bulk PCAP export |
| **Session Reconstruction** | TCP/UDP application-layer payload decoding with a hex + ASCII viewer for inspecting raw packet payloads |
| **Packet Inspector** | Click a packet in Conversations to decode its complete original frame, explore protocol fields, and inspect NAS bit masks with byte-linked evidence; see [packet details](docs/features/packet-details.rst) |
| **File Extraction** | HTTP object extraction and raw TCP/UDP stream extraction; automatic MIME type detection; bulk download |
| **Timeline Analysis** | Chronological traffic visualization with configurable time granularity and protocol breakdown |

### 🛡️ Detect — surface threats and anomalies

| Capability | What it does |
|---|---|
| **nDPI Deep Packet Inspection** | nDPI v5: application identification, traffic categories, risk/alert flags, JA3/JA3S TLS fingerprints, SNI extraction, and TLS certificate metadata per conversation |
| **Custom Signature Rules** | YAML detection rules matched against IP, CIDR, port, JA3, hostname, app, protocol, and payload byte / regex patterns; live-reloaded without restart |
| **Geolocation & ASN Enrichment** | Country/ASN enrichment for external IPs via a bundled offline GeoIP database (optional online enrichment when reachable) |

### 🤖 Narrate (AI) — turn packets into plain language

| Capability | What it does |
|---|---|
| **Story Mode** | AI-generated narrative reconstruction of network activity with an interactive LLM Q&A chat, custom context input, and story timeline |
| **AI Filter Generator** | LLM-powered Wireshark/tcpdump filter generation from natural-language queries, with confidence scores and packet-level results |

### 📈 Track over time — detect drift across captures

| Capability | What it does |
|---|---|
| **Network Monitor** | Load multiple PCAPs as ordered snapshots to track device, IP, protocol, and topology changes over time — useful for repeated audits or ongoing capture sessions |
| **Change Detection** | Automatic diffing between consecutive snapshots — ARP/MAC drift, gateway changes, new devices, new protocols/apps, ASN and VPN shifts — ranked by severity ([details](https://notyusheng.github.io/TracePcap/features/network-monitor.html)) |

### Platform

**PCAP Upload & Management** (PCAP/PCAPNG/CAP with MinIO object storage, duplicate detection, configurable limits) · **Real-time asynchronous processing** with stage-by-stage progress · **Multi-protocol support** (TCP, UDP, ICMP, TLS, HTTP, DNS, QUIC, and L2: ARP, STP, LLDP, CDP) · **Export** as PDF report (with live topology capture), per-conversation or bulk PCAP, and CSV.

## Quick Start

### Prerequisites

| Software | Version | Purpose |
|----------|---------|---------|
| Docker | Latest | Container runtime |
| Docker Compose | Latest | Multi-container orchestration |
| LLM Server | Any OpenAI-compatible API, self- or LAN-hosted | AI features (e.g. LM Studio, Ollama) — optional |

**Minimum hardware** (sizes the TracePcap stack only; the LLM, if self-hosted, is extra):

| | Minimum | Recommended | Comfortable |
|---|---------|-------------|-------------|
| RAM | 6GB (`SURICATA_ENABLED=false`) | 8GB+ | 16GB |
| CPU | 4 cores | 4+ cores | 8 cores |
| Storage | 10GB | 50GB+ | 100GB+ SSD |

The default stack's container limits total ~4.4GB (~5.4GB with the Keycloak auth overlay). Upload size is derived from `APP_MEMORY_MB` (max upload ≈ 16% of it; 327MB at the default `2048`). See [Container Resource Limits](docs/operations/production-hardening.rst) for the per-service breakdown and tuning.

### Installation

**1. Clone and set up:**
```bash
git clone https://github.com/PatrickCheol/TracePcap.git
cd TracePcap
cp .env.example .env
```

**2. Configure `.env`** (defaults work out of the box; AI features need an LLM endpoint):
```env
APP_MEMORY_MB=2048                          # 327MB max upload (derived from this)
NGINX_PORT=80                               # change if port 80 is in use
LLM_API_BASE_URL=http://localhost:1234/v1   # local/LAN inference server (must not be a public API)
LLM_MODEL=Qwen2.5-14B-Coder-Instruct
```

**3. Start the application:**
```bash
docker compose up -d
```

**4. Open** [http://localhost:80](http://localhost:80) in your browser.

> **Note:** First startup may take a minute while PostgreSQL and MinIO initialise. All non-AI features work without an LLM. For fully offline AI, use a self- or LAN-hosted inference server reachable from the backend container.

### ChatGPT login (no API key)

This checkout also supports an optional ChatGPT OAuth bridge through the official Codex
app-server. Run the stack with:

```bash
docker compose -f docker-compose.yml -f docker-compose.chatgpt.yml up -d --build
```

Open [http://localhost:8787](http://localhost:8787), select **Sign in with ChatGPT**, and
complete the device-code login. Then use TracePcap at its normal address. The login is stored
in a separate Docker volume; no host Codex credentials need to be copied.

This mode sends AI prompts and capture-derived context to OpenAI and requires internet access
and an eligible ChatGPT account. It is a local, single-account integration. See
[ChatGPT setup and M3 build troubleshooting](CHATGPT_SETUP.md) for details.

## Usage

### Single-file analysis

1. **Upload** — drag-and-drop a PCAP/PCAPNG/CAP file; optionally enable nDPI analysis and file extraction
2. **Analyze** — processed asynchronously with a per-stage progress view
3. **Overview** — detected applications, protocols, risk alerts, and custom signature matches
4. **Visualize** — explore the interactive topology with filters, layout controls, and node detail panels
5. **Conversations** — review flows with advanced filtering, session reconstruction, and payload inspection
6. **Story Mode** — read the AI-generated narrative and ask follow-up questions
7. **Extracted Files** — browse and download files recovered from HTTP responses and raw streams
8. **Generate Filters** — create Wireshark/tcpdump filters from natural language
9. **Export** — a PDF report, per-conversation or bulk PCAP, or CSV

### Multi-file Network Monitor

Build a picture of an unknown network from captures taken at different times, and track how it changes between them:

1. **Create a Network** (e.g. "Client Site — Building A")
2. **Add Snapshots** — upload PCAPs in capture order; each becomes a time-ordered snapshot
3. **Review the Diagram** — changed nodes are highlighted by severity
4. **Track Drift** — device, IP, protocol, and VPN changes detected automatically between consecutive snapshots
5. **Define Subnets** — "Detect Subnets" to infer CIDRs from traffic, or add them manually
6. **Annotate Nodes** — assign role labels, with "Suggest with AI" from traffic signals
7. **Correlate Events** — log real-world events (maintenance windows, incidents) against observed changes
8. **Generate Insights** — an AI narrative explaining changes across snapshots

The Monitor assumes you know nothing about the network upfront: there is no persistent agent or sensor — you feed in PCAPs and it compares them. Subnets, device roles, and topology are all **inferred from traffic** rather than imported from a CMDB, and the first snapshot becomes the implicit baseline for change detection. See [Network Monitor](https://notyusheng.github.io/TracePcap/features/network-monitor.html) for the full change-detection event reference.

### Supported file formats

PCAP, PCAPNG, CAP (max 327MB at the default `APP_MEMORY_MB`).

## Tech Stack

| Component | Technology |
|-----------|------------|
| **Backend** | Spring Boot 3.2.1, Java 21, Maven, Lombok, MapStruct |
| **Frontend** | React 19, Vite, TypeScript, SGDS React |
| **Visualization** | Sigma.js + graphology + ELK (topology), React Flow (cluster graph), Recharts, D3.js |
| **Reverse Proxy** | Nginx |
| **Packet Parsing** | tshark / Wireshark, nDPI v5 (deep packet inspection) |
| **Database** | PostgreSQL 15 with Flyway migrations |
| **Object Storage** | MinIO (S3-compatible) |
| **Containerization** | Docker, Docker Compose |
| **API Documentation** | SpringDoc OpenAPI (Swagger UI) |

## Documentation

Full documentation is at **https://notyusheng.github.io/TracePcap**. Start here for anything not covered in this README:

- [Installation & prerequisites](https://notyusheng.github.io/TracePcap/getting-started/installation.html) · [Offline / air-gapped deployment](https://notyusheng.github.io/TracePcap/getting-started/offline-deployment.html)
- [Feature guides](https://notyusheng.github.io/TracePcap/) — one page per capability above
- [Custom signature rules](https://notyusheng.github.io/TracePcap/configuration/signature-rules.html) — full YAML spec, match fields, and payload/regex matching
- [Authentication (OIDC / Keycloak)](https://notyusheng.github.io/TracePcap/configuration/authentication.html) · [Environment variables](https://notyusheng.github.io/TracePcap/configuration/environment-variables.html) · [LLM setup](https://notyusheng.github.io/TracePcap/configuration/llm-setup.html)
- [Operations](https://notyusheng.github.io/TracePcap/) — logs, backups, database access, production hardening

Interactive API docs (Swagger UI) are at **http://localhost:80/swagger-ui.html** when the app is running.

## Security

- **Local processing** — all PCAP analysis runs on your server; packet data never leaves your infrastructure
- **Offline-capable** — GeoIP uses a bundled DB-IP MMDB fallback; LLM queries use a configurable local endpoint
- **No authentication by default** — the base stack runs fully open; enable OIDC/Keycloak auth before exposing to multiple users (see the [Authentication guide](https://notyusheng.github.io/TracePcap/configuration/authentication.html), and **change all default credentials** for any real deployment)
- **Object storage** — MinIO is not exposed outside the Docker network

Data is shared across all authenticated users (no per-user ownership) in this version; per-user scoping is tracked separately (issues #360, #444).

## Sample Files

The [`sample-files/`](sample-files/) directory contains example PCAPs, including `atm_capture1.cap` (ATM traffic), `free5gc.pcap` (5G core), `demo_all_rules.pcap` (triggers the full set of custom signature demo rules), `dns_demo.pcap` and `http_demo.pcap` (classification demos, each with a `gen_*.py` regenerator), and `monitor_large/` (8 weekly snapshots of a simulated 550-node network for the Network Monitor). A full set of demo rules is in [`signatures.sample.yml`](signatures.sample.yml).

## Star History

<a href="https://www.star-history.com/?type=date&repos=NotYuSheng%2FTracePcap">
 <picture>
   <source media="(prefers-color-scheme: dark)" srcset="https://api.star-history.com/chart?repos=NotYuSheng/TracePcap&type=date&theme=dark&legend=top-left&sealed_token=D9LPtWzHI5tnKqoizk26myDmStDNwaytLiuCwkJKxwX7MzFH4ohD0wndbvmqPTyMMgETf436S_A9Rn9P6oUJg0G90ahClkr_pehyp6Ka7gHIXUjxbpQDiBlxtg6UmTpTHVZGfAYIFWBPTLmPxFIGtV6WXBbEX3nFrriIph2g7prnmubhH7xBaxldvq8s" />
   <source media="(prefers-color-scheme: light)" srcset="https://api.star-history.com/chart?repos=NotYuSheng/TracePcap&type=date&legend=top-left&sealed_token=D9LPtWzHI5tnKqoizk26myDmStDNwaytLiuCwkJKxwX7MzFH4ohD0wndbvmqPTyMMgETf436S_A9Rn9P6oUJg0G90ahClkr_pehyp6Ka7gHIXUjxbpQDiBlxtg6UmTpTHVZGfAYIFWBPTLmPxFIGtV6WXBbEX3nFrriIph2g7prnmubhH7xBaxldvq8s" />
   <img alt="Star History Chart" src="https://api.star-history.com/chart?repos=NotYuSheng/TracePcap&type=date&legend=top-left&sealed_token=D9LPtWzHI5tnKqoizk26myDmStDNwaytLiuCwkJKxwX7MzFH4ohD0wndbvmqPTyMMgETf436S_A9Rn9P6oUJg0G90ahClkr_pehyp6Ka7gHIXUjxbpQDiBlxtg6UmTpTHVZGfAYIFWBPTLmPxFIGtV6WXBbEX3nFrriIph2g7prnmubhH7xBaxldvq8s" />
 </picture>
</a>

## License

Licensed under the MIT License. See [LICENSE](LICENSE) for details.
