# TracePcap: ChatGPT 로그인으로 AI 기능 사용하기

이 구성은 API 키 대신 공식 Codex app-server의 ChatGPT OAuth 로그인을 사용한다.
일반적인 PCAP 분석은 로컬에서 진행하고, AI 기능을 실행하면 기존 TracePcap이 만든
프롬프트와 분석 문맥이 OpenAI로 전송된다. 완전한 오프라인 모드는 아니다.

## 실행

프로젝트 디렉터리에서 실행한다.

```bash
docker compose -f docker-compose.yml -f docker-compose.chatgpt.yml up -d --build
```

1. <http://localhost:8787>을 연다.
2. ChatGPT 로그인 버튼을 누른다.
3. 표시된 공식 인증 페이지를 열고 일회용 코드를 입력한다.
4. 연결 완료 상태를 확인한 뒤 <http://localhost>에서 PCAP을 업로드한다.
5. Story, AI Filter, 패킷 설명 등 AI 기능을 사용한다.

`NGINX_PORT`를 바꿨다면 해당 포트로 TracePcap에 접속한다.
`CHATGPT_LOGIN_PORT`를 설정하면 로그인 페이지의 로컬 포트도 바꿀 수 있다.
계정에서 디바이스 로그인을 허용하도록 요청받으면 공식 인증 화면의 안내를 따른다.
사용 가능한 모델과 사용량은 로그인한 ChatGPT 계정의 접근 권한과 한도를 따른다.

이 브리지는 TracePcap이 사용하는 비스트리밍 텍스트 요청을 지원한다. Codex의 생성 설정을
사용하므로 기존 `LLM_TEMPERATURE`, `LLM_MAX_TOKENS` 값은 실제 생성의 temperature나
출력 토큰 상한을 강제하지 않는다. `LLM_MAX_TOKENS`는 백엔드의 문맥 예산 계산에는 계속
사용된다. 함수 호출은 이 모드에서 끄고 기존 텍스트 JSON 처리 경로를 사용한다.

로그인 정보는 별도의 Docker 볼륨 `chatgpt_auth`에 보관한다. 기존 호스트의 Codex 로그인
파일을 복사하거나 마운트하지 않는다. 컨테이너를 재시작해도 로그인은 유지되며,
로그인 페이지에서 로그아웃할 수 있다. `docker compose down -v`는 로그인뿐 아니라
기존 PCAP·DB 볼륨까지 지울 수 있으므로 일반적인 재시작에는 사용하지 않는다.

기본 모델은 `gpt-6-astra`, 추론 강도는 `high`다. 패킷 필드와 세션 문맥을 비교하는
질문에 충분한 추론을 사용하도록 지정한다. 현재 연결 계정의 공식 `model/list`에서 이
조합의 지원을 확인했다. 계정 권한이 바뀌어 사용할 수 없으면 오류를 표시하며, 다른
모델로 자동 변경하지 않는다. 계정 기본값보다 응답 시간과 사용량이 늘어날 수 있다.

다른 모델을 지정하려면 `.env`의 `CHATGPT_MODEL`과 `CHATGPT_REASONING_EFFORT`를
설정하고 브리지와 백엔드를 다시 생성한다. 추론 강도는 해당 모델에서 지원해야 한다.

```dotenv
CHATGPT_MODEL=gpt-6-astra
CHATGPT_REASONING_EFFORT=high
```

```bash
docker compose -f docker-compose.yml -f docker-compose.chatgpt.yml up -d --build --force-recreate codex-bridge backend
```

기존 `.env`의 `LLM_API_KEY`와 `LLM_API_BASE_URL`은 이 오버레이에서 사용하지 않는다.
현재 로컬 `.env`에 `COMPOSE_FILE=docker-compose.yml:docker-compose.chatgpt.yml`을 지정했다면
`docker compose up -d --build`만으로 같은 구성을 실행할 수 있다.

## M3 Docker 빌드 오류 원인

기존 backend Dockerfile은 ntop의 Ubuntu 22.04 **x64 전용 패키지 저장소**를 사용했다.
Apple Silicon에서 ARM64 이미지로 빌드하면 해당 저장소에서 `ndpi`를 찾지 못해
`E: Unable to locate package ndpi`로 종료된다.

수정한 구성은 nDPI를 소스로 빌드해 ARM64에서도 DPI 기능을 유지한다.
Intel 이미지 에뮬레이션은 필요하지 않다.

설치 후 백엔드가 `tracepcap.auth.issuer-uri must be set when authentication is enabled`로
종료된다면 `.env`의 `TRACEPCAP_AUTH_ENABLED`를 확인한다. 기본 로컬 구성에는 Keycloak이
없으므로 `false`를 사용한다. 이것은 TracePcap 웹앱의 OIDC 로그인 설정이며 ChatGPT AI
로그인과는 별개다. 운영용 오버레이는 앱 인증을 명시적으로 활성화한다.

## 확인

```bash
docker compose -f docker-compose.yml -f docker-compose.chatgpt.yml ps
curl --fail http://localhost:8787/healthz
curl --fail http://localhost:8787/auth/status
```

`healthz`는 서비스 실행 상태이며, 로그인 성공은 `auth/status`의 `authenticated`로 확인한다.
OAuth 로그인을 마치기 전에도 서비스가 실행되고 일반 패킷 분석은 가능하다.
AI 기능의 실제 응답은 로그인 후에 확인할 수 있다.

브리지 자체 검증은 Node.js 22 이상에서 실행한다.

```bash
cd codex-bridge
npm test
```

공식 참고: [Codex app-server](https://learn.chatgpt.com/docs/app-server).
이 오버레이는 개인 로컬 사용을 위한 단일 계정 구성이다.
