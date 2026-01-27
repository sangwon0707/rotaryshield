# RotaryShield AI Integration Plan

## Overview
RotaryShield에 경량 LLM을 통합하여 자연어 기반 보안 관리 기능 제공

---

## 목표
- CLI/TUI에서 자연어로 명령 가능
- 복잡한 명령어 암기 불필요
- 서버 로컬에서 실행 (외부 API 의존 X)
- CPU만으로 실행 가능한 경량 모델 사용

---

## 기술 스택

### LLM Backend - 추천 모델

#### Gemma 270M ⭐ 단일 모델 사용
| 항목 | 내용 |
|------|------|
| 파라미터 | 270M |
| 크기 | ~200MB (INT4) |
| 메모리 | ~500MB |
| CPU 실행 | ✅ 2코어 가능 |
| 응답 속도 | <1초 |
| 특징 | 초경량, 함수 호출 특화 |
| 출처 | Google (2025) |

**선택 이유:**
- 2코어 2GB 저사양 서버에서도 실행 가능
- 명령어 파싱 용도에 충분한 성능
- 웹서버와 함께 돌려도 메모리 여유 있음

**최소 요구사양:**
```
CPU: 2코어
RAM: 2GB (전체 시스템)
디스크: 500MB (모델 저장)
```

### 권장 구성
```
기본: Gemma 270M (또는 FunctionGemma)
대안: 없음 - 단일 모델로 통일
```

---

## 기능 명세

### Phase 1: 자연어 명령어 (MVP)
**우선순위: 높음 | 난이도: 쉬움**

사용자 입력을 구조화된 명령으로 변환

```
입력: "192.168.1.100 차단해"
출력: {"action": "ban", "ip": "192.168.1.100", "duration": 3600}

입력: "중국에서 오는 거 다 막아"
출력: {"action": "ban", "filter": {"country": "CN"}}

입력: "지난 1시간 공격 보여줘"
출력: {"action": "query", "type": "events", "time_range": "1h"}

입력: "어제 뭐 있었어?"
출력: {"action": "report", "date": "yesterday"}
```

**지원 명령어:**
| 자연어 예시 | 매핑 액션 |
|------------|----------|
| "X.X.X.X 차단/막아/밴해" | ban_ip |
| "X.X.X.X 풀어/해제" | unban_ip |
| "차단 목록 보여줘" | list_blocked |
| "공격 로그 보여줘" | show_events |
| "상태 알려줘" | show_status |
| "통계 보여줘" | show_stats |
| "전부 풀어" | unban_all |
| "새로고침" | refresh |

### Phase 2: 공격 분석 설명
**우선순위: 중간 | 난이도: 중간**

공격 패턴을 사람이 읽기 쉽게 설명

```
입력: 최근 이벤트 데이터
출력:
"185.220.101.45에서 3분간 47회 SSH 로그인 시도가 감지되었습니다.
이는 전형적인 Credential Stuffing 공격 패턴입니다.
해당 IP는 알려진 Tor exit node로, 자동 차단되었습니다."
```

### Phase 3: 스마트 추천
**우선순위: 낮음 | 난이도: 높음**

현재 설정과 공격 패턴 분석 후 개선안 제시

```
"현재 ban_threshold가 10으로 설정되어 있습니다.
최근 공격 패턴을 보면 평균 7회 시도 후 성공하는 경우가 있어
threshold를 5로 낮추는 것을 권장합니다."
```

---

## 아키텍처

```
┌─────────────────────────────────────────────────────────┐
│                    RotaryShield TUI                      │
├─────────────────────────────────────────────────────────┤
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐  │
│  │   Input     │───▶│  AI Parser  │───▶│  Executor   │  │
│  │  (자연어)   │    │  (Ollama)   │    │  (Actions)  │  │
│  └─────────────┘    └─────────────┘    └─────────────┘  │
│                            │                             │
│                            ▼                             │
│                    ┌─────────────┐                       │
│                    │   Ollama    │                       │
│                    │   Server    │                       │
│                    │ (localhost) │                       │
│                    └─────────────┘                       │
└─────────────────────────────────────────────────────────┘
```

### 컴포넌트

1. **AIParser** (`src/rotaryshield/ai/parser.py`)
   - 자연어 → JSON 명령 변환
   - Ollama API 호출
   - 폴백: 파싱 실패 시 기존 명령어 시스템 사용

2. **CommandExecutor** (`src/rotaryshield/ai/executor.py`)
   - JSON 명령 → 실제 함수 호출
   - 결과 포맷팅

3. **OllamaClient** (`src/rotaryshield/ai/ollama.py`)
   - Ollama REST API 래퍼
   - 연결 관리, 타임아웃 처리

---

## 프롬프트 설계

### System Prompt (Phase 1)
```
You are a security command parser for RotaryShield.
Convert user's natural language to JSON command.

Available actions:
- ban_ip: {"action": "ban", "ip": "<IP>", "duration": <seconds>}
- unban_ip: {"action": "unban", "ip": "<IP>"}
- list_blocked: {"action": "list_blocked"}
- show_events: {"action": "events", "limit": <n>, "filter": {...}}
- show_stats: {"action": "stats"}
- refresh: {"action": "refresh"}

Respond ONLY with valid JSON. No explanation.

Examples:
User: "192.168.1.1 차단해"
{"action": "ban", "ip": "192.168.1.1", "duration": 3600}

User: "차단 목록"
{"action": "list_blocked"}
```

---

## 구현 계획

### Step 1: Ollama 연동 기반 구축
```
src/rotaryshield/ai/
├── __init__.py
├── ollama.py      # Ollama API 클라이언트
├── parser.py      # 자연어 파서
└── executor.py    # 명령 실행기
```

### Step 2: TUI 통합
- 입력창에서 `/ai` 또는 `>` prefix로 AI 모드 진입
- 또는 자동 감지 (명령어가 아닌 자연어면 AI로 전달)

### Step 3: 설정 추가
```yaml
# config.yml
ai:
  enabled: true
  backend: ollama
  ollama_url: "http://ollama:11434"  # docker-compose 내부
  model: "gemma:270m"
  timeout: 5
  fallback_to_cli: true              # AI 실패 시 기존 CLI 사용
```

---

## 의존성

### 필수
```
# requirements.txt 추가
httpx>=0.24.0  # Ollama API 호출용 (또는 requests)
```

### Ollama 설치

**docker-compose에 이미 포함됨!**

```bash
# RotaryShield + Ollama 함께 실행
docker-compose up -d

# 모델 다운로드 (~200MB)
docker exec -it rotaryshield-ollama ollama pull gemma:270m
```

**수동 설치 (별도 서버):**
```bash
docker run -d -v ollama:/root/.ollama -p 11434:11434 --name ollama ollama/ollama
docker exec -it ollama ollama pull gemma:270m
```

---

## 예상 리소스 사용량

**Gemma 270M 단일 모델:**
| 항목 | 사용량 |
|------|--------|
| 모델 RAM | ~500MB |
| Ollama 서버 | ~200MB |
| 디스크 | ~200MB |
| 응답시간 (CPU) | <1초 |

**2코어 2GB 서버 기준:**
```
전체 메모리: 2048MB
- OS/시스템:   300MB
- 웹서버:      200MB
- RotaryShield: 100MB
- Ollama:      200MB
- 모델 (270M): 500MB
─────────────────────
잔여:         ~750MB ✅ 여유 있음
```

---

## 성공 지표

1. **명령어 파싱 정확도**: >90%
2. **응답 시간**: <2초 (CPU 환경)
3. **폴백 성공률**: 100% (AI 실패해도 기존 기능 작동)

---

## 리스크 & 대응

| 리스크 | 대응 |
|--------|------|
| Ollama 서버 다운 | 폴백으로 기존 CLI 명령어 사용 |
| 잘못된 파싱 | 실행 전 확인 프롬프트 표시 |
| 느린 응답 | 타임아웃 설정 + 로딩 인디케이터 |
| 모델 크기 | 0.5B~1B 경량 모델 사용 |

---

## 향후 확장

1. **다국어 지원**: 한국어/영어 자동 감지
2. **음성 명령**: TTS/STT 연동 (whisper)
3. **자동화 규칙**: "새벽 2-5시 사이 중국 IP는 자동 차단"
4. **학습**: 사용자 명령 패턴 학습하여 정확도 향상

---

## 타임라인 (예상)

| Phase | 기능 | 예상 기간 |
|-------|------|----------|
| 1 | 자연어 명령어 MVP | 1-2일 |
| 2 | TUI 통합 | 1일 |
| 3 | 공격 분석 설명 | 2-3일 |
| 4 | 스마트 추천 | 1주 |

---

## 참고

- Ollama API: https://github.com/ollama/ollama/blob/main/docs/api.md
- FunctionGemma 공식 발표: https://blog.google/technology/developers/functiongemma/
- Gemma 3 270M: https://developers.googleblog.com/en/introducing-gemma-3-270m/
- Gemma 3 1B (Mobile/Web): https://developers.googleblog.com/en/gemma-3-on-mobile-and-web-with-google-ai-edge/
