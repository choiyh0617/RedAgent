# pentest-agent

CTF/OSCP 연습용 침투테스트 에이전트 (MVP). VirtualBox로 격리된 랩 안에서
대상 VM을 프로비저닝하고, 정찰부터 플래그 획득까지 자동화하는 것이 목표입니다.

현재 구현된 것: 0단계(환경 프로비저닝) ~ 7단계(Reporting) 전체. Metasploit 경로
포함 exploitation.py, post_exploit.py(권한상승), flag_capture.py, reporting.py
모두 Metasploitable2 대상 실전 검증 완료.

**AD 랩 준비 + 실전 검증 완료**: `AD-DC01`(Windows Server 2022, 도메인
`goadlab.local`, IP `192.168.56.106`)이 도메인 컨트롤러로 승격되어 있고
(DESIGN.md 36절), `ad_enum.py`/`lateral_movement.py`/`sniffing.py` 전부 이
랩으로 실전 검증 완료됐습니다(버그 3개 발견/수정 - DESIGN.md 37절).
`shell_manager.py`는 msfrpcd(Metasploit RPC 데몬) + `pymetasploit3` 기반으로
재설계됨(DESIGN.md 35절).

**OWASP Juice Shop 랩**: Kali에서 Docker로 `http://192.168.56.101:3000`에
떠 있습니다(DESIGN.md 38절) - Kali 자신의 IP를 쓰기 때문에 자동 대상 탐지에는
안 잡히니, `web_exploit.py`/`run_pipeline.py` 실행 시 타겟을 `192.168.56.101`
포트 `3000`으로 수동 지정하세요.

`web_exploit.py`(sqlmap 기반 SQLi 탐지)도 Kioptrix2 대상 실전 검증
완료입니다(DESIGN.md 28절) — 이걸로 MVP 전 모듈(AD 3개 제외) 구현이 끝났습니다.

**대화형 도구(pwncat-cs 등)는 SSH로 직접 사용**: `pwncat-cs`처럼 원래 사람이
터미널에서 조작하도록 만들어진 도구는 자동화로 억지로 몰아넣지 않고, Kali에
SSH를 열어서 사람이 직접 붙어 쓸 수 있게 했습니다.
```bash
ssh kali@192.168.56.101   # 비밀번호: kali
pwncat-cs -lp 4444        # 접속 후 직접 실행
```
(DESIGN.md 26절 - pwncat-cs는 Python 3.13 호환성 패치까지 했지만 비대화형
자동 실행에서는 리버스쉘 연결이 즉시 끊기는 문제가 있어 이 방식으로 전환)

## 사전 준비물 (Prerequisites)

이 코드를 다른 환경에 배포하기 전에 아래가 준비되어 있어야 합니다.

### 1. VirtualBox
- 설치되어 있어야 하며, `VBoxManage.exe`가 다음 경로에 있다고 가정합니다:
  `C:\Program Files\Oracle\VirtualBox\VBoxManage.exe`
  다른 경로에 설치했다면 `env/guest_control.py`, `env/provision_target.py`,
  `env/provision_network.py` 세 파일 상단의 `VBOXMANAGE` 상수를 수정하세요.
- 개발/테스트는 VirtualBox 7.2.14 기준입니다.

### 2. Kali Linux VM (미리 만들어져 있어야 함 — 이 코드가 만들어주지 않습니다)
- VirtualBox에 VM 이름이 정확히 **`kali`** 로 등록되어 있어야 합니다.
- 공식 Kali VirtualBox 이미지를 쓰는 걸 권장합니다 (Guest Additions가 기본 포함되어 있어서
  `guestcontrol`로 네트워크 없이 바로 명령을 실행할 수 있습니다).
- 로그인 계정은 기본값 **`kali` / `kali`** 를 가정합니다. 다르게 설정했다면
  `env/guest_control.py`의 `KALI_USER`, `KALI_PASS`를 수정하세요.
- NIC1은 NAT(툴 설치/업데이트용 인터넷)로 두는 걸 권장합니다. NIC2(랩 네트워크용)는
  `python -m env.provision_network` 최초 실행 시 자동으로 확인/연결됩니다 — 다만 VM이
  켜져 있으면 NIC 재배정이 막힐 수 있으니, **처음 실행할 때는 Kali를 꺼둔 상태**를 권장합니다.
- `nmap`, `arp-scan` 등 정찰 도구가 설치되어 있어야 합니다 (Kali 기본 이미지는 포함됨).
- AD/멀티호스트 지원(`modules/sniffing.py`, `ad_enum.py`, `lateral_movement.py`)에는
  `netexec`, `bloodhound-python`, `impacket-secretsdump`, `impacket-GetNPUsers`,
  `impacket-GetUserSPNs`, `responder`, `tshark`가 필요합니다 — Kali 기본 이미지에
  전부 포함되어 있습니다 (2026-08-08 기준 `kali` VM에서 확인함).

### 3. Python
- Python 3.10 이상
- 의존 패키지 설치:
  ```bash
  pip install pyyaml anthropic python-dotenv paramiko pymetasploit3 requests
  ```
  `anthropic`은 `vuln_analysis.py`/`post_exploit.py`가 Claude API를 직접 호출하는 데
  씁니다. `paramiko`는 `env/kali_ssh.py`가 Kali에 SSH로 접속해서 진짜 pty가 붙은
  대화형 세션(pwncat-cs 등)을 구동하는 데 씁니다(DESIGN.md 27절). `pymetasploit3`는
  `modules/shell_manager.py`가 Kali의 msfrpcd(Metasploit RPC 데몬)에 접속해서
  진짜 재연결 가능한 세션을 관리하는 데 씁니다(DESIGN.md 35절) - Kali 쪽에는
  별도 설치 필요 없이 `msfrpcd` 바이너리(Metasploit Framework에 포함)만 있으면 됩니다.
  `requests`는 `vuln_analysis.py`가 NVD(CVE) API를 실시간 조회하는 데 씁니다(DESIGN.md 41절).

### 3-1. LLM 인증 설정 (Claude Pro/Max 구독 우선, 한도 걸리면 API로 자동 전환)
```bash
cp .env.example .env
```
1. **구독(우선 사용, 권장)**: `npm i -g @anthropic-ai/claude-code`로 CLI 설치 후
   ```bash
   claude setup-token
   ```
   브라우저 로그인 화면이 뜨고, 완료되면 1년짜리 OAuth 토큰이 출력됩니다. 이 토큰을
   `.env`의 `CLAUDE_CODE_OAUTH_TOKEN=` 뒤에 붙여 넣으세요.
2. **API(폴백용)**: [console.anthropic.com](https://console.anthropic.com)에서
   발급받은 키를 `.env`의 `ANTHROPIC_API_KEY=` 뒤에 채워 넣으세요. 구독 사용량
   한도에 걸렸을 때만(그리고 리셋되기 전까지만, 기본 30분) 자동으로 이쪽으로
   전환됩니다(DESIGN.md 16절). 전환되는 순간과 호출마다의 예상 비용이 콘솔에
   출력됩니다.
3. **지출 상한**: `.env`의 `MAX_API_SPEND_USD`를 실제 충전한 금액에 맞춰 설정하세요
   (비워두면 기본 $5). Anthropic API에 잔액 조회 기능이 없어서 코드가 자체 계산한
   추정치 기준으로만 막을 수 있습니다 — **Anthropic Console에서 별도로 지출 한도를
   설정하는 걸 추가로 권장합니다**(진짜 하드 스톱, DESIGN.md 14절). 이 상한은
   구독이 막혀서 종량제로 도는 한 구간당 예산이라, 구독 한도가 리셋되면 자동으로
   초기화됩니다(16-1절).

`.env`는 `.gitignore`에 포함되어 있어 커밋되지 않습니다. **토큰/키를 다른 사람(에이전트
포함)에게 채팅으로 붙여넣지 마세요** — 대화 기록에 영구히 남습니다. `python -m
env.check_api_key`로 어느 경로든 정상 동작하는지 확인할 수 있습니다(값 자체는
출력하지 않습니다).

### 4. 대상 CTF VM 이미지 (.vmdk)
- VulnHub 등에서 **직접 다운로드는 사용자가 해야 합니다** (에이전트가 자동으로 다운로드하지 않습니다).
- `.rar`/`.zip`으로 배포되는 경우가 많으니, 압축을 풀어서 안에 있는 `.vmdk` 실제 경로를 확보해두세요.

## 사용법 (Usage)

프로젝트 루트(`pentest-agent/`)에서 실행하는 걸 기준으로 합니다.

### 전체 킬체인 한 번에 (권장)

랩 네트워크 준비 + 대상 VM 임포트/기동이 끝난 뒤에는, 아래 단계별 실행 대신
`run_pipeline.py` 하나로 recon부터 reporting까지 순서대로 돌릴 수 있습니다.
단계가 넘어갈 때마다 콘솔에 진행상황이 찍혀서(`core/progress.py`), 오래
걸리는 스캔/익스플로잇 단계 중에도 지금 뭘 하고 있는지 알 수 있습니다.
```bash
python run_pipeline.py <타겟_IP> [VM_이름] [--label=라벨]
```
- `VM_이름`을 주면 익스플로잇 전 스냅샷 + 리포트 완료 후 정상종료까지 자동 처리합니다.
- Metasploit로 성공한 경우에만 post_exploit/flag_capture까지 진행됩니다(PoC 스크립트
  성공만으로는 세션을 이어받을 수 없음 - DESIGN.md 30절).
- Metasploitable2 대상 실전 검증 완료(약 25분 소요, DESIGN.md 30절).

아래는 각 단계를 개별적으로 실행하고 싶을 때(디버깅, 특정 단계만 재실행 등) 쓰는 방법입니다.

### 0) 랩 네트워크 준비 (최초 1회, 또는 새 환경에 배포할 때마다)
```bash
python -m env.provision_network
```
Host-Only 네트워크(192.168.56.0/24)와 그 위의 DHCP 서버, Kali의 NIC 연결까지
전부 확인하고 없는 것만 만듭니다. 이미 다 되어 있으면 전부 `[skip]`으로 표시됩니다.

### 1) 대상 CTF VM 임포트
다운로드한 `.vmdk` 경로를 넘겨서 VM을 등록/기동합니다.
```bash
python -c "
from env.provision_target import import_target_vm, start_target_vm, TargetProfile
import_target_vm('Kioptrix2', r'C:\경로\대상.vmdk', TargetProfile(ostype='RedHat4'))
start_target_vm('Kioptrix2')
"
```
- `TargetProfile()`을 그냥 기본값으로 두면 `Oracle Linux (32-bit)` 프로파일(1024MB/cpu 1)을 씁니다.
  대상 OS에 맞는 `ostype`을 쓰고 싶으면 `VBoxManage list ostypes`로 목록을 확인하세요.
- 이미 등록된 VM 이름을 다시 넣으면 임포트는 건너뛰고, 이미 켜져 있으면 기동도 건너뜁니다
  (여러 번 실행해도 안전).
- 오래된 VulnHub 이미지는 부팅 중 "Checking for new hardware"(kudzu) 화면에서 몇 분씩
  멈춘 것처럼 보일 수 있습니다 — 실제로는 카운트다운 후 자동 진행되니 그냥 기다리면 됩니다.

### 2) 대상 탐지 + scope.yaml 생성
```bash
python -m modules.recon
```
Kali 안에서 랩 서브넷을 스캔해서, 호스트/Kali 자신을 제외한 새 호스트를 찾고
프로젝트 루트의 `scope.yaml`에 기록합니다. **이후 모든 단계는 이 파일에 없는 IP를
절대 건드리면 안 됩니다** (안전 가드).

### 3) 포트/서비스 스캔
```bash
python -m modules.scanning <target> "-p-"
```
전체 포트를 discovery(-sV)/script(-sC) 2단계로 나눠 스캔하고, 서비스별 서브모듈
(HTTP/SMB/FTP)을 병렬로 실행합니다. 오래 걸리는 스캔은 `env/job_runner.py`가
진행률을 지켜보며 감시합니다(DESIGN.md 12절). 결과는 `state/<engagement_id>/findings.jsonl`에 기록됩니다.

### 4) 취약점 후보 분석
```bash
python -m modules.vuln_analysis <engagement_id> <target>
```
scanning.py가 찾은 서비스를 searchsploit으로 조회하고, 후보마다 Claude API로
단발성 판정(confidence/risk/rationale)을 내려 우선순위를 매깁니다(Supervisor/Worker
패턴, DESIGN.md 4절). `.env`의 `ANTHROPIC_API_KEY`를 자동으로 읽습니다(3-1절).

### 5) 익스플로잇 시도
```bash
python -m modules.exploitation <engagement_id> <target> [vm_name]
```
vuln_analysis.py가 남긴 후보 중 실행 가능한 PoC 스크립트를 우선순위대로 순차
시도하고, 결과를 LLM이 판정합니다(Metasploit 없이 진행 - DESIGN.md 18절).
`vm_name`을 주면 시도 직전에 스냅샷을 떠서, 박스가 죽어도 롤백할 수 있습니다.

### 6) 뭔가 이상할 때 — 환경 진단
```bash
python -m env.health_check <target_ip...>
```
VM 상태/응답성, orphan 세션, kali 메모리, 대상 도달성, 미완료 job을 한 번에
점검하고 안전하게 자동으로 고칠 수 있는 건 바로 고칩니다(DESIGN.md 20절). 다른
명령이 원인 불명확하게 실패하거나 멈출 때 제일 먼저 이걸 돌려보세요.

### 6-1) 대화형 트러블슈팅 (MCP, 선택)
`health_check.py`로도 원인이 안 잡히는 문제(부팅 화면을 직접 봐야 하는 경우
등)를 사람이 직접 붙어서 살펴보고 싶을 때, MCP 클라이언트(Claude Desktop 등)로
VM에 붙어 대화형으로 진단할 수 있습니다(DESIGN.md 40/42절 - 파이프라인 자체는
MCP를 안 쓰지만, 순서가 정해져 있지 않은 사람 주도 트러블슈팅은 MCP가 맞는
자리라고 판단해 예외적으로 추가했습니다).

```bash
pip install "mcp[cli]"
```
Claude Desktop 설정(`claude_desktop_config.json`)의 `mcpServers`에 추가:
```json
{
  "mcpServers": {
    "pentest-vm-troubleshoot": {
      "command": "python",
      "args": ["-m", "mcp_servers.vm_troubleshoot_server"],
      "cwd": "/path/to/pentest-agent"
    }
  }
}
```
연결되면 `list_vms`/`take_screenshot`/`check_vm_state`/`vm_power_action`
(reset/poweroff/startvm만)/`check_reachability`/`run_in_kali`(진단용
읽기전용 명령만) 도구를 쓸 수 있습니다. 디스크 재구성/파일 삭제처럼
되돌리기 어려운 조치는 의도적으로 도구에 없습니다 - `env/setup_doctor.py`
(LLM이 스스로 도구를 골라 도는 에이전틱 루프)와 같은 안전 범위를 재사용한
것입니다. 모든 호출은 `state/<세션 시작 시각>-interactive-troubleshoot/
findings.jsonl`에 감사 기록으로 남습니다.

### 7) 권한상승 -> flag 획득 -> 보고서
exploitation.py로 Metasploit 세션을 얻은 후:
```python
from modules.post_exploit import run_linpeas_via_msf_session, analyze_privesc_candidates
from modules.flag_capture import search_and_capture_flags
from modules.reporting import save_report

output = run_linpeas_via_msf_session(engagement_id, target, module, port, kali_ip)
analyze_privesc_candidates(engagement_id, target, output)

search_and_capture_flags(engagement_id, target, module, port, kali_ip)

save_report(engagement_id)  # state/<engagement_id>/report.md 로 저장
```
`module`/`port`/`kali_ip`는 exploitation.py가 사용한 것과 동일한 값(Metasploit
모듈 경로, 대상 포트, `modules.exploitation._kali_ip()`)을 그대로 씁니다. 셋 다
Metasploitable2 대상으로 실전 검증됨(DESIGN.md 21/21-1절). CLI로 개별 실행하려면
`python -m modules.flag_capture <engagement_id> <target> <module> <port> <kali_ip>`,
`python -m modules.reporting <engagement_id>`.

## 디렉터리 구조
```
pentest-agent/
  env/
    provision_network.py   # 랩 네트워크(hostonly+DHCP+Kali 연결) 프로비저닝
    provision_target.py    # 대상 CTF VM 임포트/기동 + 스냅샷/롤백
    guest_control.py       # Kali 내부 명령 실행 (VBoxManage guestcontrol 래퍼)
    job_runner.py            # 장시간 명령 감시(watchdog) — DESIGN.md 12절
    health_check.py          # 환경 진단/트러블슈팅 — DESIGN.md 20절
    check_api_key.py         # LLM 인증 경로 확인
  core/
    engagement.py           # 인게이지먼트 ID 생성/조회 (구현됨)
    state_store.py           # findings.jsonl / credentials.jsonl 공용 읽기·쓰기 (구현됨)
    config.py                 # .env 로드 + stdout UTF-8 고정 (구현됨)
    llm_client.py             # 구독 우선 + API 폴백 LLM 호출 (구현됨, DESIGN.md 16절)
    llm_guard.py               # 프롬프트 크기 상한, 호출 상한 (구현됨)
    spend_tracker.py           # 종량제 지출 추정/상한 (구현됨, DESIGN.md 16-1절)
  modules/
    recon.py               # 호스트 탐지 + scope.yaml 생성 (구현됨)
    scanning.py             # Linux 포트/서비스 스캔 (구현됨, job_runner로 감시)
    ad_enum.py               # AD 전용 enum — netexec/bloodhound-python (구현됨, 미검증 — DESIGN.md 25절)
    vuln_analysis.py        # 취약점 후보 분석 (구현됨, LLM 호출)
    exploitation.py         # PoC + Metasploit 실행 + LLM 성공판정 (구현됨, DESIGN.md 18/20-4절)
    shell_manager.py        # msfconsole -x 체이닝으로 명령 실행 (구현됨, DESIGN.md 26절, pwncat-cs 조사 기록 포함)
    lateral_movement.py      # AD 크레덴셜 재사용/피벗 (구현됨, 미검증 — DESIGN.md 25절)
    sniffing.py               # responder/tshark로 크레덴셜 캡처 (구현됨, 미검증 — DESIGN.md 25절)
    post_exploit.py         # linpeas + LLM 권한상승 후보 분석 (구현됨, DESIGN.md 21절)
    flag_capture.py         # flag 파일 탐색/캡처 (구현됨, DESIGN.md 21-1절)
    reporting.py            # findings -> Markdown 보고서 (구현됨)
    web_exploit.py            # sqlmap 기반 SQLi 탐지 (구현됨, DESIGN.md 28절)
    knowledge_base.py        # 스텁 (RAG 인터페이스만, 항상 빈 리스트 반환)
  scope.yaml                # recon 단계에서 자동 생성됨 (안전 가드)
  state/                    # 인게이지먼트별 findings.jsonl / credentials.jsonl / report.md
```

설계 결정과 그 이유(왜 이런 구조인지)는 [DESIGN.md](DESIGN.md)에 정리되어 있습니다.
