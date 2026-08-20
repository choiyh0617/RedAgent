"""
로컬 웹 대시보드 - CLI 콘솔과 같은 진행상황을 브라우저에서도 실시간으로
보여준다. DESIGN.md 44절.

사용자 요청: "웹페이지에 가상의 모니터가 보여지는 것처럼 유저가 확인할 수
있도록". 다만 완전히 꾸며낸 화면 대신, 이미 있는 진짜 데이터
(findings.jsonl 진행상황 + VBoxManage screenshotpng로 찍은 실제 VM 화면)를
보여주는 라이브 뷰로 만들었다 - 이 프로젝트 전체가 "실제로 검증된 것만
표시" 원칙을 지켜왔는데(예: vuln_analysis.py가 LLM 추측보다 searchsploit/
NVD 같은 결정론적 데이터를 우선하는 것과 같은 이유), 대시보드도 실제로
일어난 일만 보여줘야 한다.

새 인프라(Flask/FastAPI, DB, WebSocket)를 끌어오지 않고 stdlib
(http.server)만으로 만들었다 - 이 프로젝트가 계속 지켜온 "별도 인프라 안
씀" 기조와 동일(LanceDB를 굳이 임베디드로 고른 것, MCP를 메인 파이프라인에
안 쓰기로 한 것과 같은 방향). 프론트엔드는 JS fetch()로 짧은 간격 폴링한다
- 진짜 스트리밍(SSE/WebSocket)보다 구현이 훨씬 간단하고, 이 정도 갱신
주기면 "라이브로 보고 있다"는 느낌엔 충분하다.

스크린샷은 기본 꺼짐(체크박스로 켬) - VBoxManage screenshotpng 자체가 VM에
부하를 주는 실제 명령이라(사용자 지적: "부하를 줄일 수 있도록 스크린샷은
온/오프가 선택 가능하도록"), 계속 찍어대면 파이프라인이 쓰고 있는 다른
guestcontrol 작업과 리소스를 다툴 수 있다. 진행상황 폴링(findings.jsonl
읽기)은 호스트 파일 읽기라 VM에 전혀 부하를 안 줘서 기본으로 켜둠.

실행: `python web_monitor.py` (기본 포트 8765) -> 브라우저에서
http://127.0.0.1:8765 접속.
"""

import json
import subprocess
import tempfile
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from core import config  # noqa: F401 - .env 로드 + stdout UTF-8 고정
from core.engagement import list_engagements
from core.state_store import read_findings
from env.provision_target import VBOXMANAGE

PORT = 8765
SCREENSHOT_TIMEOUT = 15


def _take_screenshot(vm_name: str) -> bytes | None:
    """setup_doctor.py/vm_troubleshoot_server.py와 같은 패턴 - screenshotpng는
    VBoxManage가 실행되는 호스트에 저장된다(Kali 안의 경로가 아님)."""
    path = Path(tempfile.gettempdir()) / f"web_monitor_{vm_name}.png"
    try:
        subprocess.run(
            [VBOXMANAGE, "controlvm", vm_name, "screenshotpng", str(path)],
            timeout=SCREENSHOT_TIMEOUT, capture_output=True, check=True,
        )
    except (subprocess.SubprocessError, OSError):
        return None
    try:
        return path.read_bytes()
    except OSError:
        return None


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt: str, *args) -> None:  # noqa: A002 - 폴링 요청마다 콘솔에 안 찍히게
        pass

    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler 관례
        parsed = urlparse(self.path)
        if parsed.path == "/":
            self._send_bytes(INDEX_HTML.encode("utf-8"), "text/html; charset=utf-8")
        elif parsed.path == "/api/engagements":
            self._send_json(list(reversed(list_engagements()))[:30])
        elif parsed.path == "/api/findings":
            self._handle_findings(parse_qs(parsed.query))
        elif parsed.path == "/api/screenshot":
            self._handle_screenshot(parse_qs(parsed.query))
        else:
            self.send_response(404)
            self.end_headers()

    def _handle_findings(self, qs: dict) -> None:
        eid = qs.get("engagement_id", [None])[0]
        since = int(qs.get("since", ["0"])[0])
        if not eid:
            self._send_json({"error": "engagement_id required"}, status=400)
            return
        findings = read_findings(eid)
        self._send_json({"total": len(findings), "events": findings[since:]})

    def _handle_screenshot(self, qs: dict) -> None:
        vm = qs.get("vm", [None])[0]
        if not vm:
            self._send_json({"error": "vm required"}, status=400)
            return
        data = _take_screenshot(vm)
        if data is None:
            self.send_response(503)
            self.end_headers()
            return
        self.send_response(200)
        self.send_header("Content-Type", "image/png")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)

    def _send_json(self, data, status: int = 200) -> None:
        self._send_bytes(json.dumps(data, ensure_ascii=False).encode("utf-8"), "application/json", status)

    def _send_bytes(self, data: bytes, content_type: str, status: int = 200) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


INDEX_HTML = r"""<!doctype html>
<html lang="ko">
<head>
<meta charset="utf-8">
<title>pentest-agent 라이브 모니터</title>
<style>
  :root { color-scheme: dark; }
  body { background: #0d1117; color: #c9d1d9; font-family: -apple-system, "Segoe UI", sans-serif; margin: 0; padding: 16px; }
  h1 { font-size: 18px; margin: 0 0 12px; }
  .row { display: flex; gap: 12px; flex-wrap: wrap; align-items: center; margin-bottom: 12px; }
  select, input[type=text] { background: #161b22; color: #c9d1d9; border: 1px solid #30363d; border-radius: 4px; padding: 4px 8px; }
  label { font-size: 13px; display: flex; align-items: center; gap: 4px; }
  .bar-wrap { background: #161b22; border: 1px solid #30363d; border-radius: 4px; height: 20px; width: 300px; overflow: hidden; }
  .bar-fill { background: #3fb950; height: 100%; transition: width 0.3s; }
  .grid { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; margin-top: 12px; }
  @media (max-width: 900px) { .grid { grid-template-columns: 1fr; } }
  .panel { background: #161b22; border: 1px solid #30363d; border-radius: 6px; padding: 12px; }
  .panel h2 { font-size: 13px; text-transform: uppercase; color: #8b949e; margin: 0 0 8px; }
  .checklist-item { padding: 4px 0; border-bottom: 1px solid #21262c; font-size: 13px; display: flex; justify-content: space-between; gap: 8px; }
  .checklist-item:last-child { border-bottom: none; }
  .ok { color: #3fb950; }
  .fail { color: #f85149; }
  #log { height: 320px; overflow-y: auto; font-family: ui-monospace, Consolas, monospace; font-size: 12px; white-space: pre-wrap; }
  .log-line { padding: 1px 0; }
  .log-stage { color: #58a6ff; }
  .screenshots { display: flex; gap: 12px; flex-wrap: wrap; }
  .screenshots img { max-width: 320px; border: 1px solid #30363d; border-radius: 4px; background: #000; }
  .shot-box { display: flex; flex-direction: column; gap: 4px; }
  .shot-box span { font-size: 12px; color: #8b949e; }
</style>
</head>
<body>
<h1>pentest-agent 라이브 모니터</h1>
<div class="row">
  <label>인게이지먼트: <select id="eid"></select></label>
  <div class="bar-wrap"><div class="bar-fill" id="bar" style="width:0%"></div></div>
  <span id="eventCount" style="font-size:12px;color:#8b949e"></span>
</div>
<div class="row">
  <label><input type="checkbox" id="shotToggle"> VM 스크린샷 보기(켜면 VM에 부하가 생길 수 있음)</label>
  <label>대상 VM: <input type="text" id="targetVm" placeholder="예: Metasploitable2" size="16"></label>
  <label>Kali 포함: <input type="checkbox" id="showKali" checked></label>
</div>
<div class="screenshots" id="screenshots"></div>

<div class="grid">
  <div class="panel">
    <h2>취약점 후보 판정 (vuln_analysis)</h2>
    <div id="vulnChecklist"></div>
  </div>
  <div class="panel">
    <h2>익스플로잇 시도 (exploitation)</h2>
    <div id="exploitChecklist"></div>
  </div>
</div>

<div class="panel" style="margin-top:16px">
  <h2>전체 이벤트 로그</h2>
  <div id="log"></div>
</div>

<script>
let since = 0;
let events = [];
const vulnByPort = new Map();
const exploitAttempts = [];

async function loadEngagements() {
  const res = await fetch('/api/engagements');
  const list = await res.json();
  const sel = document.getElementById('eid');
  const prev = sel.value;
  sel.innerHTML = list.map(e => `<option value="${e}">${e}</option>`).join('');
  if (list.includes(prev)) sel.value = prev;
}

function renderChecklist(el, items, mapFn) {
  el.innerHTML = items.map(mapFn).join('') || '<div class="checklist-item" style="color:#8b949e">아직 없음</div>';
}

function renderLog() {
  const el = document.getElementById('log');
  const atBottom = el.scrollHeight - el.scrollTop - el.clientHeight < 40;
  el.innerHTML = events.slice(-300).map(f => {
    const t = (f.ts || '').split('T')[1]?.split('.')[0] || '';
    return `<div class="log-line">[${t}] <span class="log-stage">${f.stage}</span>/${f.event}` +
           (f.target ? ` target=${f.target}` : '') + (f.port ? ` port=${f.port}` : '') + `</div>`;
  }).join('');
  if (atBottom) el.scrollTop = el.scrollHeight;
}

function renderVulnChecklist() {
  const el = document.getElementById('vulnChecklist');
  const items = [...vulnByPort.values()].sort((a, b) => a.port - b.port);
  renderChecklist(el, items, v =>
    `<div class="checklist-item"><span>포트 ${v.port} (${v.service || '?'})</span>` +
    `<span>confidence ${v.confidence?.toFixed?.(2) ?? v.confidence}, risk ${v.risk}</span></div>`);
}

function renderExploitChecklist() {
  const el = document.getElementById('exploitChecklist');
  renderChecklist(el, exploitAttempts, a =>
    `<div class="checklist-item"><span>${a.exploit || '?'} (포트 ${a.port})</span>` +
    `<span class="${a.event === 'exploit_success' ? 'ok' : 'fail'}">${a.event === 'exploit_success' ? '성공 ✓' : '실패 ✗'}</span></div>`);
}

function ingest(newEvents) {
  for (const f of newEvents) {
    events.push(f);
    if (f.stage === 'vuln_analysis' && (f.event === 'candidate_judged' || f.event === 'candidate_ranked')) {
      vulnByPort.set(f.port, f);
    }
    if (f.stage === 'exploitation' && (f.event === 'exploit_success' || f.event === 'attempt_failed') && f.exploit) {
      exploitAttempts.push(f);
    }
  }
  renderLog();
  renderVulnChecklist();
  renderExploitChecklist();
}

// 8단계 오케스트레이터(run_pipeline.py) 진행률의 근사치 - findings.jsonl에
// "지금 몇 번째 단계"라는 필드가 따로 없어서, 지금까지 등장한 stage 종류
// 개수로 근사한다(완벽하진 않지만 별도 이벤트를 새로 안 만들어도 됨).
const STAGE_ORDER = ['recon', 'scanning', 'vuln_analysis', 'exploitation', 'post_exploit', 'flag_capture', 'reporting'];
function renderBar() {
  const seen = new Set(events.map(f => f.stage));
  const reached = STAGE_ORDER.filter(s => seen.has(s)).length;
  const pct = Math.round((reached / STAGE_ORDER.length) * 100);
  document.getElementById('bar').style.width = pct + '%';
  document.getElementById('eventCount').textContent = `이벤트 ${events.length}개 (약 ${pct}%)`;
}

async function poll() {
  const eid = document.getElementById('eid').value;
  if (!eid) return;
  const res = await fetch(`/api/findings?engagement_id=${encodeURIComponent(eid)}&since=${since}`);
  const data = await res.json();
  if (data.events && data.events.length) {
    ingest(data.events);
    since = data.total;
    renderBar();
  }
}

async function pollScreenshots() {
  const el = document.getElementById('screenshots');
  if (!document.getElementById('shotToggle').checked) { el.innerHTML = ''; return; }
  const targets = [];
  if (document.getElementById('showKali').checked) targets.push('kali');
  const tv = document.getElementById('targetVm').value.trim();
  if (tv) targets.push(tv);
  el.innerHTML = targets.map(vm => `<div class="shot-box"><span>${vm}</span><img id="shot-${vm}"></div>`).join('');
  for (const vm of targets) {
    const img = document.getElementById(`shot-${vm}`);
    if (img) img.src = `/api/screenshot?vm=${encodeURIComponent(vm)}&t=${Date.now()}`;
  }
}

document.getElementById('eid').addEventListener('change', () => { since = 0; events = []; vulnByPort.clear(); exploitAttempts.length = 0; poll(); });

loadEngagements().then(poll);
setInterval(loadEngagements, 15000);
setInterval(poll, 2000);
setInterval(pollScreenshots, 4000);
</script>
</body>
</html>
"""


def run(port: int = PORT) -> None:
    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    print(f"[web_monitor] http://127.0.0.1:{port} 에서 대기 중 (Ctrl+C로 종료)")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[web_monitor] 종료")


if __name__ == "__main__":
    import sys

    p = int(sys.argv[1]) if len(sys.argv) > 1 else PORT
    run(p)
