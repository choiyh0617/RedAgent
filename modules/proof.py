"""
플래그가 없는 대상(Metasploitable2 등 CTF용이 아닌 이미지)에서 권한상승을
증명할 스크린샷을 만든다. DESIGN.md 63절.

**왜 필요한가**: Metasploitable2는 flag 파일이 애초에 없는 범용 취약점 실습
이미지라(59절), root 셸을 획득해도 `flag_capture.py`가 찾을 게 없어서 "성공"의
증거가 findings.jsonl 텍스트 로그 말고는 안 남는다. 사용자 요청: "flag가
존재하지 않는 경우엔 권한상승을 증명할 수 있는 스크린샷을 가지고 나와서
report". VirtualBox VM 콘솔을 직접 캡처(`screenshotpng`)하는 건 안 맞다 -
이 프로젝트의 모든 익스플로잇은 네트워크로만 들어가서(Metasploit/커맨드
인젝션), VM 콘솔 화면 자체엔 로그인 프롬프트 말고 아무 변화가 없다(사용자도
확인 후 동의 - "명령 출력 기반 이미지" 방식 선택). 그래서 실제 세션 출력
(uid=0 등 권한상승 증거)을 텍스트 대신 **이미지로 렌더링**해서 report.md
옆에 파일로 남긴다 - 대화형 Artifact 도구(이 대화 세션 전용)에 의존하면 이
코드를 독립 실행할 때 동작 안 하므로, PIL로 로컬에서 직접 PNG를 그린다.
"""

from datetime import datetime, timezone
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

from core import config  # noqa: F401 - import 시점에 .env를 로드함 + stdout UTF-8 고정
from core.engagement import engagement_dir

_FONT_CANDIDATES = [
    r"C:\Windows\Fonts\consola.ttf",
    r"C:\Windows\Fonts\cour.ttf",
    "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf",
]
_FONT_SIZE = 16
_PADDING = 24
_LINE_HEIGHT = 22
_BG_COLOR = (12, 12, 12)
_FG_COLOR = (0, 230, 90)
_HEADER_COLOR = (255, 255, 255)
_DIM_COLOR = (140, 140, 140)


def _load_font() -> ImageFont.FreeTypeFont:
    for path in _FONT_CANDIDATES:
        if Path(path).exists():
            return ImageFont.truetype(path, _FONT_SIZE)
    return ImageFont.load_default()


def generate_proof_image(
    engagement_id: str, target: str, exploit: str, proof_output: str, extra_lines: list[str] | None = None,
) -> str:
    """세션 출력(uid=0 등)을 터미널 스타일 PNG로 렌더링해서
    `state/<engagement_id>/proof_<timestamp>.png`에 저장하고 경로를 반환한다.
    flag가 없는 대상에서 report.md가 인용할 "권한상승 증거"로 씀."""
    font = _load_font()
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    header_lines = [
        "=== PRIVILEGE ESCALATION PROOF ===",
        f"engagement: {engagement_id}",
        f"target: {target}",
        f"exploit: {exploit}",
        f"captured: {ts}",
        "-" * 60,
    ]
    body_lines = proof_output.strip().splitlines() or ["(빈 출력)"]
    footer_lines = (["-" * 60] + extra_lines) if extra_lines else []
    all_lines = header_lines + body_lines + footer_lines

    width = 900
    height = _PADDING * 2 + _LINE_HEIGHT * len(all_lines)
    img = Image.new("RGB", (width, height), color=_BG_COLOR)
    draw = ImageDraw.Draw(img)

    y = _PADDING
    for i, line in enumerate(all_lines):
        if i < len(header_lines):
            color = _HEADER_COLOR if i == 0 else _DIM_COLOR
        elif i >= len(header_lines) + len(body_lines):
            color = _DIM_COLOR
        else:
            color = _FG_COLOR
        draw.text((_PADDING, y), line, font=font, fill=color)
        y += _LINE_HEIGHT

    out_dir = engagement_dir(engagement_id)
    out_dir.mkdir(parents=True, exist_ok=True)
    filename = f"proof_{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}.png"
    out_path = out_dir / filename
    img.save(out_path)
    return str(out_path)


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 4:
        print("usage: python -m modules.proof <engagement_id> <target> <exploit>")
        sys.exit(1)

    sample_output = (
        "Meterpreter session 1 opened (192.168.56.101:4444 -> 192.168.56.105:50190)\n\n"
        "meterpreter > shell\nProcess 1 created.\nChannel 1 created.\n"
        "id\nuid=0(root) gid=0(root) groups=0(root)\nhostname\nmetasploitable.localdomain"
    )
    path = generate_proof_image(sys.argv[1], sys.argv[2], sys.argv[3], sample_output)
    print(f"저장됨: {path}")
