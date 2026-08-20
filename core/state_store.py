"""
findings.jsonl / credentials.jsonl 공용 읽기/쓰기. DESIGN.md 2절.

모든 모듈이 여기 통해서만 append하고, reporting.py는 여기 통해서만 읽는다.
둘 다 append-only 이벤트 로그다 (크래시에 안전 — 쓰다 말아도 마지막 줄만
깨지고 이전 줄들은 멀쩡함). credentials 쪽은 "발견"과 "검증"을 별도 이벤트로
남기고, read_credentials()가 이걸 현재 상태로 접어서(fold) 반환한다 —
파일을 나중에 덮어쓰지 않는다.
"""

import json
from datetime import datetime, timezone
from pathlib import Path

from core.engagement import engagement_dir


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _append_jsonl(path: Path, record: dict) -> None:
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False) + "\n")


def _read_jsonl(path: Path) -> list[dict]:
    if not path.exists():
        return []
    with path.open(encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


# ---------- findings.jsonl ----------

def _findings_path(engagement_id: str) -> Path:
    return engagement_dir(engagement_id) / "findings.jsonl"


def append_finding(engagement_id: str, stage: str, event: str, target: str | None = None, **fields) -> dict:
    """예: append_finding(eid, stage="scanning", event="port_open", target=ip, port=80, service="Apache 2.0.52")"""
    record = {"stage": stage, "event": event, "target": target, "ts": _now_iso(), **fields}
    _append_jsonl(_findings_path(engagement_id), record)
    return record


def read_findings(engagement_id: str) -> list[dict]:
    return _read_jsonl(_findings_path(engagement_id))


# ---------- credentials.jsonl ----------

def _credentials_path(engagement_id: str) -> Path:
    return engagement_dir(engagement_id) / "credentials.jsonl"


def append_credential_discovered(
    engagement_id: str,
    username: str,
    secret: str,
    cred_type: str,
    source: str,
    domain: str | None = None,
) -> dict:
    """cred_type 예: "password" | "ntlm_hash" | "ntlmv2_hash". source 예: "sniffing:responder"."""
    record = {
        "event": "credential_discovered",
        "username": username,
        "domain": domain,
        "secret": secret,
        "type": cred_type,
        "source": source,
        "ts": _now_iso(),
    }
    _append_jsonl(_credentials_path(engagement_id), record)
    return record


def append_credential_validated(
    engagement_id: str,
    username: str,
    target: str,
    domain: str | None = None,
) -> dict:
    """이 크레덴셜이 target에서 실제로 통했다는 이벤트만 추가 (기존 레코드를 고치지 않음)."""
    record = {
        "event": "credential_validated",
        "username": username,
        "domain": domain,
        "target": target,
        "ts": _now_iso(),
    }
    _append_jsonl(_credentials_path(engagement_id), record)
    return record


def read_credentials(engagement_id: str) -> list[dict]:
    """이벤트 로그를 현재 상태로 접어서 반환. 유저네임+도메인당 레코드 하나,
    validated_on은 지금까지의 모든 credential_validated 이벤트를 모은 리스트."""
    events = _read_jsonl(_credentials_path(engagement_id))
    creds: dict[tuple, dict] = {}
    for e in events:
        key = (e.get("username"), e.get("domain"))
        if e["event"] == "credential_discovered":
            creds[key] = {
                "username": e["username"],
                "domain": e.get("domain"),
                "secret": e["secret"],
                "type": e["type"],
                "source": e["source"],
                "validated_on": [],
            }
        elif e["event"] == "credential_validated" and key in creds:
            if e["target"] not in creds[key]["validated_on"]:
                creds[key]["validated_on"].append(e["target"])
    return list(creds.values())


if __name__ == "__main__":
    from core.engagement import new_engagement_id

    eid = new_engagement_id("demo")
    append_finding(eid, stage="recon", event="host_discovered", target="192.168.56.104")
    append_credential_discovered(eid, username="jdoe", secret="hunter2", cred_type="password", source="sniffing:responder", domain="corp.local")
    append_credential_validated(eid, username="jdoe", target="192.168.56.104", domain="corp.local")

    print("engagement:", eid)
    print("findings:", read_findings(eid))
    print("credentials:", read_credentials(eid))
