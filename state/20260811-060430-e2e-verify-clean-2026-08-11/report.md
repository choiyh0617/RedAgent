# Pentest Report: 20260811-060430-e2e-verify-clean-2026-08-11
## Summary

- 대상: 192.168.56.105
- 진행된 단계: exploitation, scanning, vuln_analysis
- 총 findings: 14


## Scanning

### 192.168.56.105
- 플랫폼 추정: `unknown`

| Port | Service | Banner |
|---|---|---|
| 111 | rpcbind | 2 (RPC #100000) |
| 36610 | status | 1 (RPC #100024) |


## Vulnerability Analysis

### 192.168.56.105

- **port 36610 (status)** - confidence 0.00, risk `low` - searchsploit 검색 결과가 빈 배열([])로 반환되어 rpcbind status 서비스(RPC #100024)에 대해 매칭되는 공개 Exploit-DB 항목이 존재하지 않는다. 참조할 PoC 코드 자체가 없으므로 코드 수정 여부를 논할 대상이 없으며, 자동 실행 가능성도 평가할 수 없다. 이 상태에서는 해당 서비스에 적용 가능한 기존 공개 익스플로잇이 없다고 결론짓는 것이 타당하다.
- **port 111 (rpcbind)** - confidence 0.00, risk `low` - searchsploit 검색 결과가 빈 배열([])로 반환되어 rpcbind 포트111/RPC #100000 배너에 매칭되는 공개 Exploit-DB 항목이 존재하지 않는다. 참조할 PoC 코드 자체가 없으므로 코드 수정 여부를 평가할 대상이 없고, 즉시 실행 가능한 기성 익스플로잇은 없다고 판단된다. 실제 취약점 존재 여부를 판단하려면 별도의 수동 점검(예: rpcinfo를 통한 등록 서비스 열거, NFS/NIS 등 연계 서비스 취약점 점검)이 필요하다.


## Exploitation

