"""
RAG 인터페이스 — 지금은 껍데기만 (DESIGN.md 9절 참고).

지금 당장은 필요 없음(searchsploit/netexec/BloodHound가 이미 구조화된 검색
역할을 하고, 일반적인 privesc/AD 패턴은 모델이 이미 앎). 다만 나중에
"회사 요청으로 분리망 안에서, 주어진 매뉴얼/가이드라인 문서를 참고해서 진행"
같은 시나리오가 생기면, 이미 완성된 LLM 호출 코드(vuln_analysis.py,
post_exploit.py)를 리팩터링하는 비용이 지금 인터페이스를 만들어두는 비용보다
훨씬 크다. 그래서 자리만 선점해둔다.

TODO (실제 구현, 지금은 안 함):
- 로컬 문서(매뉴얼/가이드라인) 임베딩 + 벡터 검색 - **벡터 스토어는 LanceDB
  사용 예정**(사용자 결정). 임베디드 방식이라 별도 서버 프로세스 없이
  `state/` 밑에 로컬 파일로 저장 가능 - 이 프로젝트가 지금까지 써온 "별도
  인프라(Neo4j 등) 없이 로컬 파일로 해결" 방침(BloodHound를 Neo4j 없이 JSON만
  쓴 것과 같은 이유, 8-2절)과 일치해서 선택.
- vuln_analysis.py / post_exploit.py 프롬프트 조립부에서 retrieve() 결과를
  추가 컨텍스트로 삽입
"""


def retrieve(query: str) -> list[str]:
    """MVP: 항상 빈 리스트. 나중에 벡터 검색으로 교체."""
    return []
