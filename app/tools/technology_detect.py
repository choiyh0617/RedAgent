from __future__ import annotations

from app.core.models import TechnologyEvidence, WebProbeResult


def detect_technologies(probe: WebProbeResult) -> list[TechnologyEvidence]:
    findings: dict[str, list[str]] = {}
    headers = {header.name.lower(): header.value.lower() for header in probe.headers}
    body_preview = (probe.body_preview or "").lower()
    title = (probe.title or "").lower()
    script_urls = [script.lower() for script in probe.script_urls]

    if any("angular" in script for script in script_urls):
        _record(findings, "Angular", "script reference contains angular")
    if "ng-version" in body_preview or "_ngcontent" in body_preview:
        _record(findings, "Angular", "html contains angular runtime markers")
    if "<app-root" in body_preview and {"main.js", "polyfills.js"}.issubset({script.split("/")[-1] for script in script_urls}):
        _record(findings, "Angular", "html contains app-root and angular bundle layout")

    if any("react" in script for script in script_urls):
        _record(findings, "React", "script reference contains react")
    if "__next_data__" in body_preview:
        _record(findings, "React", "html contains next.js bootstrap data")

    if any("vue" in script for script in script_urls):
        _record(findings, "Vue.js", "script reference contains vue")
    if "data-v-" in body_preview or "__vue__" in body_preview:
        _record(findings, "Vue.js", "html contains vue runtime markers")

    if "express" in headers.get("x-powered-by", ""):
        _record(findings, "Express", "x-powered-by header contains express")
        _record(findings, "Node.js", "x-powered-by header contains express")
    if "node" in (probe.server or "").lower():
        _record(findings, "Node.js", "server header contains node")

    generator = probe.meta_tags.get("generator", "").lower()
    if "wordpress" in generator:
        _record(findings, "WordPress", "meta generator contains wordpress")
    if "swagger-ui" in body_preview or "swagger" in body_preview:
        _record(findings, "Swagger UI", "html contains swagger markers")
    if "owasp juice shop" in title or "owasp juice shop" in body_preview:
        _record(findings, "OWASP Juice Shop", "page title or html identifies owasp juice shop")
        _record(findings, "Angular", "juice shop fingerprint implies angular frontend")
        _record(findings, "Node.js", "juice shop fingerprint implies node.js backend")

    results: list[TechnologyEvidence] = []
    for name, evidence in findings.items():
        confidence = min(0.95, 0.55 + (0.15 * len(evidence)))
        results.append(TechnologyEvidence(name=name, confidence=confidence, evidence=evidence))
    return results


def _record(findings: dict[str, list[str]], technology: str, evidence: str) -> None:
    bucket = findings.setdefault(technology, [])
    if evidence not in bucket:
        bucket.append(evidence)
