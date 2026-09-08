"""风险评分：与 agent1 保持一致的 0-10 分口径。"""

SEV_WEIGHT = {"CRITICAL": 10, "HIGH": 8, "MEDIUM": 6, "LOW": 4}


def risk_score(severity: str | None, cvss: float | None, known_exploited: bool) -> float:
    """单条漏洞风险分：取 max(级别权重, CVSS)，KEV +2（上限 10）。"""
    sev = (severity or "").upper()
    score = SEV_WEIGHT.get(sev, 5.0)
    if cvss is not None:
        score = max(score, float(cvss))
    if known_exploited:
        score = min(10.0, score + 2.0)
    return round(score, 1)


def host_risk(matches: list[dict]) -> float:
    """资产风险 = 命中漏洞的最高风险分；无命中为 0。"""
    if not matches:
        return 0.0
    return max(risk_score(m["severity"], m["cvss_score"], bool(m["known_exploited"]))
               for m in matches)


def risk_level(score: float) -> str:
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score > 0:
        return "LOW"
    return "NONE"
