import json
from pathlib import Path
from typing import Any, Dict, List

# 解析 Trivy JSON 报告并生成精简摘要，避免把大 JSON 直接交给 LLM。

SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]


def load_report(report_path: Path) -> Dict[str, Any]:
    with report_path.open("r", encoding="utf-8") as f:
        return json.load(f)


def _collect_items(results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """提取漏洞和配置问题，统一字段，便于排序。"""
    items: List[Dict[str, Any]] = []
    for entry in results:
        for vuln in entry.get("Vulnerabilities", []) or []:
            items.append(
                {
                    "id": vuln.get("VulnerabilityID"),
                    "title": vuln.get("Title") or vuln.get("Description"),
                    "severity": vuln.get("Severity"),
                    "pkg": vuln.get("PkgName"),
                    "type": "vuln",
                }
            )
        for mis in entry.get("Misconfigurations", []) or []:
            items.append(
                {
                    "id": mis.get("ID"),
                    "title": mis.get("Title") or mis.get("Description"),
                    "severity": mis.get("Severity"),
                    "pkg": mis.get("Target"),
                    "type": "misconfig",
                }
            )
    return items


def _severity_rank(sev: str) -> int:
    try:
        return SEVERITY_ORDER.index(sev.upper())
    except Exception:
        return len(SEVERITY_ORDER)


def summarize_report(report_path: Path, top_k: int = 5) -> Dict[str, Any]:
    """返回摘要信息：高危计数、Top K 风险条目、总数."""
    data = load_report(report_path)
    results = data.get("Results") or []
    items = _collect_items(results)

    high = sum(1 for i in items if (i.get("severity") or "").upper() == "HIGH")
    critical = sum(1 for i in items if (i.get("severity") or "").upper() == "CRITICAL")

    # 按严重度排序，严重度相同保持原顺序
    sorted_items = sorted(items, key=lambda x: _severity_rank(x.get("severity") or "ZZZ"))
    top_items = sorted_items[:top_k]

    top_brief = [
        {
            "id": i.get("id"),
            "title": i.get("title"),
            "severity": i.get("severity"),
            "pkg": i.get("pkg"),
            "type": i.get("type"),
        }
        for i in top_items
    ]

    summary_text = (
        f"扫描完成。High: {high}, Critical: {critical}。"
        f" Top {len(top_brief)} 风险示例: "
        + "; ".join(
            f"[{t.get('severity')}] {t.get('id')} - {t.get('title')}"
            for t in top_brief
            if t.get("id")
        )
    )

    return {
        "summary_text": summary_text,
        "high": high,
        "critical": critical,
        "top": top_brief,
        "total_findings": len(items),
    }
