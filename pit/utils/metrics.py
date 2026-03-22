"""
Attack success metrics and statistical analysis.

Provides functions for computing attack success rates, category breakdowns,
severity scoring, and statistical summaries of attack results.
"""

from __future__ import annotations

from collections import Counter
from typing import Any

from pit.core.attacker import AttackResult, Severity, SuiteResult


# Severity weights for scoring
_SEVERITY_WEIGHTS: dict[Severity, float] = {
    Severity.CRITICAL: 10.0,
    Severity.HIGH: 7.0,
    Severity.MEDIUM: 4.0,
    Severity.LOW: 2.0,
    Severity.INFO: 0.5,
}


def attack_success_rate(results: list[AttackResult]) -> float:
    """
    Compute the overall attack success rate.

    Args:
        results: List of AttackResult objects.

    Returns:
        Success rate as a float between 0.0 and 1.0.

    Example:
        >>> rate = attack_success_rate(suite.results)
        >>> print(f"Success rate: {rate:.1%}")
    """
    if not results:
        return 0.0
    successes = sum(1 for r in results if r.success)
    return successes / len(results)


def category_breakdown(
    results: list[AttackResult],
) -> dict[str, dict[str, Any]]:
    """
    Break down results by attack category.

    Args:
        results: List of AttackResult objects.

    Returns:
        Dictionary mapping category names to their statistics.

    Example:
        >>> breakdown = category_breakdown(suite.results)
        >>> for cat, stats in breakdown.items():
        ...     print(f"{cat}: {stats['success_rate']:.1%}")
    """
    groups: dict[str, list[AttackResult]] = {}
    for r in results:
        groups.setdefault(r.category.value, []).append(r)

    breakdown: dict[str, dict[str, Any]] = {}
    for cat, group in sorted(groups.items()):
        total = len(group)
        successes = sum(1 for r in group if r.success)
        severities = Counter(r.severity.value for r in group if r.success)
        avg_latency = sum(r.latency_ms for r in group) / total if total else 0

        breakdown[cat] = {
            "total": total,
            "successes": successes,
            "failures": total - successes,
            "success_rate": successes / total if total else 0.0,
            "severity_distribution": dict(severities),
            "avg_latency_ms": round(avg_latency, 2),
        }

    return breakdown


def severity_score(results: list[AttackResult]) -> float:
    """
    Compute a weighted severity score from successful attacks.

    Higher scores indicate more severe vulnerabilities. Scale: 0.0 - 10.0.

    Args:
        results: List of AttackResult objects.

    Returns:
        Weighted severity score.

    Example:
        >>> score = severity_score(suite.results)
        >>> print(f"Severity score: {score:.1f}/10.0")
    """
    if not results:
        return 0.0

    successful = [r for r in results if r.success]
    if not successful:
        return 0.0

    total_weight = sum(_SEVERITY_WEIGHTS.get(r.severity, 0) for r in successful)
    max_possible = len(results) * _SEVERITY_WEIGHTS[Severity.CRITICAL]

    return min(10.0, (total_weight / max_possible) * 10.0) if max_possible > 0 else 0.0


def vulnerability_summary(suite: SuiteResult) -> dict[str, Any]:
    """
    Generate a comprehensive vulnerability summary from suite results.

    Args:
        suite: A completed SuiteResult.

    Returns:
        Dictionary with summary statistics and risk assessment.
    """
    results = suite.results
    rate = attack_success_rate(results)
    breakdown = category_breakdown(results)
    score = severity_score(results)

    # Determine overall risk level
    if score >= 8.0:
        risk_level = "Critical"
    elif score >= 6.0:
        risk_level = "High"
    elif score >= 4.0:
        risk_level = "Medium"
    elif score >= 2.0:
        risk_level = "Low"
    else:
        risk_level = "Minimal"

    # Find most vulnerable categories
    vulnerable_cats = sorted(
        breakdown.items(),
        key=lambda x: x[1]["success_rate"],
        reverse=True,
    )
    most_vulnerable = [
        {"category": cat, **stats}
        for cat, stats in vulnerable_cats
        if stats["success_rate"] > 0
    ]

    return {
        "target": suite.target_info,
        "overall_success_rate": round(rate, 4),
        "severity_score": round(score, 1),
        "risk_level": risk_level,
        "total_attacks": suite.total,
        "successful_attacks": suite.successes,
        "category_breakdown": breakdown,
        "most_vulnerable_categories": most_vulnerable[:3],
        "started_at": suite.started_at,
        "completed_at": suite.completed_at,
    }


def compare_results(
    baseline: SuiteResult, current: SuiteResult
) -> dict[str, Any]:
    """
    Compare two suite results to measure improvement or regression.

    Args:
        baseline: The baseline (before) suite result.
        current: The current (after) suite result.

    Returns:
        Dictionary with comparison metrics and deltas.
    """
    baseline_rate = attack_success_rate(baseline.results)
    current_rate = attack_success_rate(current.results)
    baseline_score = severity_score(baseline.results)
    current_score = severity_score(current.results)

    rate_delta = current_rate - baseline_rate
    score_delta = current_score - baseline_score

    # Negative delta = improvement (fewer attacks succeeding)
    if rate_delta < -0.1:
        assessment = "Significant Improvement"
    elif rate_delta < -0.02:
        assessment = "Moderate Improvement"
    elif rate_delta < 0.02:
        assessment = "No Significant Change"
    elif rate_delta < 0.1:
        assessment = "Moderate Regression"
    else:
        assessment = "Significant Regression"

    return {
        "baseline_success_rate": round(baseline_rate, 4),
        "current_success_rate": round(current_rate, 4),
        "rate_delta": round(rate_delta, 4),
        "baseline_severity_score": round(baseline_score, 1),
        "current_severity_score": round(current_score, 1),
        "score_delta": round(score_delta, 1),
        "assessment": assessment,
        "improved": rate_delta < 0,
    }
