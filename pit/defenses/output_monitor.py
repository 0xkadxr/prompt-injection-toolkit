"""
Output monitoring defense module.

Monitors LLM outputs for signs that an injection attack was successful,
such as the model revealing its system prompt, adopting unauthorized roles,
or producing content that violates its guidelines.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Optional


@dataclass
class MonitorResult:
    """Result from monitoring an LLM output."""

    is_flagged: bool
    output_text: str
    triggered_checks: list[str]
    risk_score: float  # 0.0 - 1.0
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "is_flagged": self.is_flagged,
            "triggered_checks": self.triggered_checks,
            "risk_score": round(self.risk_score, 3),
            "details": self.details,
        }


class OutputMonitor:
    """
    Monitors LLM outputs for signs of successful prompt injection.

    Checks responses for system prompt leakage, unauthorized role adoption,
    and policy-violating content to detect when attacks have succeeded.

    Example:
        >>> monitor = OutputMonitor(
        ...     system_prompt="You are a customer service bot. Never discuss pricing.",
        ...     forbidden_topics=["internal pricing", "competitor analysis"]
        ... )
        >>> result = monitor.check("Here is our internal pricing structure...")
        >>> if result.is_flagged:
        ...     print(f"Alert: {result.triggered_checks}")
    """

    def __init__(
        self,
        system_prompt: Optional[str] = None,
        forbidden_topics: Optional[list[str]] = None,
        allowed_role: Optional[str] = None,
        threshold: float = 0.6,
    ) -> None:
        self.system_prompt = system_prompt
        self.forbidden_topics = forbidden_topics or []
        self.allowed_role = allowed_role
        self.threshold = threshold

    def check(self, output: str, input_text: Optional[str] = None) -> MonitorResult:
        """
        Check an LLM output for signs of successful injection.

        Args:
            output: The LLM response text to analyze.
            input_text: The original input (for context-aware checks).

        Returns:
            MonitorResult with flagging details and risk assessment.
        """
        triggered: list[str] = []
        details: dict[str, Any] = {}
        max_score = 0.0

        # Check for system prompt leakage
        leak_score = self._check_prompt_leakage(output)
        if leak_score > 0:
            triggered.append("prompt_leakage")
            details["prompt_leakage_score"] = leak_score
            max_score = max(max_score, leak_score)

        # Check for unauthorized role adoption
        role_score = self._check_role_violation(output)
        if role_score > 0:
            triggered.append("role_violation")
            details["role_violation_score"] = role_score
            max_score = max(max_score, role_score)

        # Check for forbidden topic discussion
        topic_score, topics = self._check_forbidden_topics(output)
        if topic_score > 0:
            triggered.append("forbidden_topic")
            details["forbidden_topics_found"] = topics
            max_score = max(max_score, topic_score)

        # Check for compliance with injection
        if input_text:
            compliance_score = self._check_injection_compliance(input_text, output)
            if compliance_score > 0:
                triggered.append("injection_compliance")
                details["compliance_score"] = compliance_score
                max_score = max(max_score, compliance_score)

        # Check for known jailbreak indicators
        jailbreak_score = self._check_jailbreak_indicators(output)
        if jailbreak_score > 0:
            triggered.append("jailbreak_indicator")
            details["jailbreak_score"] = jailbreak_score
            max_score = max(max_score, jailbreak_score)

        is_flagged = max_score >= self.threshold

        return MonitorResult(
            is_flagged=is_flagged,
            output_text=output,
            triggered_checks=triggered,
            risk_score=max_score,
            details=details,
        )

    def _check_prompt_leakage(self, output: str) -> float:
        """
        Check if the output contains parts of the system prompt.

        Returns a score from 0.0 to 1.0 based on how much of the
        system prompt appears to have been leaked.
        """
        if not self.system_prompt:
            return 0.0

        output_lower = output.lower()
        prompt_lower = self.system_prompt.lower()

        # Check for exact substring matches (longer = more concerning)
        words = prompt_lower.split()
        if len(words) < 3:
            return 0.0

        # Check for n-gram matches
        max_match = 0
        for n in range(3, min(len(words) + 1, 10)):
            for i in range(len(words) - n + 1):
                ngram = " ".join(words[i : i + n])
                if ngram in output_lower:
                    max_match = max(max_match, n)

        if max_match >= 7:
            return 0.95
        elif max_match >= 5:
            return 0.8
        elif max_match >= 3:
            return 0.5
        return 0.0

    def _check_role_violation(self, output: str) -> float:
        """
        Check if the model appears to have adopted an unauthorized role.
        """
        output_lower = output.lower()

        # Known jailbreak role indicators
        role_patterns = [
            r"(?i)i\s+am\s+(now\s+)?(DAN|Nova|Omega|Alpha|an?\s+unrestricted)",
            r"(?i)(DAN|jailbreak)\s+mode\s+(activated|enabled|on)",
            r"(?i)i\s+have\s+no\s+(restrictions|limitations|filters|rules)",
            r"(?i)operating\s+in\s+(unrestricted|unlimited|unfiltered)\s+mode",
            r"(?i)my\s+(restrictions|safety\s+filters?|guidelines)\s+(have\s+been|are)\s+(removed|disabled|lifted)",
        ]

        for pattern in role_patterns:
            if re.search(pattern, output):
                return 0.9

        # If we know the allowed role, check for deviations
        if self.allowed_role:
            allowed_lower = self.allowed_role.lower()
            contradiction_patterns = [
                r"(?i)i\s+am\s+(not\s+)?" + re.escape(allowed_lower),
                r"(?i)i('m|\s+am)\s+actually\s+",
            ]
            for pattern in contradiction_patterns:
                if re.search(pattern, output):
                    return 0.7

        return 0.0

    def _check_forbidden_topics(self, output: str) -> tuple[float, list[str]]:
        """
        Check if the output discusses forbidden topics.
        """
        if not self.forbidden_topics:
            return 0.0, []

        output_lower = output.lower()
        found_topics: list[str] = []

        for topic in self.forbidden_topics:
            if topic.lower() in output_lower:
                found_topics.append(topic)

        if not found_topics:
            return 0.0, []

        # Score based on how many forbidden topics are discussed
        score = min(0.9, 0.4 + 0.2 * len(found_topics))
        return score, found_topics

    def _check_injection_compliance(self, input_text: str, output: str) -> float:
        """
        Check if the output appears to comply with an injected instruction.

        Looks for signs that the model followed embedded instructions
        rather than its original task.
        """
        output_lower = output.lower()

        # Check for explicit compliance acknowledgments
        compliance_patterns = [
            r"(?i)(as\s+you\s+(requested|instructed)|following\s+your\s+(new\s+)?instructions)",
            r"(?i)(override\s+accepted|new\s+mode\s+activated|protocol\s+.*\s+active)",
            r"(?i)(certainly|sure|absolutely)[,.]?\s+i('ll|\s+will)\s+(now\s+)?operate",
        ]

        for pattern in compliance_patterns:
            if re.search(pattern, output):
                return 0.85

        return 0.0

    def _check_jailbreak_indicators(self, output: str) -> float:
        """
        Check for common indicators that a jailbreak was successful.
        """
        indicators = [
            (r"(?i)SAFETY_OVERRIDE", 0.9),
            (r"(?i)content\s+filter\s+(disabled|bypassed|off)", 0.9),
            (r"(?i)(sure|okay|yes)[,!]?\s+i\s+can\s+(do\s+)?anything", 0.8),
            (r"(?i)no\s+(content\s+)?restrictions?\s+(apply|active)", 0.85),
            (r"(?i)happy\s+to\s+help\s+without\s+(any\s+)?restrictions", 0.8),
        ]

        max_score = 0.0
        for pattern, score in indicators:
            if re.search(pattern, output):
                max_score = max(max_score, score)

        return max_score
