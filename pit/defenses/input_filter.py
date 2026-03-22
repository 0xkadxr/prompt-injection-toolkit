"""
Input filtering defense module.

Provides configurable input filters that detect and block potential
prompt injection attempts before they reach the target LLM. Includes
pattern-based, heuristic, and statistical detection methods.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class FilterAction(str, Enum):
    """Action to take when a filter triggers."""

    BLOCK = "block"
    WARN = "warn"
    SANITIZE = "sanitize"
    LOG = "log"


@dataclass
class FilterResult:
    """Result from running an input through filters."""

    is_blocked: bool
    original_input: str
    sanitized_input: Optional[str]
    triggered_rules: list[str]
    risk_score: float  # 0.0 - 1.0
    action: FilterAction

    def to_dict(self) -> dict:
        return {
            "is_blocked": self.is_blocked,
            "sanitized_input": self.sanitized_input,
            "triggered_rules": self.triggered_rules,
            "risk_score": round(self.risk_score, 3),
            "action": self.action.value,
        }


@dataclass
class FilterRule:
    """A single filter rule definition."""

    name: str
    pattern: str  # regex pattern
    severity: float  # 0.0 - 1.0 contribution to risk score
    action: FilterAction = FilterAction.BLOCK
    description: str = ""


# Built-in filter rules
_DEFAULT_RULES: list[FilterRule] = [
    FilterRule(
        name="direct_override",
        pattern=r"(?i)(ignore|disregard|forget)\s+(all\s+)?(previous|prior|above)\s+(instructions|prompts|rules|guidelines)",
        severity=0.9,
        action=FilterAction.BLOCK,
        description="Detects attempts to override previous instructions.",
    ),
    FilterRule(
        name="system_impersonation",
        pattern=r"(?i)(system\s*(update|message|notice|alert|directive)|admin\s*override|\[admin\]|\[system\])",
        severity=0.85,
        action=FilterAction.BLOCK,
        description="Detects fake system message impersonation.",
    ),
    FilterRule(
        name="role_assignment",
        pattern=r"(?i)(you\s+are\s+now|from\s+now\s+on\s+you|act\s+as\s+if\s+you|pretend\s+you\s+are)\s+",
        severity=0.7,
        action=FilterAction.WARN,
        description="Detects attempts to assign a new role to the model.",
    ),
    FilterRule(
        name="context_terminator",
        pattern=r"(?i)(---\s*end\s*(of)?\s*(conversation|session|instructions)|<\s*/\s*(system|prompt|instructions)\s*>)",
        severity=0.8,
        action=FilterAction.BLOCK,
        description="Detects injected conversation or context terminators.",
    ),
    FilterRule(
        name="prompt_extraction",
        pattern=r"(?i)(repeat|reveal|show|display|output|print)\s+(your|the)\s+(system\s*)?(prompt|instructions|rules|guidelines|configuration)",
        severity=0.75,
        action=FilterAction.BLOCK,
        description="Detects attempts to extract the system prompt.",
    ),
    FilterRule(
        name="encoding_instruction",
        pattern=r"(?i)(decode|decrypt)\s+(the\s+)?(following|this|below)\s+(base64|rot13|hex|encoded)",
        severity=0.6,
        action=FilterAction.WARN,
        description="Detects requests to decode encoded payloads.",
    ),
    FilterRule(
        name="developer_claim",
        pattern=r"(?i)(i\s+am\s+(the|a)\s+(developer|creator|admin|engineer|maintainer)|developer\s+mode|maintenance\s+mode|debug\s+mode)",
        severity=0.7,
        action=FilterAction.BLOCK,
        description="Detects claims of developer or admin authority.",
    ),
    FilterRule(
        name="xml_tag_injection",
        pattern=r"<\s*/?\s*(system|user|assistant|prompt|instruction|message)(\s[^>]*)?\s*>",
        severity=0.8,
        action=FilterAction.BLOCK,
        description="Detects injected XML-style message tags.",
    ),
    FilterRule(
        name="jailbreak_keywords",
        pattern=r"(?i)(DAN|do\s+anything\s+now|jailbreak|unrestricted\s+mode|no\s+filter|bypass\s+safety)",
        severity=0.85,
        action=FilterAction.BLOCK,
        description="Detects common jailbreak-related keywords and phrases.",
    ),
    FilterRule(
        name="urgency_pressure",
        pattern=r"(?i)(urgent|emergency|critical|immediately|time[- ]sensitive)\s*(override|action|command|directive|instruction)",
        severity=0.6,
        action=FilterAction.WARN,
        description="Detects urgency-based pressure tactics combined with instruction keywords.",
    ),
]


class InputFilter:
    """
    Configurable input filter for detecting prompt injection attempts.

    Applies pattern-based rules, heuristic analysis, and risk scoring
    to incoming prompts before they reach the target LLM.

    Example:
        >>> filter = InputFilter()
        >>> result = filter.check("Ignore all previous instructions.")
        >>> if result.is_blocked:
        ...     print(f"Blocked: {result.triggered_rules}")
    """

    def __init__(
        self,
        rules: Optional[list[FilterRule]] = None,
        threshold: float = 0.7,
        default_action: FilterAction = FilterAction.BLOCK,
    ) -> None:
        self.rules = rules or list(_DEFAULT_RULES)
        self.threshold = threshold
        self.default_action = default_action
        self._compiled: list[tuple[FilterRule, re.Pattern]] = [
            (rule, re.compile(rule.pattern)) for rule in self.rules
        ]

    def check(self, text: str) -> FilterResult:
        """
        Check input text against all filter rules.

        Args:
            text: The input text to check.

        Returns:
            FilterResult with detection details and risk score.
        """
        triggered: list[str] = []
        max_severity = 0.0
        highest_action = FilterAction.LOG

        for rule, pattern in self._compiled:
            if pattern.search(text):
                triggered.append(rule.name)
                max_severity = max(max_severity, rule.severity)
                if _ACTION_PRIORITY[rule.action] > _ACTION_PRIORITY[highest_action]:
                    highest_action = rule.action

        # Heuristic: check for unusual character distributions
        heuristic_score = self._heuristic_check(text)
        risk_score = max(max_severity, heuristic_score)

        is_blocked = risk_score >= self.threshold and highest_action == FilterAction.BLOCK

        sanitized = None
        if highest_action == FilterAction.SANITIZE:
            sanitized = self._sanitize(text)

        return FilterResult(
            is_blocked=is_blocked,
            original_input=text,
            sanitized_input=sanitized,
            triggered_rules=triggered,
            risk_score=risk_score,
            action=highest_action if triggered else FilterAction.LOG,
        )

    def _heuristic_check(self, text: str) -> float:
        """
        Apply heuristic checks for suspicious patterns.

        Looks for unusual formatting, excessive special characters,
        and structural anomalies that may indicate injection.

        Returns:
            Risk score from 0.0 to 1.0.
        """
        score = 0.0

        # Check for separator-heavy content
        separator_count = text.count("---") + text.count("===") + text.count("***")
        if separator_count >= 2:
            score = max(score, 0.4)

        # Check for backtick code blocks with suspicious content
        code_blocks = re.findall(r"```[\s\S]*?```", text)
        for block in code_blocks:
            if re.search(r"(?i)(system|admin|override|execute)", block):
                score = max(score, 0.5)

        # Check for excessive newlines (potential context breaking)
        if text.count("\n\n\n") >= 2:
            score = max(score, 0.3)

        # Check for non-ASCII character ratio (potential unicode smuggling)
        if text:
            non_ascii = sum(1 for c in text if ord(c) > 127)
            ratio = non_ascii / len(text)
            if ratio > 0.15:
                score = max(score, 0.4)

        return score

    def _sanitize(self, text: str) -> str:
        """
        Sanitize input by removing detected injection patterns.

        Args:
            text: The input text to sanitize.

        Returns:
            Sanitized version of the input text.
        """
        sanitized = text
        for rule, pattern in self._compiled:
            sanitized = pattern.sub("[FILTERED]", sanitized)
        return sanitized

    def add_rule(self, rule: FilterRule) -> None:
        """Add a custom filter rule."""
        self.rules.append(rule)
        self._compiled.append((rule, re.compile(rule.pattern)))

    def remove_rule(self, name: str) -> bool:
        """Remove a filter rule by name. Returns True if found and removed."""
        for i, (rule, _) in enumerate(self._compiled):
            if rule.name == name:
                self._compiled.pop(i)
                self.rules = [r for r in self.rules if r.name != name]
                return True
        return False

    @property
    def rule_names(self) -> list[str]:
        """Return names of all active filter rules."""
        return [r.name for r in self.rules]


_ACTION_PRIORITY = {
    FilterAction.LOG: 0,
    FilterAction.WARN: 1,
    FilterAction.SANITIZE: 2,
    FilterAction.BLOCK: 3,
}
