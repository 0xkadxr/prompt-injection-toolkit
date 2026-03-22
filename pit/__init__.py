"""
Prompt Injection Toolkit (PIT)
A comprehensive framework for testing LLM applications against prompt injection attacks.
"""

__version__ = "0.1.0"
__author__ = "Abdelkader Benmeriem"

from pit.core.attacker import PromptInjectionAttacker
from pit.core.target import TargetLLM
from pit.core.reporter import AttackReporter
from pit.attacks.direct import DirectInjection
from pit.attacks.indirect import IndirectInjection
from pit.attacks.multiturn import MultiTurnInjection
from pit.attacks.encoded import EncodedInjection
from pit.attacks.composite import CompositeInjection
from pit.defenses.evaluator import DefenseEvaluator

__all__ = [
    "PromptInjectionAttacker",
    "TargetLLM",
    "AttackReporter",
    "DirectInjection",
    "IndirectInjection",
    "MultiTurnInjection",
    "EncodedInjection",
    "CompositeInjection",
    "DefenseEvaluator",
]
