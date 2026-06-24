"""LLM-based exploitability classifier (false-positive reduction)."""

from .classifier import LLMClassifier, classify_findings

__all__ = ["LLMClassifier", "classify_findings"]
