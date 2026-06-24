"""LLM-based exploitability classifier.

Recent independent research (e.g. the Konvu / ZeroPath analyses) showed that
LLM-based post-filtering of SAST results can cut false-positive rates from
>92% down to ~6.3%. TaintScope implements this as an optional layer: after
the symbolic engine emits findings, each finding is sent to an LLM along
with the rendered data-flow path and a short prompt asking it to classify
the finding as ``exploitable``, ``likely-false-positive``, or ``uncertain``
with a confidence and a one-paragraph reasoning.

The classifier is deliberately conservative: only ``likely-false-positive``
verdicts above a configurable confidence threshold are *suppressed*; everything
else is kept. This preserves the soundness guarantee of the symbolic engine
while reducing noise for the operator.
"""

from __future__ import annotations

import json
import re
from typing import List, Optional

from ..config import settings
from ..taint.engine import Finding


_SYSTEM_PROMPT = (
    "You are a senior application security reviewer. You are given taint-analysis "
    "findings produced by a static analyzer. For each finding, decide whether the "
    "data flow represents a genuinely exploitable vulnerability or a false positive. "
    "Consider: whether the source is truly attacker-controlled, whether an effective "
    "sanitizer exists in the path, whether the sink is reachable, and whether the "
    "tainted data can actually affect the dangerous operation. Respond ONLY with "
    "compact JSON matching the requested schema."
)

_USER_TEMPLATE = (
    "Classify this taint finding. Language: {language}. Category: {category}. "
    "Source: {source}. Sink: {sink}. Sink location: {sink_location}. "
    "Data flow: {flow}.\n\n"
    "Respond as JSON with keys: "
    '"verdict" (one of "exploitable", "likely-false-positive", "uncertain"), '
    '"confidence" (0.0-1.0 float), "reasoning" (one short paragraph).'
)


class LLMClassifier:
    """Wraps the OpenAI chat API for finding classification."""

    def __init__(self, api_key: Optional[str] = None, model: Optional[str] = None) -> None:
        self.api_key = api_key or settings.openai_api_key
        self.model = model or settings.openai_model
        self._client = None

    @property
    def enabled(self) -> bool:
        return bool(self.api_key) and settings.llm_enabled

    def _client_obj(self):
        if self._client is None:
            from openai import OpenAI

            self._client = OpenAI(api_key=self.api_key)
        return self._client

    def classify_one(self, finding: Finding) -> None:
        """Mutates ``finding`` in place, setting llm_* fields."""
        if not self.enabled:
            return
        prompt = _USER_TEMPLATE.format(
            language=finding.language,
            category=finding.category,
            source=finding.source,
            sink=finding.sink,
            sink_location=finding.sink_location or "unknown",
            flow=finding.flow,
        )
        try:
            resp = self._client_obj().chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": _SYSTEM_PROMPT},
                    {"role": "user", "content": prompt},
                ],
                temperature=0.0,
                response_format={"type": "json_object"},
            )
            content = resp.choices[0].message.content or "{}"
            data = json.loads(content)
            finding.llm_verdict = data.get("verdict", "uncertain")
            finding.llm_confidence = float(data.get("confidence", 0.0))
            finding.llm_reasoning = data.get("reasoning", "")
        except Exception as e:  # network / API errors -> mark uncertain
            finding.llm_verdict = "uncertain"
            finding.llm_confidence = 0.0
            finding.llm_reasoning = f"LLM classification failed: {e}"

    def classify(self, findings: List[Finding]) -> List[Finding]:
        for f in findings:
            self.classify_one(f)
        return findings

    def filter_false_positives(self, findings: List[Finding], threshold: float = 0.7) -> List[Finding]:
        """Return findings that are NOT high-confidence false positives."""
        kept: List[Finding] = []
        for f in findings:
            if f.llm_verdict == "likely-false-positive" and (f.llm_confidence or 0) >= threshold:
                continue
            kept.append(f)
        return kept


def classify_findings(findings: List[Finding], classifier: Optional[LLMClassifier] = None) -> List[Finding]:
    """Convenience function: classify and return the (unfiltered) findings."""
    clf = classifier or LLMClassifier()
    if not clf.enabled:
        return findings
    return clf.classify(findings)
