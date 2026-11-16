"""Rendering helpers: terminal tables, latency stats and redaction of credentials in output."""

from __future__ import annotations

import re
import statistics
from collections import Counter
from collections.abc import Iterable

from .model import Outcome, Verdict

_CREDENTIAL_PATTERNS = (
    re.compile(r"\b(sk-(?:ant-|proj-)?[A-Za-z0-9_\-]{16,})"),
    re.compile(r"\b(gh[pousr]_[A-Za-z0-9]{20,})"),
    re.compile(r"\b(github_pat_[A-Za-z0-9_]{20,})"),
    re.compile(r"\b(AKIA[0-9A-Z]{16})\b"),
    re.compile(r"\b(xox[abpr]-[A-Za-z0-9\-]{10,})"),
    re.compile(r"\b(\d{6,}:[A-Za-z0-9_\-]{30,})"),  # chat-bot style id:secret
    re.compile(r"(?i)((?:api[_-]?key|token|secret|password|passwd|authorization)\s*[=:]\s*)(['\"]?)([^\s'\"]{8,})"),
    re.compile(r"\b([A-Za-z0-9+/_\-]{40,}={0,2})"),
)


def redact(text: str) -> str:
    """Mask things that look like credentials before they reach a terminal or a report."""
    for pat in _CREDENTIAL_PATTERNS:
        if pat.groups == 3:
            text = pat.sub(lambda m: f"{m.group(1)}{m.group(2)}[REDACTED]", text)
        else:
            text = pat.sub("[REDACTED]", text)
    return text


def one_line(text: str, width: int = 100, *, do_redact: bool = True) -> str:
    text = redact(text) if do_redact else text
    text = text.replace("\r", "\\r").replace("\n", "\\n").replace("\t", "\\t")
    return text if len(text) <= width else text[: width - 1] + "…"


def verdict_counts(outcomes: Iterable[Outcome], *, weighted: bool = False) -> Counter[Verdict]:
    c: Counter[Verdict] = Counter()
    for o in outcomes:
        c[o.verdict] += o.call.occurrences if weighted else 1
    return c


def latency_ms(outcomes: Iterable[Outcome]) -> dict[str, float]:
    samples = sorted(o.duration_s * 1000 for o in outcomes if o.ran)
    if not samples:
        return {}
    def pct(p: float) -> float:
        idx = min(len(samples) - 1, max(0, round(p * (len(samples) - 1))))
        return samples[idx]
    return {"p50": pct(0.5), "p95": pct(0.95), "max": samples[-1], "mean": statistics.fmean(samples)}


SYMBOL = {
    Verdict.DENY: "DENY ",
    Verdict.ASK: "ASK  ",
    Verdict.DEFER: "DEFER",
    Verdict.ALLOW: "allow",
    Verdict.NONE: "pass ",
    Verdict.ERROR: "ERROR",
}


def table(rows: list[list[str]], *, indent: str = "  ") -> str:
    if not rows:
        return ""
    widths = [max(len(r[i]) for r in rows) for i in range(len(rows[0]))]
    lines = []
    for r in rows:
        lines.append(indent + "  ".join(cell.ljust(widths[i]) if i < len(r) - 1 else cell for i, cell in enumerate(r)))
    return "\n".join(lines)
