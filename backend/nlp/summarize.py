"""Extractive summary generator with no model download required."""
import re


def summarize(text: str, max_sentences: int = 3) -> str:
    sentences = [s.strip() for s in re.split(r"(?<=[.!?])\s+", text.strip()) if s.strip()]
    if len(sentences) <= max_sentences:
        return " ".join(sentences)
    ranked = sorted(enumerate(sentences), key=lambda x: len(re.findall(r"\w+", x[1])), reverse=True)[:max_sentences]
    return " ".join(sentence for _, sentence in sorted(ranked))
