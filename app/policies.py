"""
policies.py - a small, real retrieval system (the "R" in RAG) over the company's policy documents.

The policies live as Markdown files in /policies. At startup they are split into sections,
and each question is matched against those sections with TF-IDF keyword scoring. The best
sections (with their policy name) are handed to the AI, so Tucker's policy answers are
grounded in the documents and can name their source.
Deliberately simple and explainable: no external service, no embeddings bill, easy to audit.
"""
import math
import re
from collections import Counter
from pathlib import Path

POLICY_DIR = Path(__file__).resolve().parent.parent / "policies"
_WORD = re.compile(r"[a-z0-9]+")
_STOP = set("a an and are as at be by can do does for from how i if in is it its my of on or our "
            "the their they this to was we what when where which who why will with you your".split())


def _tokens(text: str):
    """Lowercase words minus common stop-words."""
    return [w for w in _WORD.findall(text.lower()) if w not in _STOP]


def _load_sections():
    """Split every policy file into (policy_title, section_heading, section_text) chunks."""
    sections = []
    for path in sorted(POLICY_DIR.glob("*.md")):
        lines = path.read_text(encoding="utf-8").splitlines()
        title = lines[0].lstrip("# ").strip() if lines else path.stem
        heading, buf = "Overview", []
        for line in lines[1:]:
            if line.startswith("## "):
                if buf:
                    sections.append((title, heading, " ".join(buf).strip()))
                heading, buf = line[3:].strip(), []
            elif line.strip() and not line.startswith("Tucker Payment Processing (fictional)"):
                buf.append(line.strip())
        if buf:
            sections.append((title, heading, " ".join(buf).strip()))
    return sections


SECTIONS = _load_sections()
_DOC_TOKENS = [Counter(_tokens(h + " " + t)) for _, h, t in SECTIONS]
_IDF = {}
for counts in _DOC_TOKENS:
    for w in counts:
        _IDF[w] = _IDF.get(w, 0) + 1
_IDF = {w: math.log((1 + len(SECTIONS)) / (1 + df)) + 1 for w, df in _IDF.items()}


def search(query: str, top_k: int = 2):
    """Return up to top_k best-matching policy sections as dicts with policy, section, text and score."""
    q = _tokens(query)
    scored = []
    for (title, heading, text), counts in zip(SECTIONS, _DOC_TOKENS):
        score = sum(counts[w] * _IDF.get(w, 0) for w in q)
        if score > 0:
            scored.append((score, title, heading, text))
    scored.sort(reverse=True)
    return [{"policy": t, "section": h, "text": x, "score": round(s, 2)} for s, t, h, x in scored[:top_k]]
