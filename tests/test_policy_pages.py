"""
The policy pages on the website are generated from policies/*.md, the same documents Tucker answers from.
These tests fail if someone edits a policy without rebuilding the pages (python deploy/build_policy_pages.py),
so what visitors read can never drift from what the AI is told.

Tucker Payment Processing by Michael Cunningham. (c) 2026. Built with AI-assisted development.
"""
import importlib.util
import pathlib

ROOT = pathlib.Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("build_policy_pages", ROOT / "deploy" / "build_policy_pages.py")
build_policy_pages = importlib.util.module_from_spec(spec)
spec.loader.exec_module(build_policy_pages)


def test_policy_pages_match_the_policy_documents():
    for path, expected in build_policy_pages.build().items():
        assert path.exists(), f"{path.name} is missing: run python deploy/build_policy_pages.py"
        assert path.read_text(encoding="utf-8") == expected, f"{path.name} is out of date: run python deploy/build_policy_pages.py"


def test_policy_text_is_escaped():
    p = build_policy_pages.parse("# T <b>\nSub\n## H & co\nA <script>x</script> line")
    out = build_policy_pages.policy_page("x", p)
    assert "<script>x" not in out and "&lt;script&gt;" in out and "H &amp; co" in out
