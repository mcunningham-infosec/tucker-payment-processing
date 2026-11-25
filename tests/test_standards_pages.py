"""
The standards write-ups (docs/standards/*.md) are the source for the website pages. These tests fail if a page is out
of date (run python deploy/build_standards.py), if an item has no valid status, or if a write-up cites a file as
evidence that doesn't exist in the repository, so the evidence links can never quietly break.

Tucker Payment Processing by Michael Cunningham. (c) 2026. Built with AI-assisted development.
"""
import importlib.util
import pathlib

ROOT = pathlib.Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("build_standards", ROOT / "deploy" / "build_standards.py")
build_standards = importlib.util.module_from_spec(spec)
spec.loader.exec_module(build_standards)


def test_standards_pages_match_the_write_ups():
    for path, expected in build_standards.build().items():
        assert path.exists(), f"{path.name} is missing: run python deploy/build_standards.py"
        assert path.read_text(encoding="utf-8") == expected, f"{path.name} is out of date: run python deploy/build_standards.py"


def test_every_item_has_a_status_and_every_cited_file_exists():
    for name, _, _, doc in build_standards.load():
        assert (ROOT / "site" / "standards" / f"{name}.pdf").exists(), f"{name}.pdf is missing"
        for sec in doc["sections"]:
            for it in sec["items"]:
                assert it["status"] in build_standards.STATUSES, f"{name}: '{it['heading']}' has status '{it['status']}'"
            for text in [sec.get("evidence", "")] + [it["evidence"] for it in sec["items"]]:
                for p in build_standards.paths(text):
                    assert (ROOT / p).exists(), f"{name} cites {p}, which doesn't exist"


def test_write_up_text_is_escaped():
    doc = build_standards.parse("# T <b>\nSub\n## H\n### I <script>\n**Status: Met**\nA <script>x</script> `app/chat.py`")
    out = build_standards.standard_page("x", doc)
    assert "<script>x" not in out and "&lt;script&gt;" in out and "/blob/main/app/chat.py" in out
