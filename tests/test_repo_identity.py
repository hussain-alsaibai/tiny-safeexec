"""Guards that this repo cannot silently drift back into a confusing clone.

Added 2026-11-04. `tiny-safeexec` shipped as a byte-identical copy of
`tiny-sandbox` -- same 681-line module, same test file, same LICENSE, same
SECURITY.md, and a README whose H1 was `# tiny-sandbox`. The only difference
between the two repositories was one CI badge URL.

Both also declared `name = "tiny-sandbox"` in pyproject.toml, so only one of
them could ever be published, and nobody could tell which from the README.

These tests fail if any of that quietly comes back.
"""
import io
import pathlib
import re

ROOT = pathlib.Path(__file__).resolve().parents[1]


def test_package_name_is_not_the_other_repo():
    """This repo must not claim the `tiny-sandbox` package name."""
    text = io.open(ROOT / "pyproject.toml", encoding="utf-8").read()
    match = re.search(r'^name\s*=\s*["\']([^"\']+)["\']', text, re.M)
    assert match, "pyproject.toml should declare a package name"
    assert match.group(1) == "tiny-safeexec", (
        f"package name is {match.group(1)!r}; this repo must not claim "
        "the tiny-sandbox package name -- that belongs to tiny-sandbox"
    )


def test_readme_says_it_is_a_copy():
    """The README must point readers at the original."""
    text = io.open(ROOT / "README.md", encoding="utf-8").read()
    assert "tiny-sandbox" in text, "the README should mention tiny-sandbox"
    assert re.search(r"\bcopy\b", text, re.I), (
        "the README must state plainly that this repository is a copy"
    )


def test_readme_title_does_not_claim_to_be_the_other_repo():
    """The H1 must not say `# tiny-sandbox` -- that is what misled readers."""
    text = io.open(ROOT / "README.md", encoding="utf-8").read()
    title = text.split("\n", 1)[0].strip()
    assert not re.match(r"^#\s+tiny-sandbox\s*$", title), (
        f"README title is {title!r}; it must not present this repo as tiny-sandbox"
    )
