"""The repository security policy and README stay true to the source they ship with."""

from pathlib import Path
import re
import tomllib
import unittest

from tools import publish_hf_source as publisher


ROOT = Path(__file__).resolve().parents[1]
POLICY = ROOT / "SECURITY.md"
DOCUMENTS = ("README.md", "SECURITY.md")
COMPONENTS = ("safe-qa-service", "frontier-evidence-gateway")
PRIVATE_CLASSIFIER = "Private :: Do Not Upload"
FENCE = re.compile(r"(?ms)^```.*?^```[^\n]*$")
LINK = re.compile(r"\]\(([^)\s]+)\)")
HEADING = re.compile(r"(?m)^#{1,6} (.+?)\s*$")


def _prose(name: str) -> str:
    return FENCE.sub("", (ROOT / name).read_text(encoding="utf-8"))


def _anchor(heading: str) -> str:
    # GitHub heading anchors: lower case, punctuation dropped, spaces become hyphens.
    return re.sub(r"[^\w\- ]", "", heading.lower()).replace(" ", "-")


class SecurityPolicyTests(unittest.TestCase):
    def test_relative_links_resolve_in_checkout_and_source_distribution(self):
        for name in DOCUMENTS:
            text = _prose(name)
            anchors = {_anchor(heading) for heading in HEADING.findall(text)}
            targets = [target for target in LINK.findall(text)
                       if "://" not in target and not target.startswith("mailto:")]
            self.assertTrue(targets, name)
            for target in targets:
                path, _, anchor = target.partition("#")
                with self.subTest(document=name, target=target):
                    if not path:
                        self.assertIn(anchor, anchors)
                        continue
                    self.assertTrue((ROOT / path).is_file(), "link target is not a checked-in file")
                    # README.md and SECURITY.md travel in the private source archive,
                    # so every file they link to must travel with them.
                    self.assertTrue(publisher.allowed_source_path(path), "link target is left out of the source archive")

    def test_unpublished_statement_matches_component_metadata(self):
        self.assertIn(PRIVATE_CLASSIFIER, POLICY.read_text(encoding="utf-8"))
        for component in COMPONENTS:
            with self.subTest(component=component):
                text = (ROOT / component / "pyproject.toml").read_text(encoding="utf-8")
                self.assertIn(PRIVATE_CLASSIFIER, tomllib.loads(text)["project"]["classifiers"])


if __name__ == "__main__":
    unittest.main()
