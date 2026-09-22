"""Source-owned Hugging Face card metadata contracts."""

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]


class HuggingFaceCardContractTests(unittest.TestCase):
    def test_card_license_matches_checked_in_source_license(self):
        license_text = (ROOT / "LICENSE").read_text(encoding="utf-8-sig")
        self.assertIn("Apache License", license_text)
        self.assertIn("Version 2.0", license_text)

        card = (ROOT / "hf-space" / "README.md").read_text(encoding="utf-8")
        self.assertTrue(card.startswith("---\n"))
        frontmatter = card.split("---", 2)[1]
        fields = {line.strip() for line in frontmatter.splitlines() if line.strip()}
        self.assertIn("license: apache-2.0", fields)


if __name__ == "__main__":
    unittest.main()
