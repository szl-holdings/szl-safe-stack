---
title: SZL Safe Stack Source
emoji: 📦
colorFrom: blue
colorTo: gray
sdk: static
app_file: index.html
pinned: false
license: apache-2.0
---

# SZL Safe Stack source distribution

This private Space distributes the Python software source from
[`szl-holdings/szl-safe-stack`](https://github.com/szl-holdings/szl-safe-stack/tree/{{SOURCE_SHA}})
at immutable GitHub revision `{{SOURCE_SHA}}`.

Download [the source archive](source.tar.gz), [the self-contained Markdown/Python
payload](source_payload.md), or [the source manifest](source-manifest.json).
The archive SHA-256 is `{{ARCHIVE_SHA256}}`.

The payload verifies and extracts source into a new local directory. It does not
install dependencies or deploy infrastructure. The source contains the Safe QA
API, PostgreSQL audit ledger migrations, policy and approval verification,
container definitions, tests, and deployment documentation, plus the Frontier
Evidence Gateway. Read the extracted root README for setup and verification.

This static download page does not host the API or PostgreSQL database. Cloud
enforcement, credential revocation, independent human approval, third-party
witnessing, and model training are not established by publishing source here.
Clinical and biological claims remain unverified.
