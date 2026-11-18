# PhishEMLyzer

A Python-based phishing email forensics and SOC investigation tool designed to automate email analysis, extract indicators of compromise (IOCs), and support security investigations.

PhishEMLyzer is being developed in five phases, progressing from a CLI email analyzer to a SOC investigation platform with threat intelligence and SIEM integration.

## Features

**Phase 1 — Completed (v0.1)**
- `.eml` parsing and email header extraction
- Plain-text and HTML body extraction
- URL extraction, including HTML hyperlinks
- Attachment metadata and SHA-256 hashing
- Structured JSON investigation reports
- CLI interface and automated unit tests

## Installation & Usage

```bash
git clone https://github.com/pavanpavithran/PhishEMLyzer.git
cd PhishEMLyzer

python3 main.py -f path/to/email.eml
```

Generated reports are saved to `reports/output/`.

## Development Roadmap

| Phase | Description | Status |
|---|---|---|
| 1 | Email Forensics & CLI Analyzer | ✅ Complete |
| 2 | Phishing Detection & Risk Scoring | Planned |
| 3 | Threat Intelligence Integration | Planned |
| 4 | Web Dashboard & Case Management | Planned |
| 5 | Wazuh SIEM Integration | Planned |

## Documentation

Detailed technical documentation, implementation decisions, test results, and screenshots are available in the `docs/` directory.

- [Phase 1 — Email Forensics & Parsing](docs/01-email-parsing.md)

Documentation for subsequent phases will be added as development progresses.

## Testing

```bash
python3 -m unittest discover -s tests -v
```

**Phase 1:** 7/7 unit tests passed.

## Disclaimer

PhishEMLyzer is an educational cybersecurity project. It is not currently a production-ready phishing detection solution. Analyze only emails you are authorized to handle.