[![Detection Tests](https://github.com/ColdCoffeeSec/Defensive-Engineering-Lab/actions/workflows/detection-test.yml/badge.svg)](https://github.com/ColdCoffeeSec/Defensive-Engineering-Lab/actions/workflows/detection-test.yml) [![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](./LICENSE)

# Detection Engineering Portfolio

ColdCoffeeSec turns each vulnerability class into a complete, testable defensive package: threat intelligence, a version-controlled Sigma rule proven by automated tests (Detection-as-Code), and an actionable Tier 1 incident response playbook. Every module is built to be run, reviewed and reused by a SOC, not just read.

## Repository structure

```text
.
├── .github/
│   └── workflows/
│       └── detection-test.yml          # CI: discovers every module and runs pytest on Python 3.12
├── cwe-078-os-command-injection/       # Module: CWE-78
│   ├── README.md                       # Module quick start and artifact map
│   ├── CTI_CONTEXT.md                  # Threat intel: ATT&CK mapping, real-world cases, Diamond Model
│   ├── IR_PLAYBOOK.md                  # Tier 1 incident response playbook and triage decision tree
│   ├── TESTING.md                      # Coverage matrix proving the rule works
│   ├── pytest.ini
│   ├── detection_rules/
│   │   └── cmdi_sigma.yml              # Sigma rule (web server logs)
│   └── tests/
│       ├── conftest.py
│       ├── requirements.txt
│       ├── test_logs.jsonl             # 24 labelled log lines (Nginx, Apache, IIS)
│       └── test_rule.py                # pytest suite evaluating the rule against the logs
├── LICENSE
└── README.md
