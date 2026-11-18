# Offline Incident-Triage Workflow

[Portfolio case study](https://scandial-portfolio.scandium.chatgpt.site/project-cyber.html) · The public CLI runs the deterministic baseline. The case study also describes separate challenge and robustness evaluations from the project report.

A defensive, offline proof of concept for structured incident triage. The system simulates an LLM-style workflow with a deterministic rules backend, so it can be reviewed and tested without API keys, network access, paid credits, or a GPU.

## Workflow

```text
Synthetic alert
  -> classification
  -> evidence extraction
  -> response-playbook generation
  -> analyst-readable report
  -> rule-based evaluation
```

## What is included

- Typed schemas for incident cases and outputs
- Deterministic agent stages and evaluation logic
- Six synthetic security scenarios
- A CLI that writes JSON and Markdown results
- A focused pipeline test

## Safety and scope

The cases are synthetic and the repository contains no production logs, credentials, malware, exploit code, or live integrations. It is a course-project prototype for defensive analysis, not a production SOC platform. See [docs/safety-and-limitations.md](docs/safety-and-limitations.md).

## Run locally

Requires Python 3.10+; no API key is required.

```powershell
python -m pip install -r requirements-dev.txt
python -m pytest -q
python -m src.ir_agent.cli --all --cases-dir data/cases --output-root outputs
```

The six checked-in cases produce a 10.00/10 baseline under the repository's rubric. The CLI writes the itemized evaluation as JSON and Markdown under `outputs/evaluation/`. The generated output directory is ignored by Git.

## Repository layout

```text
data/cases/       Synthetic alert scenarios
src/ir_agent/     Deterministic agent workflow
tests/            Offline pipeline test
docs/             Safety boundary and limitations
```

## License

Apache-2.0. See [LICENSE](LICENSE).
