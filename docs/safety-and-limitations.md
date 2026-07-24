# Safety and limitations

## Defensive boundary

This repository analyzes synthetic incident descriptions. It does not connect to networks, execute alerts, contact third-party services, retrieve credentials, or contain malware or exploit payloads.

The phishing-like URLs and process names inside the synthetic cases are inert examples used only as text for a classifier. They use reserved example domains and are not targets for interaction.

## Limitations

- The implementation is deterministic rather than an API-backed LLM.
- The rules are deliberately narrow and do not substitute for SOC review.
- The generated playbooks are learning artifacts, not operational security advice for a live incident.
- False positives and missed detections remain possible.

Use controlled, synthetic data when experimenting. Do not upload production logs, credentials, or sensitive indicators to this project.
