from __future__ import annotations

import re
from dataclasses import asdict

from .schemas import ClassificationResult, EvidenceResult, IncidentCase, PlaybookResult


IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?\b")
URL_RE = re.compile(r"https?://[^\s)]+")
EMAIL_RE = re.compile(r"[\w.+-]+@[\w.-]+")
TIMESTAMP_RE = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z")
WINDOWS_PATH_RE = re.compile(r"[A-Z]:\\(?:[^\\/:*?\"<>|\r\n]+\\)*[^\\/:*?\"<>|\r\n]+")
UNC_PATH_RE = re.compile(r"\\\\[A-Za-z0-9_.-]+\\[^\s]+")
PROCESS_RE = re.compile(r"\b(?:powershell|cmd|update|python|wscript|cscript|rundll32|regsvr32)\.exe\b", re.I)


class DeterministicIncidentAgents:
    """Local deterministic backend for repeatable course-project verification."""

    def classify(self, case: IncidentCase) -> ClassificationResult:
        text = case.raw_alert.lower()
        evidence: list[str] = []

        if any(k in text for k in ["phishing", "mailbox", "password", "mfa code", "verify the account"]):
            incident_type = "phishing"
            severity = "high"
            evidence = self._pick_evidence(case.raw_alert, ["sender", "password", "MFA", "verify", "urgent", "suspended"])
        elif any(k in text for k in ["failed login", "successful login", "no mfa", "password spraying"]):
            incident_type = "credential_abuse"
            severity = "critical" if "administrative" in text or "admin" in text else "high"
            evidence = self._pick_evidence(case.raw_alert, ["failed login", "successful login", "No MFA", "administrative", "admin"])
        elif any(k in text for k in ["powershell", "executionpolicy bypass", "scheduled task", "update.exe"]):
            incident_type = "endpoint_malware"
            severity = "critical"
            evidence = self._pick_evidence(case.raw_alert, ["powershell.exe", "ExecutionPolicy Bypass", "scheduled task", "update.exe"])
        elif any(k in text for k in ["uploaded", "gb", "salary", "dns history", "exfiltration"]):
            incident_type = "data_exfiltration"
            severity = "critical"
            evidence = self._pick_evidence(case.raw_alert, ["uploaded", "2.8 GB", "salary", "DNS history", "files-sync"])
        elif any(k in text for k in ["bucket", "public-read", "anonymous get", "cloud"]):
            incident_type = "cloud_misconfiguration"
            severity = "high"
            evidence = self._pick_evidence(case.raw_alert, ["bucket", "public-read", "anonymous GET", "database-backup"])
        elif any(k in text for k in ["or '1'='1", "/login", "http 500", "/admin/export", "sql injection"]):
            incident_type = "web_attack"
            severity = "high"
            evidence = self._pick_evidence(case.raw_alert, ["OR '1'='1", "HTTP 500", "/admin/export", "/login"])
        else:
            incident_type = "unknown"
            severity = "medium"
            evidence = ["No strong rule matched; manual review required."]

        return ClassificationResult(
            incident_type=incident_type,
            severity=severity,
            confidence=0.86 if incident_type != "unknown" else 0.45,
            supporting_evidence=evidence,
        )

    def extract_evidence(self, case: IncidentCase) -> EvidenceResult:
        raw = case.raw_alert
        urls = URL_RE.findall(raw)
        domains = sorted({u.split("//", 1)[1].split("/", 1)[0].split(":", 1)[0] for u in urls})
        ips = IP_RE.findall(raw)
        emails = EMAIL_RE.findall(raw)
        timestamps = TIMESTAMP_RE.findall(raw)
        file_paths = WINDOWS_PATH_RE.findall(raw) + UNC_PATH_RE.findall(raw)
        processes = PROCESS_RE.findall(raw)
        hosts = sorted(set(re.findall(r"\b[A-Z]+-[A-Z]+-\d+\b|\b[A-Z]+-[A-Z]+-\d{2}\b|\b[A-Z]+-[A-Z]+-[A-Z]+-\d+\b", raw)))
        commands = []
        if "ExecutionPolicy Bypass" in raw:
            commands.append("-ExecutionPolicy Bypass")
        if "OR '1'='1" in raw:
            commands.append("SQL injection pattern: OR '1'='1")

        behaviors = self._behaviors(raw)
        notes = []
        for token in sorted(set(urls + ips + emails + file_paths + processes + hosts + commands)):
            notes.append(f"Observed: {token}")
        notes.extend(behaviors)

        return EvidenceResult(
            observables={
                "ips": ips,
                "domains": domains,
                "urls": urls,
                "users": sorted(set(emails + self._users(raw))),
                "timestamps": timestamps,
                "hosts": hosts,
                "file_paths": file_paths,
                "processes": processes,
                "commands": commands,
            },
            behaviors=behaviors,
            evidence_notes=notes,
        )

    def generate_playbook(self, classification: ClassificationResult, evidence: EvidenceResult) -> PlaybookResult:
        incident_type = classification.incident_type
        common_review = [
            "Preserve the original alert, relevant logs, and generated analysis for later review.",
            "Document decisions and distinguish confirmed facts from assumptions.",
        ]
        if incident_type == "phishing":
            return PlaybookResult(
                containment=["Quarantine the email and block the sender/domain at the mail gateway.", "Warn potentially affected users not to submit credentials."],
                investigation=["Check whether users clicked the URL or submitted credentials.", "Review mailbox forwarding rules and recent login activity."],
                eradication=["Remove related messages from mailboxes.", "Block identified phishing URLs and lookalike domains."],
                recovery=["Reset passwords and MFA tokens for affected accounts.", "Restore normal mailbox access after account checks are clean."],
                post_incident_review=common_review + ["Update phishing detection rules and user awareness examples."],
            )
        if incident_type == "credential_abuse":
            return PlaybookResult(
                containment=["Disable account access temporarily for the affected account.", "Revoke sessions and block the suspicious source IP."],
                investigation=["Review MFA status, authentication logs, and privilege use.", "Review file server logs and admin activity after the successful login."],
                eradication=["Reset password and enforce MFA.", "Remove unauthorized access paths if discovered."],
                recovery=["Re-enable the account only after validation.", "Monitor for renewed password spraying attempts."],
                post_incident_review=common_review + ["Review password policy, MFA coverage, and alert thresholds."],
            )
        if incident_type == "web_attack":
            return PlaybookResult(
                containment=["Temporarily block source IP and suspicious request pattern.", "Restrict access to sensitive admin export routes."],
                investigation=["Review application logs, web server logs, and database access around the event time.", "Check whether the SQL injection attempt returned data or caused errors."],
                eradication=["Patch input validation and parameterized query handling.", "Remove exposed debug behavior that leaks HTTP 500 details."],
                recovery=["Retest the login endpoint and admin export route.", "Restore normal traffic after controls are verified."],
                post_incident_review=common_review + ["Add regression tests for injection payloads."],
            )
        if incident_type == "endpoint_malware":
            return PlaybookResult(
                containment=["Isolate the affected host from the network.", "Block the destination IP and preserve volatile evidence."],
                investigation=["Collect process tree, file hashes, PowerShell logs, and scheduled task details.", "Check hash reputation and search for the same indicators across other endpoints."],
                eradication=["Remove malicious files and eradicate persistence mechanisms such as the scheduled task.", "Reset affected credentials if credential theft is possible."],
                recovery=["Reimage or clean the endpoint according to policy.", "Return the host after endpoint protection scans are clean."],
                post_incident_review=common_review + ["Improve endpoint detection for script execution bypass behavior."],
            )
        if incident_type == "data_exfiltration":
            return PlaybookResult(
                containment=["Block destination domain and isolate workstation involved in the upload.", "Disable the suspicious temporary account if not business-critical."],
                investigation=["Review file access logs, preserve logs, upload volume, and destination reputation.", "Identify whether sensitive data left the environment."],
                eradication=["Remove unauthorized access routes and rotate credentials.", "Confirm no persistence or unauthorized sync tool remains."],
                recovery=["Restore normal access after data-owner approval.", "Increase monitoring on sensitive file shares."],
                post_incident_review=common_review + ["Notify data owner if sensitive payroll files may have been exposed.", "Review DLP coverage and outbound transfer thresholds."],
            )
        if incident_type == "cloud_misconfiguration":
            return PlaybookResult(
                containment=["Immediately revoke public-read access on the bucket.", "Disable or restrict the service account if misuse is suspected."],
                investigation=["Review access logs, object list, and permission change history.", "Identify exposed data and whether database backups or member lists were accessed anonymously."],
                eradication=["Rotate service account credentials and enforce least privilege.", "Apply bucket policy guardrails to prevent public exposure."],
                recovery=["Restore private access settings and validate access controls.", "Notify data owners if sensitive files were exposed."],
                post_incident_review=common_review + ["Add cloud policy guardrails, posture checks, and approval workflow for public access changes."],
            )
        return PlaybookResult(
            containment=["Escalate to a human analyst for manual triage."],
            investigation=["Collect more evidence and validate the alert source."],
            eradication=["Do not eradicate until the incident type is confirmed."],
            recovery=["Restore only after containment and investigation are complete."],
            post_incident_review=common_review,
        )

    def result_dict(self, obj):
        return asdict(obj)

    @staticmethod
    def _pick_evidence(text: str, needles: list[str]) -> list[str]:
        found = []
        lower = text.lower()
        for needle in needles:
            if needle.lower() in lower:
                found.append(needle)
        return found or ["Relevant evidence exists in the alert text but needs analyst review."]

    @staticmethod
    def _users(text: str) -> list[str]:
        candidates = re.findall(r"\b(?:user account|account)\s+([A-Za-z0-9_.-]+)", text)
        candidates += re.findall(r"\bfinance\.temp\b|\bncu-admin\b", text)
        return sorted(set(candidates))

    @staticmethod
    def _behaviors(text: str) -> list[str]:
        checks = [
            ("urgent", "Urgent or time-pressure language is present."),
            ("password", "Credential request or credential risk is present."),
            ("mfa", "MFA-related evidence is present."),
            ("failed login", "Repeated failed login behavior is present."),
            ("successful login", "Successful login after failures is present."),
            ("http 500", "Application error after suspicious request is present."),
            ("public-read", "Public cloud access change is present."),
            ("anonymous get", "Anonymous access activity is present."),
            ("uploaded", "Large outbound upload behavior is present."),
            ("scheduled task", "Persistence-like scheduled task behavior is present."),
            ("executionpolicy bypass", "PowerShell execution-policy bypass behavior is present."),
        ]
        lower = text.lower()
        return [description for key, description in checks if key in lower]
