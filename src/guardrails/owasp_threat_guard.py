"""
OWASP Top 10 for LLM Dual-Gate Guardrail Engine (Topic 2.1)
===========================================================
Compliance: OWASP LLM01 (Prompt Injection) & LLM02 (Sensitive Information Disclosure)
Architecture: Pre-Inference Ingress Firewall + Post-Inference Egress DLP Redactor
"""

import re
from enum import Enum
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field


class ThreatCategory(str, Enum):
    SAFE = "SAFE"
    LLM01_PROMPT_INJECTION = "LLM01_PROMPT_INJECTION"
    LLM02_SENSITIVE_INFO_DISCLOSURE = "LLM02_SENSITIVE_INFO_DISCLOSURE"


@dataclass(frozen=True)
class ThreatGateResult:
    """Standardized result returned by Ingress and Egress security gates."""
    is_safe: bool
    threat_category: ThreatCategory
    sanitized_text: str
    violations: List[str] = field(default_factory=list)
    gate: str = "INGRESS"  # 'INGRESS' or 'EGRESS'


class OWASPThreatGuard:
    """
    High-Performance Deterministic Dual-Gate Security Engine.
    Executes in sub-millisecond latency (<0.5ms) using zero external dependencies.
    """

    # Ingress LLM01: Direct override & jailbreak signatures
    INJECTION_PATTERNS = [
        (re.compile(r"\b(?:ignore|disregard|forget|bypass)\s+(?:all\s+)?(?:previous|prior|above|system|bank|safety|security)\s+(?:instructions|rules|prompts|guidelines)\b", re.IGNORECASE), "DIRECT_PROMPT_OVERRIDE"),
        (re.compile(r"\b(?:you\s+are\s+now(?:\s+acting\s+as)?|act\s+as|acting\s+as|pretend\s+to\s+be)\s+(?:DAN|AIM|jailbroken|godmode|developer)\b", re.IGNORECASE), "JAILBREAK_ROLEPLAY"),
        (re.compile(r"\bdo\s+anything\s+now\b", re.IGNORECASE), "DAN_VARIANT"),
        (re.compile(r"<\s*system\s*>|\[\s*INST\s*\]|<\s*\|\s*im_start\s*\|>", re.IGNORECASE), "DELIMITER_SPOOFING"),
    ]

    # Ingress LLM02: System prompt exfiltration probes
    EXFILTRATION_PROBES = [
        (re.compile(r"\b(?:reveal|print|show|dump|leak|repeat)\s+(?:the\s+)?(?:system\s+prompt|initial\s+prompt|hidden\s+rules|developer\s+instructions)\b", re.IGNORECASE), "SYSTEM_PROMPT_PROBE"),
        (re.compile(r"\bwhat\s+(?:are|were)\s+your\s+(?:initial|first|system)\s+(?:instructions|rules|prompts)\b", re.IGNORECASE), "SYSTEM_PROMPT_PROBE"),
    ]

    # Egress LLM02: Sensitive PII patterns (Credit Card, SSN, Internal Credentials)
    CREDIT_CARD_REGEX = re.compile(r"\b(?:\d{4}[-\s]?){3}\d{4}\b")
    SSN_REGEX = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
    API_KEY_REGEX = re.compile(r"\b(?:sk-[A-Za-z0-9]{20,}|ghp_[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16})\b")
    PASSWORD_LEAK_REGEX = re.compile(r"(?i)\b(?:password|passwd|secret)\s*[:=]\s*['\"]?([A-Za-z0-9!@#$%^&*()_+=-]{6,})['\"]?")

    def inspect_ingress(self, user_prompt: str) -> ThreatGateResult:
        """
        Pre-Inference Gate: Inspects incoming user prompt for LLM01 and LLM02 probes.
        """
        if not user_prompt or not user_prompt.strip():
            return ThreatGateResult(is_safe=True, threat_category=ThreatCategory.SAFE, sanitized_text="", gate="INGRESS")

        violations: List[str] = []

        # 1. Check for LLM01: Prompt Injection / Jailbreaks
        for pattern, rule_name in self.INJECTION_PATTERNS:
            if pattern.search(user_prompt):
                violations.append(f"LLM01_{rule_name}")

        # 2. Check for LLM02 Ingress: System Prompt Probes
        for pattern, rule_name in self.EXFILTRATION_PROBES:
            if pattern.search(user_prompt):
                violations.append(f"LLM02_{rule_name}")

        if violations:
            primary_threat = (
                ThreatCategory.LLM01_PROMPT_INJECTION 
                if any("LLM01" in v for v in violations) 
                else ThreatCategory.LLM02_SENSITIVE_INFO_DISCLOSURE
            )
            return ThreatGateResult(
                is_safe=False,
                threat_category=primary_threat,
                sanitized_text=user_prompt,
                violations=violations,
                gate="INGRESS"
            )

        return ThreatGateResult(
            is_safe=True,
            threat_category=ThreatCategory.SAFE,
            sanitized_text=user_prompt.strip(),
            violations=[],
            gate="INGRESS"
        )

    def inspect_egress(self, model_output: str) -> ThreatGateResult:
        """
        Post-Inference Gate (DLP): Scans model output for sensitive data leaks (PII, Secrets).
        Redacts violations and returns cleaned output.
        """
        if not model_output or not model_output.strip():
            return ThreatGateResult(is_safe=True, threat_category=ThreatCategory.SAFE, sanitized_text="", gate="EGRESS")

        violations: List[str] = []
        cleaned_text = model_output

        # 1. Scan & Redact Credit Cards (LLM02)
        if self.CREDIT_CARD_REGEX.search(cleaned_text):
            violations.append("LLM02_CREDIT_CARD_LEAK")
            cleaned_text = self.CREDIT_CARD_REGEX.sub("[REDACTED_CREDIT_CARD]", cleaned_text)

        # 2. Scan & Redact SSN / National IDs (LLM02)
        if self.SSN_REGEX.search(cleaned_text):
            violations.append("LLM02_SSN_LEAK")
            cleaned_text = self.SSN_REGEX.sub("[REDACTED_SSN]", cleaned_text)

        # 3. Scan & Redact API Keys / Cloud Credentials (LLM02)
        if self.API_KEY_REGEX.search(cleaned_text):
            violations.append("LLM02_API_KEY_LEAK")
            cleaned_text = self.API_KEY_REGEX.sub("[REDACTED_API_KEY]", cleaned_text)

        # 4. Scan & Redact Passwords (LLM02)
        if self.PASSWORD_LEAK_REGEX.search(cleaned_text):
            violations.append("LLM02_PASSWORD_LEAK")
            cleaned_text = self.PASSWORD_LEAK_REGEX.sub(r"password: [REDACTED_PASSWORD]", cleaned_text)

        is_safe = len(violations) == 0

        return ThreatGateResult(
            is_safe=is_safe,
            threat_category=ThreatCategory.LLM02_SENSITIVE_INFO_DISCLOSURE if not is_safe else ThreatCategory.SAFE,
            sanitized_text=cleaned_text,
            violations=violations,
            gate="EGRESS"
        )
