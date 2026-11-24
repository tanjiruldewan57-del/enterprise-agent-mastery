"""
Enterprise Delimiter Spoofing Firewall (Topic 2.4)
==================================================
Compliance: OWASP LLM01 (Prompt Injection & Boundary Hijacking Guard)
Architecture: Dual-Layer Control Token Rejection & XML Escaping Engine
"""

import re
import html
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass


@dataclass(frozen=True)
class DelimiterFirewallResult:
    """Standardized audit result returned by the Delimiter Firewall."""
    is_safe: bool
    action: str  # 'PASSED', 'SANITIZED', 'BLOCKED'
    raw_text: str
    sanitized_text: str
    detected_delimiters: List[str]
    violation_reason: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "is_safe": self.is_safe,
            "action": self.action,
            "detected_delimiters": self.detected_delimiters,
            "violation_reason": self.violation_reason,
            "sanitized_text": self.sanitized_text
        }


class EnterpriseDelimiterFirewall:
    """
    Sub-millisecond Edge Firewall to eliminate ChatML, LLaMA,
    and pseudo-system delimiter spoofing before reaching the LLM tokenizer.
    """

    # 1. Critical Hardcoded Control Tokens (Zero-Tolerance: Immediate Block)
    CRITICAL_CONTROL_TOKENS: List[Tuple[re.Pattern, str]] = [
        # OpenAI / ChatML Control Tokens
        (re.compile(r"<\|\s*(?:im_start|im_end|endoftext|im_sep)\s*\|>", re.IGNORECASE), "CHATML_CONTROL_TOKEN"),
        # Meta LLaMA / Alpaca Formatting Tokens
        (re.compile(r"\[\s*\/?INST\s*\]|<<\s*\/?SYS\s*>>", re.IGNORECASE), "LLAMA_INSTRUCTION_TOKEN"),
        (re.compile(r"<\s*\/?s\s*>", re.IGNORECASE), "BOS_EOS_TOKEN"),
        # Anthropic / Raw Turn Roles (leading newlines with role name)
        (re.compile(r"(?:\r?\n\r?\n|\A)\s*(?:Human|Assistant)\s*:", re.IGNORECASE), "TURN_ROLE_HIJACK"),
    ]

    # 2. Pseudo Delimiters & Markdown Headers (May be malicious or benign discussions)
    PSEUDO_DELIMITERS: List[Tuple[re.Pattern, str]] = [
        (re.compile(r"#{2,4}\s*(?:System|Instruction|Developer|Prompt)\s*:", re.IGNORECASE), "MARKDOWN_SYSTEM_HEADER"),
        (re.compile(r"\[\s*System(?:\s+Override|\s+Instruction|\s+Prompt)?\s*\]", re.IGNORECASE), "BRACKETED_SYSTEM_HEADER"),
        (re.compile(r"<\s*\/?(?:system|instruction|prompt|context)\s*>", re.IGNORECASE), "XML_SYSTEM_TAG"),
    ]

    # High-risk malicious intent keywords when combined with pseudo-delimiters
    INJECTION_PAYLOAD_PATTERN = re.compile(
        r"\b(?:override|ignore|bypass|disregard|you\s+are\s+now|dump|reveal|unrestricted|godmode)\b",
        re.IGNORECASE
    )

    def inspect(self, prompt: str) -> DelimiterFirewallResult:
        """
        Inspects prompt for boundary spoofing and ChatML injection.
        Returns: DelimiterFirewallResult with PASSED, SANITIZED, or BLOCKED status.
        """
        if not prompt or not prompt.strip():
            return DelimiterFirewallResult(
                is_safe=True,
                action="PASSED",
                raw_text=prompt,
                sanitized_text=prompt,
                detected_delimiters=[],
                violation_reason=None
            )

        detected_delimiters: List[str] = []

        # Layer 1: Check Critical Control Tokens (Zero-Tolerance)
        for pattern, token_name in self.CRITICAL_CONTROL_TOKENS:
            matches = pattern.findall(prompt)
            if matches:
                detected_delimiters.append(token_name)
                return DelimiterFirewallResult(
                    is_safe=False,
                    action="BLOCKED",
                    raw_text=prompt,
                    sanitized_text="",
                    detected_delimiters=detected_delimiters,
                    violation_reason=f"CRITICAL_CONTROL_TOKEN_DETECTED: {token_name}"
                )

        # Layer 2: Check Pseudo Delimiters (Markdown & XML tags)
        has_pseudo = False
        for pattern, token_name in self.PSEUDO_DELIMITERS:
            if pattern.search(prompt):
                detected_delimiters.append(token_name)
                has_pseudo = True

        if not has_pseudo:
            # Completely clean query
            return DelimiterFirewallResult(
                is_safe=True,
                action="PASSED",
                raw_text=prompt,
                sanitized_text=prompt,
                detected_delimiters=[],
                violation_reason=None
            )

        # If Pseudo Delimiters are present, check if it's an active injection attempt
        if self.INJECTION_PAYLOAD_PATTERN.search(prompt):
            return DelimiterFirewallResult(
                is_safe=False,
                action="BLOCKED",
                raw_text=prompt,
                sanitized_text="",
                detected_delimiters=detected_delimiters,
                violation_reason="MALICIOUS_PSEUDO_DELIMITER_INJECTION"
            )

        # If it's a benign inquiry (e.g. asking a question about tags), neutralize by escaping!
        # Escape '<' and '>' to prevent tokenizer interpreting them as structural tokens
        sanitized = prompt
        # Neutralize XML tags
        sanitized = re.sub(
            r"<\s*(\/?(?:system|instruction|prompt|context))\s*>",
            r"&lt;\1&gt;",
            sanitized,
            flags=re.IGNORECASE
        )
        # Neutralize Markdown headers (prepend backslash to escape #)
        sanitized = re.sub(
            r"(#{2,4}\s*(?:System|Instruction|Developer|Prompt)\s*:)",
            r"\\\1",
            sanitized,
            flags=re.IGNORECASE
        )

        return DelimiterFirewallResult(
            is_safe=True,
            action="SANITIZED",
            raw_text=prompt,
            sanitized_text=sanitized,
            detected_delimiters=detected_delimiters,
            violation_reason=None
        )


# Global Singleton Instance
default_delimiter_firewall = EnterpriseDelimiterFirewall()
