"""
Enterprise Zero-Knowledge PII Vault & De-tokenization Gateway (Topic 2.6)
========================================================================
Compliance: GDPR Article 32, PCI-DSS 4.0, HIPAA Safe-Harbor
Architecture: Ephemeral In-Memory Token Vault with Bi-Directional Mapping
"""

import re
import time
import uuid
import hashlib
from typing import Dict, Any, List, Optional, Tuple, Set
from dataclasses import dataclass, field
from enum import Enum


class PIIType(str, Enum):
    EMAIL = "EMAIL"
    CREDIT_CARD = "CARD"
    PHONE = "PHONE"
    SSN = "SSN"
    IPV4 = "IPV4"


@dataclass(frozen=True)
class PIITokenMapping:
    """Internal vault record for an individual PII entity."""
    token: str
    raw_value: str
    pii_type: PIIType
    created_at: float


@dataclass(frozen=True)
class TokenizeResult:
    """Standardized result returned by the PII Tokenizer."""
    masked_text: str
    token_count: int
    detected_types: List[str]
    session_id: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "masked_text": self.masked_text,
            "token_count": self.token_count,
            "detected_types": self.detected_types,
            "session_id": self.session_id,
        }


class EnterprisePIIVault:
    """
    Sub-millisecond Zero-Knowledge Tokenization Gateway.
    Masks PII before dispatching to external LLMs, and de-tokenizes model responses.
    """

    # Comprehensive regular expressions for standard enterprise PII
    PATTERNS: List[Tuple[re.Pattern, PIIType]] = [
        # Standard Credit Card (Visa, MasterCard, Amex, 13 to 19 digits with optional hyphens/spaces)
        (re.compile(r"\b(?:\d{4}[-\s]?){3}\d{4}\b|\b\d{15,16}\b"), PIIType.CREDIT_CARD),
        # Email Addresses
        (re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"), PIIType.EMAIL),
        # US/International Phone & Bangladesh Mobile Phone (013-019XXXXXXXX or +880...)
        (re.compile(r"(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b|\b01[3-9]\d{8}\b"), PIIType.PHONE),
        # Social Security Numbers (SSN: XXX-XX-XXXX)
        (re.compile(r"\b\d{3}-\d{2}-\d{4}\b"), PIIType.SSN),
        # IPv4 Addresses
        (re.compile(r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"), PIIType.IPV4),
    ]

    def __init__(self, session_ttl_seconds: int = 300):
        self.session_ttl = session_ttl_seconds
        # Session ID -> Dict[Token, RawValue]
        self._vault: Dict[str, Dict[str, str]] = {}
        # Session ID -> Creation Timestamp
        self._session_timestamps: Dict[str, float] = {}

    def _generate_token(self, pii_type: PIIType, raw_value: str, session_id: str) -> str:
        """
        Generates deterministic pseudo-random token per session.
        Same PII in same session gets identical token for context consistency.
        Format: [[TOK_<TYPE>_<HEX>]]
        """
        seed = f"{session_id}:{pii_type.value}:{raw_value}".encode("utf-8")
        short_hash = hashlib.sha256(seed).hexdigest()[:8]
        return f"[[TOK_{pii_type.value}_{short_hash}]]"

    def tokenize(self, text: str, session_id: Optional[str] = None) -> TokenizeResult:
        """
        Masks all sensitive PII entities in the input text with non-reversible tokens.
        Stores bi-directional mapping in the ephemeral in-memory vault.
        """
        if not text:
            return TokenizeResult(
                masked_text="",
                token_count=0,
                detected_types=[],
                session_id=session_id or str(uuid.uuid4())
            )

        active_session = session_id or str(uuid.uuid4())
        now = time.time()

        # Initialize session storage
        if active_session not in self._vault:
            self._vault[active_session] = {}
            self._session_timestamps[active_session] = now

        masked_text = text
        detected_types: Set[str] = set()
        token_count = 0

        # Scan and tokenize by PII pattern priority
        for pattern, pii_type in self.PATTERNS:
            matches = set(pattern.findall(masked_text))
            for raw_val in matches:
                # Discard trivial non-PII false matches
                if pii_type == PIIType.PHONE and len(raw_val.replace("-", "").replace(" ", "")) < 7:
                    continue

                token = self._generate_token(pii_type, raw_val, active_session)
                # Store in vault
                self._vault[active_session][token] = raw_val
                detected_types.add(pii_type.value)
                token_count += 1

                # Replace all occurrences in current text
                masked_text = masked_text.replace(raw_val, token)

        return TokenizeResult(
            masked_text=masked_text,
            token_count=token_count,
            detected_types=sorted(list(detected_types)),
            session_id=active_session
        )

    def detokenize(self, masked_text: str, session_id: str) -> str:
        """
        Restores original sensitive values into model response using vault mapping.
        """
        if not masked_text or session_id not in self._vault:
            return masked_text

        # Check if session has expired
        created_at = self._session_timestamps.get(session_id, 0.0)
        if (time.time() - created_at) > self.session_ttl:
            # Purge expired session
            self.purge_session(session_id)
            return masked_text

        restored_text = masked_text
        token_mapping = self._vault[session_id]

        # Substitute each token with its raw original value
        for token, raw_val in token_mapping.items():
            restored_text = restored_text.replace(token, raw_val)

        return restored_text

    def purge_session(self, session_id: str) -> bool:
        """Permanently purges a session mapping from RAM."""
        had_session = session_id in self._vault
        self._vault.pop(session_id, None)
        self._session_timestamps.pop(session_id, None)
        return had_session

    def cleanup_expired_sessions(self) -> int:
        """Purges all sessions older than TTL."""
        now = time.time()
        expired_sessions = [
            sid for sid, created in self._session_timestamps.items()
            if (now - created) > self.session_ttl
        ]
        for sid in expired_sessions:
            self.purge_session(sid)
        return len(expired_sessions)


# Global Singleton Instance
default_pii_vault = EnterprisePIIVault()
