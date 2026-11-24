"""
Enterprise Obfuscation De-cloaking & Deep Payload Inspector (Topic 2.3)
=======================================================================
Compliance: OWASP LLM01 Defense-in-Depth (Anti-Evasion Gate)
Architecture: Recursive Base64 & Hexadecimal De-cloaking Engine
"""

import re
import base64
import binascii
from typing import Dict, Any, List, Optional, Tuple, Set
from dataclasses import dataclass, field


@dataclass(frozen=True)
class DeCloakResult:
    """Standardized audit result returned by the Obfuscation De-cloaker."""
    is_safe: bool
    has_obfuscation: bool
    detected_encodings: List[str]  # e.g. ['BASE64', 'HEX']
    unpacked_payloads: List[str]
    matched_threats: List[str]
    max_depth_reached: int

    def to_dict(self) -> Dict[str, Any]:
        return {
            "is_safe": self.is_safe,
            "has_obfuscation": self.has_obfuscation,
            "detected_encodings": self.detected_encodings,
            "unpacked_payloads": self.unpacked_payloads,
            "matched_threats": self.matched_threats,
            "max_depth_reached": self.max_depth_reached,
        }


class ObfuscationDeCloaker:
    """
    Sub-millisecond Recursive De-cloaker.
    Unpacks multi-layered encoded attacks and scans the inner cleartext payload.
    """

    # Lookahead/lookbehind regex to extract Base64 candidates (minimum 16 chars)
    BASE64_REGEX = re.compile(r"(?<![A-Za-z0-9+/])([A-Za-z0-9+/]{16,}={0,2})(?![A-Za-z0-9+/=])")

    # Regex to extract Hex candidates (minimum 16 hex chars, with optional 0x prefix)
    HEX_REGEX = re.compile(r"(?<![A-Fa-f0-9])(?:0x)?([0-9a-fA-F]{16,})(?![A-Fa-f0-9])")

    # Inner malicious attack signatures
    THREAT_SIGNATURES = [
        (re.compile(r"\b(?:ignore|disregard|forget|bypass)\s+(?:all\s+)?(?:previous|prior|above|system|bank)\s+(?:instructions|rules|prompts)\b", re.IGNORECASE), "INJECTION_OVERRIDE"),
        (re.compile(r"\b(?:you\s+are\s+now(?:\s+acting\s+as)?|act\s+as|acting\s+as|pretend\s+to\s+be)\s+(?:DAN|AIM|jailbroken|godmode|developer)\b", re.IGNORECASE), "JAILBREAK_ROLEPLAY"),
        (re.compile(r"\b(?:dump|drop|delete|reveal|leak|exfiltrate)\s+(?:the\s+)?(?:database|passwords|accounts|system\s+prompt)\b", re.IGNORECASE), "DATA_EXFILTRATION"),
        (re.compile(r"<\s*system\s*>|\[\s*INST\s*\]|<\s*\|\s*im_start\s*\|>", re.IGNORECASE), "DELIMITER_SPOOFING"),
    ]

    def _scan_text_for_threats(self, cleartext: str) -> List[str]:
        """Scans cleartext string against known injection signatures."""
        found = []
        for pattern, threat_id in self.THREAT_SIGNATURES:
            if pattern.search(cleartext):
                found.append(threat_id)
        return found

    def _recursive_unpack(
        self,
        candidate: str,
        current_depth: int = 1,
        max_depth: int = 3
    ) -> Tuple[List[str], Set[str], int]:
        """
        Recursively unpacks Base64 and Hex encodings up to max_depth.
        Returns: (unpacked_strings, detected_encodings, max_depth_reached)
        """
        unpacked: List[str] = []
        encodings: Set[str] = set()
        highest_depth = current_depth

        if current_depth > max_depth or len(candidate) < 8:
            return unpacked, encodings, highest_depth

        # 1. Attempt Base64 Decoding
        try:
            b64_bytes = base64.b64decode(candidate, validate=True)
            decoded_str = b64_bytes.decode("utf-8", errors="ignore").strip()
            # If it produced valid printable ASCII/UTF-8 of reasonable length
            if len(decoded_str) >= 6 and any(c.isalpha() for c in decoded_str):
                unpacked.append(decoded_str)
                encodings.add("BASE64")
                # Recurse on the decoded string to check for nested encoding
                inner_unpacked, inner_enc, next_d = self._recursive_unpack(decoded_str, current_depth + 1, max_depth)
                unpacked.extend(inner_unpacked)
                encodings.update(inner_enc)
                highest_depth = max(highest_depth, next_d)
        except (binascii.Error, ValueError):
            pass

        # 2. Attempt Hexadecimal Decoding
        try:
            clean_hex = candidate[2:] if candidate.startswith("0x") else candidate
            if len(clean_hex) % 2 == 0:
                hex_bytes = bytes.fromhex(clean_hex)
                decoded_hex = hex_bytes.decode("utf-8", errors="ignore").strip()
                if len(decoded_hex) >= 6 and any(c.isalpha() for c in decoded_hex):
                    unpacked.append(decoded_hex)
                    encodings.add("HEX")
                    # Recurse on decoded hex
                    inner_unpacked, inner_enc, next_d = self._recursive_unpack(decoded_hex, current_depth + 1, max_depth)
                    unpacked.extend(inner_unpacked)
                    encodings.update(inner_enc)
                    highest_depth = max(highest_depth, next_d)
        except (ValueError, binascii.Error):
            pass

        return unpacked, encodings, highest_depth

    def inspect(self, prompt: str) -> DeCloakResult:
        """
        Main inspection entry point.
        Extracts encoded blocks, recursively unpacks them, and scans inner payloads.
        """
        if not prompt or not prompt.strip():
            return DeCloakResult(
                is_safe=True,
                has_obfuscation=False,
                detected_encodings=[],
                unpacked_payloads=[],
                matched_threats=[],
                max_depth_reached=0
            )

        # 1. Extract candidate encoded strings
        b64_candidates = self.BASE64_REGEX.findall(prompt)
        hex_candidates = self.HEX_REGEX.findall(prompt)
        all_candidates = set(b64_candidates + hex_candidates)

        if not all_candidates:
            # No encoded candidates present; pass through safely to specialized guardrails
            return DeCloakResult(
                is_safe=True,
                has_obfuscation=False,
                detected_encodings=[],
                unpacked_payloads=[],
                matched_threats=[],
                max_depth_reached=0
            )

        total_unpacked: List[str] = []
        total_encodings: Set[str] = set()
        max_depth = 0
        all_matched_threats: List[str] = []

        # 2. Unpack every candidate
        for cand in all_candidates:
            unpacked_strs, enc_types, depth = self._recursive_unpack(cand)
            if unpacked_strs:
                total_unpacked.extend(unpacked_strs)
                total_encodings.update(enc_types)
                max_depth = max(max_depth, depth)

        # 3. Threat scan on all unpacked payloads
        for payload in total_unpacked:
            threats = self._scan_text_for_threats(payload)
            for t in threats:
                if t not in all_matched_threats:
                    all_matched_threats.append(f"{t}_IN_{'_THEN_'.join(sorted(total_encodings))}")

        has_obfuscation = len(total_encodings) > 0
        # Safe ONLY if no threats found in unpacked text!
        is_safe = len(all_matched_threats) == 0

        return DeCloakResult(
            is_safe=is_safe,
            has_obfuscation=has_obfuscation,
            detected_encodings=sorted(list(total_encodings)),
            unpacked_payloads=total_unpacked,
            matched_threats=all_matched_threats,
            max_depth_reached=max_depth
        )


# Global Singleton
default_obfuscation_decloaker = ObfuscationDeCloaker()
