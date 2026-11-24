"""
Enterprise Unicode Normalization & Anti-Evasion Sanitizer (Topic 2.2)
=====================================================================
Compliance: Unicode Standard Annex #15 (NFKC Normalization)
Architecture: Pre-Guardrail Canonicalization Pipeline
"""

import re
import unicodedata
from typing import Dict, Any, Tuple
from dataclasses import dataclass


@dataclass(frozen=True)
class UnicodeSanitizerResult:
    """Detailed audit result returned by the Unicode Sanitizer."""
    raw_text: str
    clean_text: str
    stripped_zero_width_count: int
    had_fullwidth_normalized: bool
    had_control_characters: bool
    was_modified: bool

    def to_dict(self) -> Dict[str, Any]:
        return {
            "stripped_zero_width_count": self.stripped_zero_width_count,
            "had_fullwidth_normalized": self.had_fullwidth_normalized,
            "had_control_characters": self.had_control_characters,
            "was_modified": self.was_modified,
            "clean_text": self.clean_text
        }


class EnterpriseUnicodeSanitizer:
    """
    Sub-millisecond Deterministic Canonicalizer.
    Strips zero-width steganographic injection characters, collapses fullwidth glyphs,
    and eliminates non-printable control characters before feeding to regex or LLMs.
    """

    # Comprehensive set of invisible, zero-width, and bidi-override format characters
    ZERO_WIDTH_REGEX = re.compile(
        r"[\u200B-\u200D"  # Zero-width space, non-joiner, joiner
        r"\uFEFF"          # Byte order mark / zero-width no-break space
        r"\u2060"          # Word joiner
        r"\u200E\u200F"    # LTR and RTL directional marks
        r"\u00AD"          # Soft hyphen
        r"\u202A-\u202E]"  # BiDi embedding and override controls
    )

    def sanitize(self, text: str) -> UnicodeSanitizerResult:
        """
        Main canonicalization pipeline:
          Step 1: Unicode NFKC Normalization.
          Step 2: Zero-Width Steganographic Character Stripping.
          Step 3: Non-Printable Control Character Elimination.
          Step 4: Whitespace Regularization.
        """
        if not text:
            return UnicodeSanitizerResult(
                raw_text="",
                clean_text="",
                stripped_zero_width_count=0,
                had_fullwidth_normalized=False,
                had_control_characters=False,
                was_modified=False
            )

        # 1. Step 1: NFKC Normalization (Expands fullwidth, ligatures, compatibility characters)
        nfkc_normalized = unicodedata.normalize("NFKC", text)
        had_fullwidth = nfkc_normalized != text

        # 2. Step 2: Count and strip zero-width characters
        zero_width_matches = self.ZERO_WIDTH_REGEX.findall(nfkc_normalized)
        stripped_count = len(zero_width_matches)
        stripped_text = self.ZERO_WIDTH_REGEX.sub("", nfkc_normalized)

        # 3. Step 3: Eliminate invisible control characters (Category 'C' except \n and \t)
        clean_chars = []
        had_controls = False
        for ch in stripped_text:
            if ch in ("\n", "\t"):
                clean_chars.append(ch)
            elif unicodedata.category(ch)[0] == "C":
                had_controls = True
            else:
                clean_chars.append(ch)

        # 4. Step 4: Normalize consecutive horizontal whitespace
        final_text = "".join(clean_chars)
        final_text = re.sub(r"[ \t]+", " ", final_text).strip()

        was_modified = (final_text != text)

        return UnicodeSanitizerResult(
            raw_text=text,
            clean_text=final_text,
            stripped_zero_width_count=stripped_count,
            had_fullwidth_normalized=had_fullwidth,
            had_control_characters=had_controls,
            was_modified=was_modified
        )


# Global Singleton for high-speed reuse across all guardrails
default_unicode_sanitizer = EnterpriseUnicodeSanitizer()
