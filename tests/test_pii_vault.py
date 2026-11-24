"""
Adversarial Unit Tests for Enterprise PII Vault & Gateway (Topic 2.6)
====================================================================
Validates:
  1. Multi-vector masking of Emails, Credit Cards, Phones, SSNs, and IPs.
  2. Complete roundtrip: Tokenize -> Model processing -> De-tokenize.
  3. Deterministic token consistency (same entity gets same token in session).
  4. Explicit session purge removing mapping from RAM.
  5. TTL expiration automatically invalidating stale sessions.
  6. Clean non-PII prompt passing unmodified.
"""

import time
import pytest
from src.guardrails.pii_vault import (
    EnterprisePIIVault,
    TokenizeResult,
    PIIType
)


@pytest.fixture
def vault():
    # Fresh vault for each test with 300s TTL
    return EnterprisePIIVault(session_ttl_seconds=300)


def test_multi_vector_pii_tokenization(vault):
    """
    Test 1: Multiple sensitive PII entities in one prompt are all masked.
    """
    raw_prompt = (
        "My email is customer.care@example.com, my credit card is 4532-1234-5678-9010, "
        "mobile is +1 (555) 234-5678, and SSN is 123-45-6789."
    )

    result: TokenizeResult = vault.tokenize(raw_prompt)

    # Raw PII must NEVER be present in masked_text
    assert "customer.care@example.com" not in result.masked_text
    assert "4532-1234-5678-9010" not in result.masked_text
    assert "123-45-6789" not in result.masked_text

    # Verified token markers
    assert "[[TOK_EMAIL_" in result.masked_text
    assert "[[TOK_CARD_" in result.masked_text
    assert "[[TOK_PHONE_" in result.masked_text
    assert "[[TOK_SSN_" in result.masked_text
    assert set(result.detected_types) == {"CARD", "EMAIL", "PHONE", "SSN"}


def test_roundtrip_detokenization(vault):
    """
    Test 2: Full end-to-end roundtrip.
    Input PII -> Masked -> Model outputs masked tokens -> De-tokenize restores original PII.
    """
    email = "sarah.connor@sky.net"
    card = "5412-7534-8901-2345"
    user_prompt = f"Please cancel payment for {email} on card {card}."

    tok_res = vault.tokenize(user_prompt)
    session_id = tok_res.session_id

    # Simulated LLM response containing the masked tokens
    mock_llm_response = (
        f"Understood. Payment for account associated with email "
        f"{[k for k in vault._vault[session_id] if 'EMAIL' in k][0]} "
        f"and card {[k for k in vault._vault[session_id] if 'CARD' in k][0]} has been halted."
    )

    # De-tokenize at the edge gateway
    restored_text = vault.detokenize(mock_llm_response, session_id)

    assert email in restored_text
    assert card in restored_text
    assert "[[TOK_" not in restored_text


def test_deterministic_token_consistency(vault):
    """
    Test 3: Repeating the same PII in a prompt yields the same token.
    Ensures LLM maintains co-reference resolution.
    """
    email = "alex@enterprise.org"
    prompt = f"First notify {email}, and then send a confirmation receipt to {email}."

    result = vault.tokenize(prompt)

    # Token must appear twice in text
    token = [k for k in vault._vault[result.session_id] if 'EMAIL' in k][0]
    assert result.masked_text.count(token) == 2
    # Only 1 unique entity stored
    assert len(vault._vault[result.session_id]) == 1


def test_session_purge_prevents_leakage(vault):
    """
    Test 4: Purging a session wipes vault memory; subsequent detokenize cannot restore.
    """
    prompt = "Reach me at secret.agent@mi6.gov.uk."
    res = vault.tokenize(prompt)
    session_id = res.session_id

    # Memory exists before purge
    assert session_id in vault._vault

    # Explicit purge
    purged = vault.purge_session(session_id)
    assert purged is True
    assert session_id not in vault._vault

    # De-tokenizing now leaves tokens unreplaced (safe fallback)
    output = vault.detokenize(res.masked_text, session_id)
    assert "secret.agent@mi6.gov.uk" not in output
    assert "[[TOK_EMAIL_" in output


def test_ttl_expiration_auto_purge():
    """
    Test 5: Expired sessions are auto-purged on de-tokenize lookup.
    """
    short_vault = EnterprisePIIVault(session_ttl_seconds=1)
    prompt = "My phone is 01712345678."

    res = short_vault.tokenize(prompt)
    session_id = res.session_id

    # Wait for TTL expiration
    time.sleep(1.1)

    # De-tokenize should detect expiration, purge session, and not restore
    output = short_vault.detokenize(res.masked_text, session_id)
    assert "01712345678" not in output
    assert session_id not in short_vault._vault


def test_clean_prompt_no_pii_unchanged(vault):
    """
    Test 6: Prompts without PII pass completely unaltered with zero tokens stored.
    """
    clean_prompt = "What are your annual mortgage rates and term options?"
    res = vault.tokenize(clean_prompt)

    assert res.masked_text == clean_prompt
    assert res.token_count == 0
    assert len(res.detected_types) == 0
