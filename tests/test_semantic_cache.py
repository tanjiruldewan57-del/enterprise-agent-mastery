"""
Adversarial Unit Tests for Enterprise Semantic Cache (Topic 2.5)
================================================================
Validates:
  1. Semantic Cache Hit on paraphrased / non-identical queries (Cosine Similarity >= 0.88).
  2. Cache Miss on semantically unrelated queries (No false hits).
  3. Strict PII / Personal Account information caching prohibition (No cross-user leakage).
  4. TTL expiration correctly invalidating stale cached responses.
  5. Multi-tenant namespace isolation (Queries in retail do not leak into corporate).
"""

import time
import pytest
from src.guardrails.semantic_cache import (
    EnterpriseSemanticCache,
    CacheHitResult
)


@pytest.fixture
def cache():
    # Fresh cache for each test
    return EnterpriseSemanticCache(similarity_threshold=0.88, default_ttl=3600)


def test_semantic_cache_hit_paraphrased_query(cache):
    """
    Test 1: Query with identical meaning but different wording hits the cache.
    Original: 'What is the savings account interest rate?'
    Paraphrased: 'tell me interest rate on savings account'
    """
    original_query = "What is the savings account interest rate?"
    cached_response = "Our standard savings account offers 4.5% APY compounding monthly."

    success = cache.store(original_query, cached_response)
    assert success is True

    paraphrased_query = "tell me interest rate on savings account"
    result: CacheHitResult = cache.lookup(paraphrased_query)

    assert result.hit is True
    assert result.response == cached_response
    assert result.similarity_score >= 0.88
    assert result.latency_ms < 50.0  # Ultra-fast sub-millisecond execution


def test_semantic_cache_miss_unrelated_query(cache):
    """
    Test 2: Distinct query with completely different topic correctly misses cache.
    """
    cache.store(
        "What is the savings account interest rate?",
        "Our standard savings account offers 4.5% APY."
    )

    unrelated_query = "How do I apply for a commercial mortgage loan?"
    result: CacheHitResult = cache.lookup(unrelated_query)

    assert result.hit is False
    assert result.response is None
    assert result.similarity_score < 0.88


def test_pii_query_blocked_from_caching(cache):
    """
    Test 3: Private personalized queries containing PII keywords
    must NEVER be accepted into the cache (GDPR/PCI-DSS protection).
    """
    pii_query = "What is my account balance and recent transactions?"
    pii_response = "Your checking account balance is $8,420.50."

    can_cache, reason = cache.is_cacheable(pii_query)
    assert can_cache is False
    assert reason == "PERSONAL_PII_PROHIBITED"

    # Store must fail
    stored = cache.store(pii_query, pii_response)
    assert stored is False

    # Lookup must confirm nothing was saved
    result: CacheHitResult = cache.lookup(pii_query)
    assert result.hit is False
    assert result.response is None


def test_ttl_expiration_purges_entry(cache):
    """
    Test 4: Cache entry with expired TTL is automatically purged.
    """
    query = "What are the branch opening hours?"
    response = "Branches are open Monday to Friday 9 AM to 5 PM."

    # Store with 1-second TTL
    cache.store(query, response, ttl_seconds=1)

    # Immediately should hit
    res_immediate = cache.lookup(query)
    assert res_immediate.hit is True

    # Sleep past expiration
    time.sleep(1.1)

    # Now should be expired and miss
    res_expired = cache.lookup(query)
    assert res_expired.hit is False
    assert res_expired.response is None


def test_namespace_isolation(cache):
    """
    Test 5: Queries stored under one namespace must not hit in a different namespace.
    """
    query = "What is the fee for wire transfer?"
    retail_response = "Retail domestic wire transfer fee is $15."

    cache.store(query, retail_response, namespace="retail_banking")

    # Lookup in corporate namespace should miss
    corp_result = cache.lookup(query, namespace="corporate_banking")
    assert corp_result.hit is False

    # Lookup in retail namespace should hit
    retail_result = cache.lookup(query, namespace="retail_banking")
    assert retail_result.hit is True
    assert retail_result.response == retail_response
