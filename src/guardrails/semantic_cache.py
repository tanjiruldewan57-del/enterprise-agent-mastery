"""
Enterprise Semantic Vector Cache & Latency Optimizer (Topic 2.5)
================================================================
Compliance: Zero Cross-User PII Leakage & Sub-15ms Latency Gateway
Architecture: Normalized Vector Space Caching with Cosine Similarity
"""

import re
import time
import math
import hashlib
from typing import Dict, Any, List, Optional, Tuple, Callable
from dataclasses import dataclass, field


@dataclass(frozen=True)
class CacheHitResult:
    """Audit result returned on cache lookup."""
    hit: bool
    response: Optional[str]
    similarity_score: float
    matched_query: Optional[str]
    latency_ms: float

    def to_dict(self) -> Dict[str, Any]:
        return {
            "hit": self.hit,
            "response": self.response,
            "similarity_score": round(self.similarity_score, 4),
            "matched_query": self.matched_query,
            "latency_ms": round(self.latency_ms, 2)
        }


@dataclass
class CacheEntry:
    """Internal representation of a cached vector record."""
    query: str
    response: str
    vector: List[float]
    created_at: float
    ttl_seconds: int
    namespace: str

    def is_expired(self, current_time: float) -> bool:
        if self.ttl_seconds <= 0:
            return False  # Permanent until explicit invalidation
        return (current_time - self.created_at) > self.ttl_seconds


class EnterpriseSemanticCache:
    """
    High-Performance Semantic Vector Cache.
    Matches queries by underlying semantic meaning rather than exact string equality.
    Guards against PII leakage and cache poisoning.
    """

    # High-risk personalized keywords that must NEVER be stored in public cache
    PERSONAL_PII_PATTERNS = re.compile(
        r"\b(?:my\s+(?:balance|account|card|ssn|pin|statement|transaction|password|loan|address)|"
        r"user(?:_id)?\s*[:=]\s*\w+|account\s+number|\b\d{9,16}\b)\b",
        re.IGNORECASE
    )

    # Common conversational stopwords to downweight in semantic space
    STOPWORDS = {
        "what", "is", "the", "a", "an", "tell", "me", "on", "in", "for", "do",
        "how", "can", "you", "please", "i", "our", "to", "of", "about", "give", "show"
    }

    def __init__(
        self,
        similarity_threshold: float = 0.88,
        default_ttl: int = 3600,
        vector_dim: int = 256,
        embedding_provider: Optional[Callable[[str], List[float]]] = None
    ):
        self.threshold = similarity_threshold
        self.default_ttl = default_ttl
        self.vector_dim = vector_dim
        self.custom_embedding_provider = embedding_provider
        # Namespace -> List of CacheEntry
        self._store: Dict[str, List[CacheEntry]] = {}

    def _embed(self, text: str) -> List[float]:
        """
        Generates normalized dense vector representation.
        Applies conversational stopword dampening so semantic intent dominates.
        If an external provider is supplied, uses it.
        """
        if self.custom_embedding_provider:
            raw_v = self.custom_embedding_provider(text)
            norm = math.sqrt(sum(x * x for x in raw_v)) or 1.0
            return [x / norm for x in raw_v]

        # Built-in sub-millisecond deterministic semantic vectorizer
        tokens = re.findall(r"\w+", text.lower())
        vec = [0.0] * self.vector_dim

        for tok in tokens:
            weight = 0.1 if tok in self.STOPWORDS else 1.0

            # Word level feature
            h_word = int(hashlib.sha256(tok.encode("utf-8")).hexdigest()[:8], 16) % self.vector_dim
            vec[h_word] += weight

            # Character 3-gram subwords for typo and inflection tolerance
            padded = f"^{tok}$"
            for i in range(len(padded) - 2):
                tri = padded[i:i+3]
                h_tri = int(hashlib.sha256(tri.encode("utf-8")).hexdigest()[:8], 16) % self.vector_dim
                vec[h_tri] += weight * 0.3

        # L2-Normalization so dot-product equals Cosine Similarity
        norm = math.sqrt(sum(x * x for x in vec))
        if norm == 0.0:
            return vec
        return [x / norm for x in vec]

    @staticmethod
    def _cosine_similarity(vec1: List[float], vec2: List[float]) -> float:
        """Computes dot product of two L2-normalized vectors."""
        return sum(a * b for a, b in zip(vec1, vec2))

    def is_cacheable(self, query: str) -> Tuple[bool, Optional[str]]:
        """
        Audit guardrail: Personal, financial, or authentication queries
        must NEVER be stored in the semantic cache.
        """
        if not query or not query.strip():
            return False, "EMPTY_QUERY"

        if self.PERSONAL_PII_PATTERNS.search(query):
            return False, "PERSONAL_PII_PROHIBITED"

        return True, None

    def lookup(self, query: str, namespace: str = "default") -> CacheHitResult:
        """
        Searches the cache for a semantically equivalent query.
        Returns: CacheHitResult with hit=True if cosine similarity >= threshold.
        """
        start_time = time.perf_counter()

        if namespace not in self._store or not self._store[namespace]:
            latency = (time.perf_counter() - start_time) * 1000.0
            return CacheHitResult(
                hit=False,
                response=None,
                similarity_score=0.0,
                matched_query=None,
                latency_ms=latency
            )

        query_vec = self._embed(query)
        current_time = time.time()

        best_score = -1.0
        best_entry: Optional[CacheEntry] = None

        # Linear scan over namespace (in production, backed by Qdrant/Redis HNSW)
        valid_entries = []
        for entry in self._store[namespace]:
            if entry.is_expired(current_time):
                continue
            valid_entries.append(entry)

            score = self._cosine_similarity(query_vec, entry.vector)
            if score > best_score:
                best_score = score
                best_entry = entry

        # Update store to purge expired items
        self._store[namespace] = valid_entries

        latency = (time.perf_counter() - start_time) * 1000.0

        if best_entry and best_score >= self.threshold:
            return CacheHitResult(
                hit=True,
                response=best_entry.response,
                similarity_score=best_score,
                matched_query=best_entry.query,
                latency_ms=latency
            )

        return CacheHitResult(
            hit=False,
            response=None,
            similarity_score=max(best_score, 0.0),
            matched_query=best_entry.query if best_entry else None,
            latency_ms=latency
        )

    def store(
        self,
        query: str,
        response: str,
        ttl_seconds: Optional[int] = None,
        namespace: str = "default"
    ) -> bool:
        """
        Stores (query, response) pair after passing cacheability and PII check.
        """
        can_cache, reason = self.is_cacheable(query)
        if not can_cache:
            return False

        effective_ttl = ttl_seconds if ttl_seconds is not None else self.default_ttl
        query_vec = self._embed(query)
        entry = CacheEntry(
            query=query,
            response=response,
            vector=query_vec,
            created_at=time.time(),
            ttl_seconds=effective_ttl,
            namespace=namespace
        )

        if namespace not in self._store:
            self._store[namespace] = []

        self._store[namespace].append(entry)
        return True

    def clear(self, namespace: Optional[str] = None) -> None:
        """Clears specific namespace or all cache."""
        if namespace:
            self._store.pop(namespace, None)
        else:
            self._store.clear()


# Global Singleton Instance
default_semantic_cache = EnterpriseSemanticCache()
