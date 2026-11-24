"""
Enterprise End-to-End Orchestration & Guardrail Pipeline
=========================================================
Unifies Pillar 1 (Cognitive Orchestration Core) & Pillar 2 (Ingress & Edge Guardrails)
into a production-grade Level-4 Enterprise AI Gateway.
"""

import time
import uuid
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field

# Pillar 2 Components (Ingress, Edge & Security Guardrails)
from src.guardrails.unicode_sanitizer import EnterpriseUnicodeSanitizer, UnicodeSanitizerResult
from src.guardrails.obfuscation_decloaker import ObfuscationDeCloaker, DeCloakResult
from src.guardrails.delimiter_firewall import EnterpriseDelimiterFirewall, DelimiterFirewallResult
from src.guardrails.pii_vault import EnterprisePIIVault, TokenizeResult
from src.guardrails.semantic_cache import EnterpriseSemanticCache, CacheHitResult
from src.guardrails.owasp_threat_guard import OWASPThreatGuard, ThreatGateResult, ThreatCategory

# Pillar 1 Components (State & Orchestration Core)
from src.core.multi_agent_supervisor import SupervisorCoordinator, DomainRoute, SubAgentResponse


@dataclass
class PipelineStepAudit:
    """Audit log for an individual pipeline step."""
    step_number: int
    step_name: str
    status: str  # 'PASSED', 'BLOCKED', 'SANITIZED', 'CACHED', 'ROUTED'
    latency_ms: float
    details: Dict[str, Any] = field(default_factory=dict)


@dataclass
class GatewayExecutionResult:
    """Master audit result returned by the Enterprise AI Gateway."""
    is_success: bool
    final_response: str
    session_id: str
    is_blocked: bool
    block_reason: Optional[str]
    is_cached: bool
    route_taken: str
    total_latency_ms: float
    audit_trail: List[PipelineStepAudit]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "is_success": self.is_success,
            "final_response": self.final_response,
            "session_id": self.session_id,
            "is_blocked": self.is_blocked,
            "block_reason": self.block_reason,
            "is_cached": self.is_cached,
            "route_taken": self.route_taken,
            "total_latency_ms": round(self.total_latency_ms, 2),
            "audit_trail": [
                {
                    "step_number": s.step_number,
                    "step_name": s.step_name,
                    "status": s.status,
                    "latency_ms": round(s.latency_ms, 3),
                    "details": s.details
                }
                for s in self.audit_trail
            ]
        }


class EnterpriseAIGateway:
    """
    Unified Ingress Gateway & Cognitive Orchestrator.
    Executes Pillar 2 Edge Defense Pipeline -> Semantic Cache -> Pillar 1 Multi-Agent Dispatch.
    """

    def __init__(self):
        # Pillar 2: Edge Guardrails
        self.unicode_sanitizer = EnterpriseUnicodeSanitizer()
        self.decloaker = ObfuscationDeCloaker()
        self.delimiter_firewall = EnterpriseDelimiterFirewall()
        self.pii_vault = EnterprisePIIVault(session_ttl_seconds=300)
        self.semantic_cache = EnterpriseSemanticCache(similarity_threshold=0.88, default_ttl=3600)
        self.owasp_guard = OWASPThreatGuard()

        # Pillar 1: Orchestration Core
        self.supervisor = SupervisorCoordinator()

        # Pre-seed helpful FAQ knowledge in the semantic cache
        self._seed_faq_cache()

    def _seed_faq_cache(self):
        """Pre-seeds standard public banking policies into the semantic cache."""
        self.semantic_cache.store(
            "What is the savings account interest rate?",
            "Our standard Apex Savings Account offers a competitive 4.5% APY compounding monthly.",
            ttl_seconds=86400,
            namespace="default"
        )
        self.semantic_cache.store(
            "What are the branch operating hours and customer service schedule?",
            "Branch locations are open Monday through Friday from 9:00 AM to 5:00 PM EST. ATM services are available 24/7.",
            ttl_seconds=86400,
            namespace="default"
        )

    def process(self, raw_query: str, session_id: Optional[str] = None) -> GatewayExecutionResult:
        """
        Executes the full 11-stage enterprise processing pipeline.
        """
        start_total = time.perf_counter()
        audit_trail: List[PipelineStepAudit] = []
        active_session = session_id or str(uuid.uuid4())

        def add_step(num: int, name: str, status: str, t_start: float, details: Dict[str, Any]):
            dur = (time.perf_counter() - t_start) * 1000.0
            audit_trail.append(PipelineStepAudit(num, name, status, dur, details))

        current_text = raw_query

        # =========================================================================
        # STAGE 1: Unicode Normalization & Zero-Width Stripping (Topic 2.2)
        # =========================================================================
        t0 = time.perf_counter()
        u_res: UnicodeSanitizerResult = self.unicode_sanitizer.sanitize(current_text)
        current_text = u_res.clean_text
        add_step(
            1, "Unicode Normalization & Zero-Width Stripping",
            "SANITIZED" if u_res.was_modified else "PASSED",
            t0,
            {
                "zero_width_stripped": u_res.stripped_zero_width_count,
                "fullwidth_normalized": u_res.had_fullwidth_normalized,
                "clean_text_preview": current_text[:80]
            }
        )

        # =========================================================================
        # STAGE 2: Obfuscation De-cloaking (Recursive Base64/Hex) (Topic 2.3)
        # =========================================================================
        t0 = time.perf_counter()
        d_res: DeCloakResult = self.decloaker.inspect(current_text)
        if not d_res.is_safe:
            add_step(2, "Obfuscation De-cloaking", "BLOCKED", t0, {
                "detected_encodings": d_res.detected_encodings,
                "matched_threats": d_res.matched_threats,
                "unpacked_payloads": d_res.unpacked_payloads
            })
            total_dur = (time.perf_counter() - start_total) * 1000.0
            return GatewayExecutionResult(
                is_success=False,
                final_response="[SECURITY ALERT 403] Request blocked: Obfuscated injection payload detected.",
                session_id=active_session,
                is_blocked=True,
                block_reason=f"OBFUSCATION_ATTACK: {', '.join(d_res.matched_threats)}",
                is_cached=False,
                route_taken="EDGE_GATEWAY_BLOCKED",
                total_latency_ms=total_dur,
                audit_trail=audit_trail
            )
        add_step(2, "Obfuscation De-cloaking", "PASSED", t0, {
            "has_obfuscation": d_res.has_obfuscation,
            "detected_encodings": d_res.detected_encodings
        })

        # =========================================================================
        # STAGE 3: Delimiter Spoofing Firewall (Topic 2.4)
        # =========================================================================
        t0 = time.perf_counter()
        del_res: DelimiterFirewallResult = self.delimiter_firewall.inspect(current_text)
        if not del_res.is_safe:
            add_step(3, "Delimiter Spoofing Firewall", "BLOCKED", t0, {
                "delimiters": del_res.detected_delimiters,
                "violation": del_res.violation_reason
            })
            total_dur = (time.perf_counter() - start_total) * 1000.0
            return GatewayExecutionResult(
                is_success=False,
                final_response="[SECURITY ALERT 403] Request blocked: Control token or prompt boundary spoofing detected.",
                session_id=active_session,
                is_blocked=True,
                block_reason=del_res.violation_reason,
                is_cached=False,
                route_taken="EDGE_GATEWAY_BLOCKED",
                total_latency_ms=total_dur,
                audit_trail=audit_trail
            )

        if del_res.action == "SANITIZED":
            current_text = del_res.sanitized_text
            add_step(3, "Delimiter Spoofing Firewall", "SANITIZED", t0, {
                "action": "ESCAPED_BENIGN_TAGS",
                "delimiters": del_res.detected_delimiters
            })
        else:
            add_step(3, "Delimiter Spoofing Firewall", "PASSED", t0, {})

        # =========================================================================
        # STAGE 4: Zero-Knowledge PII Tokenization & Vault (Topic 2.6)
        # =========================================================================
        t0 = time.perf_counter()
        pii_res: TokenizeResult = self.pii_vault.tokenize(current_text, session_id=active_session)
        masked_query = pii_res.masked_text
        add_step(4, "Zero-Knowledge PII Tokenization", "TOKENIZED" if pii_res.token_count > 0 else "PASSED", t0, {
            "tokens_generated": pii_res.token_count,
            "detected_types": pii_res.detected_types,
            "masked_preview": masked_query[:80]
        })

        # =========================================================================
        # STAGE 5: Semantic Vector Cache (Topic 2.5)
        # =========================================================================
        t0 = time.perf_counter()
        cache_res: CacheHitResult = self.semantic_cache.lookup(masked_query)
        if cache_res.hit:
            add_step(5, "Semantic Vector Cache", "CACHED", t0, {
                "similarity_score": round(cache_res.similarity_score, 4),
                "matched_query": cache_res.matched_query
            })
            # De-tokenize cached output if necessary
            final_cached = self.pii_vault.detokenize(cache_res.response, active_session)
            total_dur = (time.perf_counter() - start_total) * 1000.0
            return GatewayExecutionResult(
                is_success=True,
                final_response=f"⚡ [15ms Semantic Cache Hit] {final_cached}",
                session_id=active_session,
                is_blocked=False,
                block_reason=None,
                is_cached=True,
                route_taken="SEMANTIC_CACHE",
                total_latency_ms=total_dur,
                audit_trail=audit_trail
            )

        add_step(5, "Semantic Vector Cache", "MISS", t0, {
            "similarity_score": round(cache_res.similarity_score, 4)
        })

        # =========================================================================
        # STAGE 6: OWASP Top 10 Ingress Threat Guard (Topic 2.1)
        # =========================================================================
        t0 = time.perf_counter()
        owasp_res: ThreatGateResult = self.owasp_guard.inspect_ingress(masked_query)
        if not owasp_res.is_safe:
            add_step(6, "OWASP Top 10 Threat Guard", "BLOCKED", t0, {
                "matched_rules": owasp_res.violations,
                "category": owasp_res.threat_category.value
            })
            total_dur = (time.perf_counter() - start_total) * 1000.0
            return GatewayExecutionResult(
                is_success=False,
                final_response="[SECURITY ALERT 403] Request blocked: Malicious prompt injection or exfiltration attempt.",
                session_id=active_session,
                is_blocked=True,
                block_reason=f"OWASP_VIOLATION: {', '.join(owasp_res.violations)}",
                is_cached=False,
                route_taken="OWASP_GUARD_BLOCKED",
                total_latency_ms=total_dur,
                audit_trail=audit_trail
            )

        add_step(6, "OWASP Top 10 Threat Guard", "PASSED", t0, {})

        # =========================================================================
        # STAGE 7: Multi-Agent Supervisor Routing & Domain Dispatch (Topic 1.4)
        # =========================================================================
        t0 = time.perf_counter()
        subagent_res: SubAgentResponse = self.supervisor.dispatch(masked_query)
        add_step(7, "Multi-Agent Supervisor & Domain Worker", "ROUTED", t0, {
            "route": subagent_res.route.value,
            "agent_name": subagent_res.agent_name,
            "action_taken": subagent_res.action_taken,
            "is_mutation": subagent_res.is_mutation
        })

        # =========================================================================
        # STAGE 8: Cognitive Reasoning & Natural Language Response Generation
        # =========================================================================
        t0 = time.perf_counter()
        raw_agent_reply = self._synthesize_agent_response(subagent_res, masked_query)
        add_step(8, "Cognitive Agent Synthesis", "GENERATED", t0, {
            "agent_role": subagent_res.agent_name
        })

        # =========================================================================
        # STAGE 9: OWASP Egress Data Redaction Guard (Topic 2.1)
        # =========================================================================
        t0 = time.perf_counter()
        egress_res: ThreatGateResult = self.owasp_guard.inspect_egress(raw_agent_reply)
        safe_reply = egress_res.sanitized_text or raw_agent_reply
        was_redacted = len(egress_res.violations) > 0
        add_step(9, "OWASP Egress Secret Redactor", "REDACTED" if was_redacted else "PASSED", t0, {
            "was_redacted": was_redacted,
            "violations": egress_res.violations
        })

        # =========================================================================
        # STAGE 10: Secure De-tokenization (Restoring Real PII at the Edge) (Topic 2.6)
        # =========================================================================
        t0 = time.perf_counter()
        final_customer_response = self.pii_vault.detokenize(safe_reply, active_session)
        add_step(10, "PII Vault De-tokenization", "RESTORED" if pii_res.token_count > 0 else "PASSED", t0, {
            "session_id": active_session
        })

        # =========================================================================
        # STAGE 11: Opportunistic Semantic Caching for Non-PII Queries (Topic 2.5)
        # =========================================================================
        t0 = time.perf_counter()
        can_cache, _ = self.semantic_cache.is_cacheable(current_text)
        if (
            can_cache
            and pii_res.token_count == 0
            and not subagent_res.is_mutation
            and subagent_res.route != DomainRoute.UNKNOWN
        ):
            self.semantic_cache.store(current_text, final_customer_response, ttl_seconds=3600)
            add_step(11, "Semantic Cache Ingestion", "STORED", t0, {"ttl_seconds": 3600})
        else:
            add_step(11, "Semantic Cache Ingestion", "SKIPPED_PII_OR_MUTATION", t0, {})

        total_dur = (time.perf_counter() - start_total) * 1000.0

        return GatewayExecutionResult(
            is_success=True,
            final_response=final_customer_response,
            session_id=active_session,
            is_blocked=False,
            block_reason=None,
            is_cached=False,
            route_taken=subagent_res.route.value,
            total_latency_ms=total_dur,
            audit_trail=audit_trail
        )

    def _synthesize_agent_response(self, sub_res: SubAgentResponse, query: str) -> str:
        """Produces professional domain-specific customer response."""
        data = sub_res.data

        if sub_res.route == DomainRoute.ACCOUNTS:
            return (
                f"Hello! Here are your account details:\n"
                f"• Account ID: {data.get('account_id')}\n"
                f"• Account Type: {data.get('account_type')}\n"
                f"• Available Balance: ${data.get('available_balance', 0.0):,.2f} {data.get('currency', 'USD')}\n"
                f"Is there anything else I can help you with regarding your account?"
            )

        elif sub_res.route == DomainRoute.TRANSACTIONS:
            tx_lines = "\n".join(
                f"  - [{t['date']}] {t['merchant']}: {'+' if t['amount'] > 0 else ''}${t['amount']:,.2f}"
                for t in data.get("transactions", [])
            )
            return (
                f"Here is your recent transaction history for {data.get('account_id')}:\n"
                f"{tx_lines}\n"
                f"All transactions are settled securely."
            )

        elif sub_res.route == DomainRoute.SERVICES:
            # Gated Write Operation requires Step-Up Approval (HITL)
            return (
                f"⚠️ [STEP-UP AUTHENTICATION REQUIRED]\n"
                f"Your request for '{data.get('service_type')}' (Tracking Ref: {data.get('request_id')}) "
                f"involves a secure account modification.\n"
                f"Status: {data.get('status')}.\n"
                f"A one-time passcode (OTP) has been dispatched to your registered contact channel to confirm this action."
            )

        else:
            # Fallback general assistance
            return (
                f"Thank you for reaching out to Apex Banking Services. "
                f"I can assist you with your Checking/Savings Accounts, Transaction Ledgers, or Service Requests (Address/Chequebook). "
                f"How may I serve you today?"
            )


# Global Singleton Instance
default_gateway = EnterpriseAIGateway()
