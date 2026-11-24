"""
Enterprise Multi-Agent Supervisor Topology
==========================================
Architecture: Hierarchical Supervisor-Worker Pattern
Compliance: Principle of Least Privilege (PoLP) & Domain Sandbox Isolation
"""

import re
from enum import Enum
from typing import Dict, Any, Optional, List
from dataclasses import dataclass, field


class DomainRoute(str, Enum):
    ACCOUNTS = "ACCOUNTS"
    TRANSACTIONS = "TRANSACTIONS"
    SERVICES = "SERVICES"
    UNKNOWN = "UNKNOWN"


@dataclass(frozen=True)
class SubAgentResponse:
    """Standardized response schema returned by any domain sub-agent."""
    agent_name: str
    route: DomainRoute
    action_taken: str
    data: Dict[str, Any]
    is_mutation: bool  # True if operation modifies database state (requires HITL)
    status: str = "SUCCESS"


class AccountsAgent:
    """Specialized Sub-Agent for Account Inquiries (Read-Only)."""
    NAME = "AccountsAgent"

    def handle(self, user_query: str) -> SubAgentResponse:
        # Domain Sandboxed Logic (Only has access to Accounts data)
        return SubAgentResponse(
            agent_name=self.NAME,
            route=DomainRoute.ACCOUNTS,
            action_taken="FETCH_ACCOUNT_BALANCE",
            data={
                "account_id": "ACC_99201",
                "account_type": "Checking",
                "available_balance": 4850.75,
                "currency": "USD"
            },
            is_mutation=False
        )


class TransactionsAgent:
    """Specialized Sub-Agent for Transaction Details & Statements (Read-Only CQRS)."""
    NAME = "TransactionsAgent"

    def handle(self, user_query: str) -> SubAgentResponse:
        # Domain Sandboxed Logic (Only has access to Ledger/Transactions data)
        return SubAgentResponse(
            agent_name=self.NAME,
            route=DomainRoute.TRANSACTIONS,
            action_taken="FETCH_TRANSACTION_HISTORY",
            data={
                "account_id": "ACC_99201",
                "transactions": [
                    {"tx_id": "TX_101", "amount": -45.00, "merchant": "Amazon", "date": "2026-11-15"},
                    {"tx_id": "TX_102", "amount": -120.50, "merchant": "Walmart", "date": "2026-11-16"},
                    {"tx_id": "TX_103", "amount": 2500.00, "merchant": "Payroll Direct Deposit", "date": "2026-11-17"}
                ]
            },
            is_mutation=False
        )


class ServicesAgent:
    """Specialized Sub-Agent for Service & Mutation Operations (Gated Write Operations)."""
    NAME = "ServicesAgent"

    def handle(self, user_query: str) -> SubAgentResponse:
        # High-Risk Mutation Logic (Flagged as is_mutation = True for Step-Up Auth)
        mutation_type = "GENERAL_SERVICE"
        if re.search(r"\b(?:address|street|apartment|city)\b", user_query, re.IGNORECASE):
            mutation_type = "CHANGE_OF_ADDRESS"
        elif re.search(r"\b(?:cheque|check|checkbook|chequebook)\b", user_query, re.IGNORECASE):
            mutation_type = "CHEQUEBOOK_REQUEST"
        elif re.search(r"\b(?:kyc|identity|document|passport)\b", user_query, re.IGNORECASE):
            mutation_type = "KYC_UPDATE"

        return SubAgentResponse(
            agent_name=self.NAME,
            route=DomainRoute.SERVICES,
            action_taken=mutation_type,
            data={
                "request_id": "REQ_SVC_5501",
                "service_type": mutation_type,
                "requires_approval": True,
                "status": "PENDING_MFA_APPROVAL"
            },
            is_mutation=True  # ⚠️ Flags this for HITL Step-Up MFA!
        )


class SupervisorCoordinator:
    """
    Central Coordinator / Router Agent.
    Zero Tool Access: Only performs Intent Classification & Delegation.
    """

    def __init__(self):
        self.accounts_agent = AccountsAgent()
        self.transactions_agent = TransactionsAgent()
        self.services_agent = ServicesAgent()

    def classify_intent(self, user_query: str) -> DomainRoute:
        """
        Determines the appropriate domain route from natural language input.
        Uses whole-word regex patterns to prevent substring collisions (e.g. 'recently' matching 'recent').
        """
        query = user_query.lower()

        # 1. Services Domain Keywords (High priority: Address, Cheque, KYC, Profile updates)
        if re.search(r"\b(?:address|cheque|checkbook|chequebook|kyc|passport|nominee)\b", query):
            return DomainRoute.SERVICES

        # 2. Accounts Domain Keywords (Balance, Account Info)
        if re.search(r"\b(?:balance|saving|savings|checking|account\s+number|account\s+info)\b", query):
            return DomainRoute.ACCOUNTS

        # 3. Transactions Domain Keywords (Statement, Spend, History, Charges)
        if re.search(r"\b(?:transaction|transactions|statement|statements|spent|purchase|purchases|deposit|deposits|ledger|history)\b", query):
            return DomainRoute.TRANSACTIONS

        return DomainRoute.UNKNOWN

    def dispatch(self, user_query: str) -> SubAgentResponse:
        """
        Main ingress dispatch method.
        Routes the request to the dedicated domain sub-agent.
        """
        route = self.classify_intent(user_query)

        if route == DomainRoute.ACCOUNTS:
            return self.accounts_agent.handle(user_query)
        elif route == DomainRoute.TRANSACTIONS:
            return self.transactions_agent.handle(user_query)
        elif route == DomainRoute.SERVICES:
            return self.services_agent.handle(user_query)
        else:
            return SubAgentResponse(
                agent_name="CoordinatorSupervisor",
                route=DomainRoute.UNKNOWN,
                action_taken="FALLBACK_INTENT_UNKNOWN",
                data={"message": "Could not determine specialized banking domain for query."},
                is_mutation=False,
                status="UNROUTED"
            )
