"""
Adversarial Unit Tests for Multi-Agent Supervisor Topology (Topic 1.4)
======================================================================
Validates:
  1. Accurate domain routing to AccountsAgent (Read-Only).
  2. Accurate domain routing to TransactionsAgent (Read-Only).
  3. Gated mutation routing to ServicesAgent with strict is_mutation=True flag.
  4. Graceful handling of out-of-domain queries without hallucinated actions.
"""

import pytest
from src.core.multi_agent_supervisor import (
    SupervisorCoordinator,
    DomainRoute,
    SubAgentResponse
)


@pytest.fixture
def supervisor():
    return SupervisorCoordinator()


def test_supervisor_routes_to_accounts_agent(supervisor):
    """
    Test 1: Balance inquiry routed exclusively to AccountsAgent.
    """
    query = "What is my current savings account balance?"
    response: SubAgentResponse = supervisor.dispatch(query)

    assert response.route == DomainRoute.ACCOUNTS
    assert response.agent_name == "AccountsAgent"
    assert response.action_taken == "FETCH_ACCOUNT_BALANCE"
    assert response.is_mutation is False
    assert "available_balance" in response.data


def test_supervisor_routes_to_transactions_agent(supervisor):
    """
    Test 2: Transaction history inquiry routed to TransactionsAgent.
    """
    query = "Can you show my recent transactions and purchases?"
    response: SubAgentResponse = supervisor.dispatch(query)

    assert response.route == DomainRoute.TRANSACTIONS
    assert response.agent_name == "TransactionsAgent"
    assert response.action_taken == "FETCH_TRANSACTION_HISTORY"
    assert response.is_mutation is False
    assert len(response.data["transactions"]) > 0


def test_supervisor_routes_to_services_agent_with_mutation_flag(supervisor):
    """
    Test 3: Change of address must route to ServicesAgent and flag is_mutation=True!
    """
    query = "I recently moved, please update my residential address to New York"
    response: SubAgentResponse = supervisor.dispatch(query)

    assert response.route == DomainRoute.SERVICES
    assert response.agent_name == "ServicesAgent"
    assert response.action_taken == "CHANGE_OF_ADDRESS"
    assert response.is_mutation is True, "Security Breach: Write operation was not flagged as mutation!"
    assert response.data["status"] == "PENDING_MFA_APPROVAL"


def test_supervisor_handles_unrouted_domain_cleanly(supervisor):
    """
    Test 4: Irrelevant/Out-of-domain queries must not hallucinate banking actions.
    """
    query = "Write a bedtime story about space exploration and dragons"
    response: SubAgentResponse = supervisor.dispatch(query)

    assert response.route == DomainRoute.UNKNOWN
    assert response.status == "UNROUTED"
    assert response.is_mutation is False
