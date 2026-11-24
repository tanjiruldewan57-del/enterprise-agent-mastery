"""
Adversarial Unit Tests for Core State Machine Engine (Topic 1.1)
=================================================================
Validates:
  1. Deterministic linear graph execution (DAG).
  2. Cyclic self-healing retry flow (DCG).
  3. Runway infinite loop mitigation via RecursionLimitExceeded.
  4. Dead-end orphan node detection.
"""

import pytest
from src.core.state_machine import (
    StateGraph,
    GraphState,
    RecursionLimitExceeded,
    InvalidStateTransition,
    END,
)


def test_linear_dag_execution():
    """Test 1: Normal linear workflow without cycles."""
    graph = StateGraph(max_recursion_limit=5)

    def step_a(state: GraphState):
        return {"data": "A", "count": 1}

    def step_b(state: GraphState):
        prev = state.get("data")
        return {"data": f"{prev}->B", "count": state.get("count") + 1}

    graph.add_node("step_a", step_a)
    graph.add_node("step_b", step_b)
    graph.set_entry_point("step_a")
    graph.add_edge("step_a", "step_b")
    graph.add_edge("step_b", END)

    result = graph.execute({"initial": True})

    assert result.get("data") == "A->B"
    assert result.get("count") == 2
    assert result.history == ["step_a", "step_b"]
    assert result.step_count == 2


def test_cyclic_self_healing_execution():
    """Test 2: Agent attempts, fails, loops back to retry, and then succeeds."""
    graph = StateGraph(max_recursion_limit=5)

    def generator_node(state: GraphState):
        # Simulated generator: increases attempt number
        attempts = state.get("attempts", 0) + 1
        return {"attempts": attempts}

    def evaluator_node(state: GraphState):
        # Passes only on attempt >= 2
        attempts = state.get("attempts", 0)
        is_valid = attempts >= 2
        return {"is_valid": is_valid}

    def route_decision(state: GraphState) -> str:
        if state.get("is_valid"):
            return END
        return "generator"  # Self-healing cyclic loop back!

    graph.add_node("generator", generator_node)
    graph.add_node("evaluator", evaluator_node)
    graph.set_entry_point("generator")
    graph.add_edge("generator", "evaluator")
    graph.add_conditional_edge("evaluator", route_decision)

    result = graph.execute({"attempts": 0})

    assert result.get("is_valid") is True
    assert result.get("attempts") == 2
    assert result.history == ["generator", "evaluator", "generator", "evaluator"]
    assert result.step_count == 4


def test_runaway_infinite_loop_protection():
    """Test 3 (Chaos/Adversarial): Faulty agent loops infinitely without resolving."""
    graph = StateGraph(max_recursion_limit=4)

    def broken_node(state: GraphState):
        return {"count": state.get("count", 0) + 1}

    def always_loop(state: GraphState) -> str:
        return "broken_node"  # Malicious/Infinite cycle

    graph.add_node("broken_node", broken_node)
    graph.set_entry_point("broken_node")
    graph.add_conditional_edge("broken_node", always_loop)

    with pytest.raises(RecursionLimitExceeded) as exc_info:
        graph.execute({"count": 0})

    assert "Exceeded max recursion limit of 4" in str(exc_info.value)
    assert "broken_node -> broken_node" in str(exc_info.value)


def test_dead_end_orphan_node_rejected():
    """Test 4: Node with no outgoing edge must fail deterministically."""
    graph = StateGraph()

    def orphan_node(state: GraphState):
        return {"done": True}

    graph.add_node("orphan", orphan_node)
    graph.set_entry_point("orphan")
    # Notice: No outgoing edge added for 'orphan'

    with pytest.raises(InvalidStateTransition) as exc_info:
        graph.execute({})

    assert "Orphan Node: 'orphan' has no outgoing edges" in str(exc_info.value)
