"""
Core Deterministic State Machine Engine (Directed Cyclic Graph - DCG)
=====================================================================
Architecture: Zero-Dependency FSM (Finite State Machine) Engine
Purpose: Demonstrates first-principles agent orchestration, conditional routing,
         and runaway infinite loop protection without external frameworks.
"""

from typing import Dict, Any, Callable, List, Optional
from dataclasses import dataclass, field


class RecursionLimitExceeded(RuntimeError):
    """Raised when an agent loop exceeds the configured recursion threshold."""
    pass


class InvalidStateTransition(ValueError):
    """Raised when a node routes to a non-existent state or dead-end."""
    pass


# Special End-of-Graph Sentinel
END = "__END__"


@dataclass
class GraphState:
    """Immutable state container representing the snapshot at step t."""
    values: Dict[str, Any] = field(default_factory=dict)
    step_count: int = 0
    history: List[str] = field(default_factory=list)

    def get(self, key: str, default: Any = None) -> Any:
        return self.values.get(key, default)

    def update(self, updates: Dict[str, Any], node_name: str) -> "GraphState":
        new_values = {**self.values, **updates}
        new_history = [*self.history, node_name]
        return GraphState(
            values=new_values,
            step_count=self.step_count + 1,
            history=new_history
        )


class StateGraph:
    """
    Deterministic Graph Orchestrator for AI Agent Workflows.
    Guarantees:
      1. Bounded execution via strict max_recursion_limit.
      2. Deterministic node execution and condition routing.
      3. Immutable state flow between cycles.
    """

    def __init__(self, max_recursion_limit: int = 10):
        self.max_recursion_limit = max_recursion_limit
        self.nodes: Dict[str, Callable[[GraphState], Dict[str, Any]]] = {}
        self.edges: Dict[str, str] = {}
        self.conditional_edges: Dict[str, Callable[[GraphState], str]] = {}
        self.entry_point: Optional[str] = None

    def add_node(self, name: str, func: Callable[[GraphState], Dict[str, Any]]) -> "StateGraph":
        """Registers an executable node in the graph."""
        if name in self.nodes:
            raise ValueError(f"Node '{name}' already exists in graph.")
        self.nodes[name] = func
        return self

    def set_entry_point(self, name: str) -> "StateGraph":
        """Sets the initial starting node for execution."""
        if name not in self.nodes:
            raise ValueError(f"Entry point '{name}' must be an existing node.")
        self.entry_point = name
        return self

    def add_edge(self, from_node: str, to_node: str) -> "StateGraph":
        """Adds a deterministic direct transition edge between two nodes."""
        if from_node not in self.nodes:
            raise ValueError(f"Source node '{from_node}' does not exist.")
        if to_node != END and to_node not in self.nodes:
            raise ValueError(f"Target node '{to_node}' does not exist.")
        self.edges[from_node] = to_node
        return self

    def add_conditional_edge(
        self,
        from_node: str,
        condition_func: Callable[[GraphState], str]
    ) -> "StateGraph":
        """
        Adds a dynamic cyclic/branching edge where the next node is decided
        by inspecting the current state (e.g. check for errors to loop back).
        """
        if from_node not in self.nodes:
            raise ValueError(f"Source node '{from_node}' does not exist.")
        self.conditional_edges[from_node] = condition_func
        return self

    def execute(self, initial_inputs: Dict[str, Any]) -> GraphState:
        """
        Executes the State Machine until END sentinel is reached
        or max_recursion_limit is triggered.
        """
        if not self.entry_point:
            raise RuntimeError("Graph cannot execute without an entry_point defined.")

        current_node = self.entry_point
        state = GraphState(values=initial_inputs)

        while current_node != END:
            # 1. Runway Infinite Loop Protection Guard
            if state.step_count >= self.max_recursion_limit:
                raise RecursionLimitExceeded(
                    f"Execution halted: Exceeded max recursion limit of {self.max_recursion_limit} steps. "
                    f"Execution path trace: {' -> '.join(state.history)}"
                )

            # 2. Execute Node logic
            node_fn = self.nodes.get(current_node)
            if not node_fn:
                raise InvalidStateTransition(f"Dead-end: Node '{current_node}' is not registered.")

            # Update state immutably
            node_output = node_fn(state)
            state = state.update(node_output, current_node)

            # 3. Determine Next Transition
            if current_node in self.conditional_edges:
                routing_fn = self.conditional_edges[current_node]
                next_node = routing_fn(state)
            elif current_node in self.edges:
                next_node = self.edges[current_node]
            else:
                raise InvalidStateTransition(
                    f"Orphan Node: '{current_node}' has no outgoing edges or condition defined."
                )

            current_node = next_node

        return state
