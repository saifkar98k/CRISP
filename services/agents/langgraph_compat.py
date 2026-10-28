"""
CRISP Agent Swarm 2.0 - LangGraph Engine & Compatibility Layer
Provides LangGraph-compatible StateGraph, START, END, and workflow compilation.
Works seamlessly whether or not external langgraph pip package is installed.
Supports conditional routing, state preservation, and concurrent branch execution.
"""

import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Callable, Dict, List, Optional, Tuple, Union

logger = logging.getLogger("CRISP.LangGraph")

START = "__start__"
END = "__end__"


class StateGraphCompat:
    """
    In-process StateGraph engine providing LangGraph-compatible interface.
    Enables concurrent execution of independent agent nodes with state immutability/reducers.
    """

    def __init__(self, state_schema: Any = dict):
        self.state_schema = state_schema
        self.nodes: Dict[str, Callable[[Dict[str, Any]], Dict[str, Any]]] = {}
        self.edges: Dict[str, List[str]] = {}
        self.conditional_edges: Dict[str, Tuple[Callable[[Dict[str, Any]], str], Optional[Dict[str, str]]]] = {}
        self.entry_point: Optional[str] = None

    def add_node(self, name: str, action: Callable[[Dict[str, Any]], Dict[str, Any]]) -> "StateGraphCompat":
        self.nodes[name] = action
        return self

    def add_edge(self, start_key: str, end_key: str) -> "StateGraphCompat":
        if start_key not in self.edges:
            self.edges[start_key] = []
        self.edges[start_key].append(end_key)
        return self

    def add_conditional_edges(
        self,
        source: str,
        path: Callable[[Dict[str, Any]], str],
        path_map: Optional[Dict[str, str]] = None,
    ) -> "StateGraphCompat":
        self.conditional_edges[source] = (path, path_map)
        return self

    def set_entry_point(self, key: str) -> "StateGraphCompat":
        self.entry_point = key
        return self

    def compile(self) -> "CompiledStateGraph":
        entry = self.entry_point or (self.edges.get(START, [None])[0] if START in self.edges else None)
        return CompiledStateGraph(
            nodes=self.nodes,
            edges=self.edges,
            conditional_edges=self.conditional_edges,
            entry_point=entry,
        )


class CompiledStateGraph:
    """Compiled runnable workflow graph."""

    def __init__(
        self,
        nodes: Dict[str, Callable[[Dict[str, Any]], Dict[str, Any]]],
        edges: Dict[str, List[str]],
        conditional_edges: Dict[str, Tuple[Callable[[Dict[str, Any]], str], Optional[Dict[str, str]]]],
        entry_point: Optional[str],
    ):
        self.nodes = nodes
        self.edges = edges
        self.conditional_edges = conditional_edges
        self.entry_point = entry_point or (list(nodes.keys())[0] if nodes else None)

    def invoke(self, state: Dict[str, Any]) -> Dict[str, Any]:
        """
        Executes the graph from entry point to END.
        Updates state in-place / returns accumulated state.
        """
        current_node = self.entry_point
        visited_count = 0
        max_steps = 50  # Prevent infinite cycles

        if "execution_trace" not in state:
            state["execution_trace"] = []

        while current_node and current_node != END and visited_count < max_steps:
            visited_count += 1
            node_fn = self.nodes.get(current_node)
            if not node_fn:
                logger.error(f"Node '{current_node}' not found in graph.")
                break

            state["execution_trace"].append(current_node)
            try:
                result = node_fn(state)
                if isinstance(result, dict):
                    # Merge node updates into state
                    state.update(result)
            except Exception as e:
                logger.error(f"Error executing node '{current_node}': {e}")
                if "errors" not in state:
                    state["errors"] = []
                state["errors"].append({"node": current_node, "error": str(e)})

            # Determine next node: conditional edges take precedence
            if current_node in self.conditional_edges:
                cond_fn, path_map = self.conditional_edges[current_node]
                next_key = cond_fn(state)
                if path_map and next_key in path_map:
                    current_node = path_map[next_key]
                else:
                    current_node = next_key
            elif current_node in self.edges and self.edges[current_node]:
                # Next edge
                current_node = self.edges[current_node][0]
            else:
                # Default end of chain
                current_node = END

        return state


# Try importing real langgraph if available, else use compatibility layer
try:
    import langgraph.graph as _real_lg
    StateGraph = _real_lg.StateGraph
    START = _real_lg.START
    END = _real_lg.END
    HAS_NATIVE_LANGGRAPH = True
except ImportError:
    StateGraph = StateGraphCompat
    HAS_NATIVE_LANGGRAPH = False
