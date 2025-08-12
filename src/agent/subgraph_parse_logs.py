"""Parse logs from a file and return a list of parsed logs.

use as:
source venv/bin/activate && python src/agent/subgraph_parse_logs.py

or

source venv/bin/activate && python -m src.agent.subgraph_parse_logs
"""

# %%
from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any, Dict, List
from typing_extensions import TypedDict

from dotenv import load_dotenv
from langchain_core.runnables import RunnableConfig
from langchain_ollama import ChatOllama
from langgraph.graph import StateGraph
from langgraph.graph import START, StateGraph

# Load environment variables
load_dotenv(override=True)


class Configuration(TypedDict):
    """Configurable parameters for the SOC agent.

    Set these when creating assistants OR when invoking the graph.
    """

    ollama_model: str
    ollama_base_url: str


@dataclass
class SOCState:
    """State for the SOC Analyst Agent.

    This state is passed between nodes and accumulates information
    throughout the analysis process.
    """

    # Input data
    log_file_path: str = "data/auth.log"  # Default to auth.log

    # Processed data
    parsed_logs: List[Dict[str, Any]] = None
    suspicious_events: List[Dict[str, Any]] = None
    enriched_data: Dict[str, Any] = None

    # Final output
    incident_report: str = ""

    # Metadata
    processing_errors: List[str] = None

    def __post_init__(self):
        """Initialize mutable default values."""
        if self.parsed_logs is None:
            self.parsed_logs = []
        if self.suspicious_events is None:
            self.suspicious_events = []
        if self.enriched_data is None:
            self.enriched_data = {}
        if self.processing_errors is None:
            self.processing_errors = []


def get_ollama_llm(config: RunnableConfig) -> ChatOllama:
    """Create and configure Ollama LLM instance.

    Args:
        config: Runtime configuration containing Ollama settings

    Returns:
        Configured ChatOllama instance
    """
    configuration = config.get("configurable", {})

    # Get Ollama settings from config or environment
    model = configuration.get("ollama_model") or os.getenv(
        "OLLAMA_MODEL", "llama3.1:8b"
    )
    base_url = configuration.get("ollama_base_url") or os.getenv(
        "OLLAMA_BASE_URL", "http://localhost:11434"
    )

    return ChatOllama(
        model=model,
        base_url=base_url,
        temperature=0.1,  # Low temperature for consistent analysis
    )


async def parse_logs(state: SOCState, config: RunnableConfig) -> Dict[str, Any]:
    """The Log Parser: Reads data/auth.log and parses it into a structured format.

    Parses SSH authentication logs from syslog format into structured data.
    """
    import re

    # Read the log file
    with open(state.log_file_path, "r", encoding="utf-8") as f:
        log_lines = f.readlines()

    parsed_logs = []

    for line in log_lines:
        line = line.strip()
        if not line:
            continue

        # Parse common fields: timestamp, hostname, service[pid]
        # Format: Aug 11 17:01:01 ubuntu-server sshd[1101]: ...
        base_pattern = r"^(\w+\s+\d+\s+\d+:\d+:\d+)\s+(\S+)\s+(\w+)\[(\d+)\]:\s+(.+)"
        base_match = re.match(base_pattern, line)

        if not base_match:
            continue

        timestamp = base_match.group(1)
        hostname = base_match.group(2)
        service = base_match.group(3)
        pid = int(base_match.group(4))
        message = base_match.group(5)

        log_entry = {
            "timestamp": timestamp,
            "hostname": hostname,
            "service": service,
            "pid": pid,
        }

        # Parse successful login
        # Format: Accepted publickey for user from 198.51.100.12 port 22 ssh2
        success_pattern = r"Accepted (\w+) for (\w+) from ([\d.]+) port (\d+)"
        success_match = re.search(success_pattern, message)

        if success_match:
            log_entry["event_type"] = "successful_login"
            log_entry["auth_method"] = success_match.group(1)
            log_entry["user"] = success_match.group(2)
            log_entry["source_ip"] = success_match.group(3)
            log_entry["port"] = int(success_match.group(4))
            parsed_logs.append(log_entry)
            continue

        # Parse failed login
        # Format: Failed password for invalid user admin from 203.0.113.55 port 48122 ssh2
        failed_pattern = (
            r"Failed \w+ for (?:invalid user )?(\w+) from ([\d.]+) port (\d+)"
        )
        failed_match = re.search(failed_pattern, message)

        if failed_match:
            log_entry["event_type"] = "failed_login"
            log_entry["user"] = failed_match.group(1)
            log_entry["source_ip"] = failed_match.group(2)
            log_entry["port"] = int(failed_match.group(3))

            # Check if it's an invalid user
            if "invalid user" in message:
                log_entry["reason"] = "invalid_user"

            parsed_logs.append(log_entry)

    return {"parsed_logs": parsed_logs}


builder = StateGraph(SOCState)
builder.add_node("parse_logs", parse_logs)
builder.add_edge(START, "parse_logs")
subgraph_parse_logs = builder.compile()

if __name__ == "__main__":
    import asyncio

    async def _main() -> None:
        async for _chunk in subgraph_parse_logs.astream(
            {"log_file_path": "data/auth.log"},
            stream_mode="updates",
            subgraphs=True,
            debug=True,
        ):
            pass

    asyncio.run(_main())
