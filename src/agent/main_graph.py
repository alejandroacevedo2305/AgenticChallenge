"""Main graph for the SOC agent.

This graph orchestrates the complete security analysis workflow by composing
the following subgraphs in sequence:

1. subgraph_parse_logs: Parses authentication logs from auth.log
2. subgraph_detect_anomalies: Detects suspicious patterns using LLM
3. subgraph_enrich_indicators: Enriches IPs with threat intelligence
4. subgraph_generate_report: Generates comprehensive incident report

Workflow: auth.log → [Parse] → [Detect Anomalies] → [Enrich with Threat Intel] → [Generate Report] → incident_report.md

use as:
source venv/bin/activate && python src/agent/main_graph.py

or

source venv/bin/activate && python -m src.agent.main_graph
"""

from __future__ import annotations

import asyncio
import os
from dataclasses import dataclass
from typing import Any, Dict, List
from typing_extensions import TypedDict

from dotenv import load_dotenv
from langchain_core.runnables import RunnableConfig
from langchain_ollama import ChatOllama
from langgraph.graph import END, START, StateGraph

# Import all subgraphs
from src.agent.subgraph_parse_logs import subgraph_parse_logs
from src.agent.subgraph_detect_anomalies import subgraph_detect_anomalies
from src.agent.subgraph_enrich_indicators import subgraph_enrich_indicators
from src.agent.subraph_generate_report import subgraph_generate_report

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
    throughout the analysis process. All subgraphs share this state schema.
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


# Build the main graph by composing subgraphs
def build_main_graph():
    """Build the main SOC agent graph by composing all subgraphs.

    The graph executes the following workflow:
    1. Parse logs from auth.log
    2. Detect anomalies in parsed logs
    3. Enrich suspicious IPs with threat intelligence
    4. Generate comprehensive incident report

    Returns:
        Compiled StateGraph ready for execution
    """
    builder = StateGraph(SOCState)

    # Add all subgraphs as nodes
    # Since all subgraphs share the SOCState schema, we can add them directly
    builder.add_node("parse_logs", subgraph_parse_logs)
    builder.add_node("detect_anomalies", subgraph_detect_anomalies)
    builder.add_node("enrich_indicators", subgraph_enrich_indicators)
    builder.add_node("generate_report", subgraph_generate_report)

    # Define the workflow sequence
    builder.add_edge(START, "parse_logs")
    builder.add_edge("parse_logs", "detect_anomalies")
    builder.add_edge("detect_anomalies", "enrich_indicators")
    builder.add_edge("enrich_indicators", "generate_report")
    builder.add_edge("generate_report", END)

    # Compile the graph
    return builder.compile()


# Create the main graph instance
main_graph = build_main_graph()


async def save_report_to_file(
    report_content: str, output_path: str = "incident_report.md"
):
    """Save the generated incident report to a markdown file.

    Args:
        report_content: The markdown-formatted incident report
        output_path: Path where to save the report (default: incident_report.md)
    """
    try:
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(report_content)
        print(f"\n✅ Report saved to: {output_path}")
    except Exception as e:
        print(f"❌ Error saving report to file: {e}")


if __name__ == "__main__":

    async def _main() -> None:
        """Execute the complete SOC analysis workflow."""

        print("=" * 80)
        print("🚀 Starting SOC Agent Analysis Pipeline")
        print("=" * 80)

        # Initial state with log file path
        initial_state = {"log_file_path": "data/auth.log"}

        # Track progress through the pipeline
        step_names = {
            "parse_logs": "📖 Step 1/4: Parsing authentication logs",
            "detect_anomalies": "🔍 Step 2/4: Detecting anomalies with AI",
            "enrich_indicators": "🌐 Step 3/4: Enriching with threat intelligence",
            "generate_report": "📝 Step 4/4: Generating incident report",
        }

        final_state = None

        # Stream the graph execution with subgraph outputs
        async for chunk in main_graph.astream(
            initial_state,
            stream_mode="updates",
            subgraphs=True,  # Include subgraph outputs
            debug=False,  # Set to True for detailed debugging
        ):
            # Handle main graph updates
            if isinstance(chunk, tuple) and len(chunk) == 2:
                path, update = chunk

                # Check if this is a main graph node update
                if not path:  # Empty tuple means main graph
                    for node_name, node_data in update.items():
                        if node_name in step_names:
                            print(f"\n{step_names[node_name]}")

                            # Show summary of what was processed
                            if node_name == "parse_logs" and "parsed_logs" in node_data:
                                print(
                                    f"  ✓ Parsed {len(node_data['parsed_logs'])} log entries"
                                )

                            elif (
                                node_name == "detect_anomalies"
                                and "suspicious_events" in node_data
                            ):
                                print(
                                    f"  ✓ Detected {len(node_data['suspicious_events'])} suspicious events"
                                )

                            elif (
                                node_name == "enrich_indicators"
                                and "enriched_data" in node_data
                            ):
                                print(
                                    f"  ✓ Enriched {len(node_data['enriched_data'])} unique IPs"
                                )

                            elif (
                                node_name == "generate_report"
                                and "incident_report" in node_data
                            ):
                                print(f"  ✓ Report generated successfully")
                                final_state = node_data

                # Subgraph updates (nested path)
                elif len(path) > 0:
                    # Extract subgraph name from path
                    subgraph_info = path[0].split(":")[0] if ":" in path[0] else path[0]

                    # Optional: Show subgraph internal progress
                    # Uncomment for more detailed output
                    # print(f"    → Subgraph [{subgraph_info}] processing...")

        # Save the final report
        if final_state and "incident_report" in final_state:
            print("\n" + "=" * 80)
            print("📊 Analysis Complete!")
            print("=" * 80)

            # Save to file
            await save_report_to_file(final_state["incident_report"])

            # Print summary from the report
            report_lines = final_state["incident_report"].split("\n")

            # Extract risk level
            for line in report_lines[:10]:
                if "**Risk Level**:" in line:
                    print(f"\n{line}")
                    break

            # Show first few lines of executive summary
            print("\n📋 Report Preview:")
            print("-" * 40)
            in_summary = False
            lines_shown = 0
            for line in report_lines:
                if "## Executive Summary" in line:
                    in_summary = True
                    continue
                if in_summary and line.strip() and not line.startswith("#"):
                    print(line)
                    lines_shown += 1
                    if lines_shown >= 2:
                        break

            print("-" * 40)
            print("\n✅ Full report saved to: incident_report.md")
            print("📄 Open the file to view the complete analysis")

        else:
            print("\n❌ Error: No report was generated")

    # Run the async main function
    asyncio.run(_main())
