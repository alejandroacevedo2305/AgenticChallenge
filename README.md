# Take-Home Assessment: The AI Junior SOC Analyst

Welcome! We're excited to see what you can build. This challenge is designed to be a fun, practical, and representative sample of the kind of work we do.

Think of this as an open source project. We're more interested in your thought process, design choices, and the quality of your work than in a specific "correct" answer. Be biased toward production-ready code over a large quantity of features.

**Time Expectation:** Please aim to spend approximately 3-4 hours of focused work on this challenge. If you run out of time, document your remaining plans in `DESIGN_CHOICES.md` rather than rushing through implementation.

---

## 1. The Mission: Build an AI Junior SOC Analyst

Your mission is to build the first prototype of an autonomous AI agent that assists a Security Operations Center (SOC) analyst.

This agent will receive a system log file (`auth.log`) and will need to autonomously:

1.  **Parse and analyze** the log data to identify suspicious patterns.
2.  **Use tools to enrich** suspicious indicators (like IP addresses) with threat intelligence from a local, mocked data source.
3.  **Synthesize its findings** into a structured, actionable incident report for a human analyst.

---

## 2. Getting Started: Your Development Environment

### Step 1: Fork and Clone the Repository

Fork this repository, then clone it to your local machine.

```bash
git clone git@github.com:<YOUR_GITHUB_USERNAME>/AgenticChallenge.git
cd AgenticChallenge
```

### Step 2: Set Up a Virtual Environment

```bash
python -m venv venv
source venv/bin/activate  # On Windows, use `venv\Scripts\activate`
```

### Step 3: Install Dependencies

```bash
pip install -e .
```

### Step 4: Set Up Your Local LLM with Ollama (Crucial Step!)

This project uses a local LLM to ensure privacy and avoid API key costs.

1. **Install Ollama:** Follow the instructions on the [Ollama website](https://ollama.com/).
2. **Pull the Model:** Once Ollama is running, pull the `llama3.1:8b` model.
   ```bash
   ollama pull llama3.1:8b
   ```
3. **Verify:** Ollama should be running and serving the model at `http://localhost:11434`.

**Optional Setup:** Configure environment variables by copying `.env.example` to `.env` and adjusting settings as needed.

**Start the Agent:** Once you've implemented your SOC agent, you can start it with:

```bash
langgraph dev
```

This will start the LangGraph server and make your agent accessible for testing and debugging.

You are now ready to start building!

---

## 3. The Core Challenge: Architecting the Agent

Your primary task is to build the agent's logic using LangGraph. The template is provided in `/src/agent/` following Python conventions, but you can reorganize as needed. The agent should be structured as a graph of interconnected nodes, where each node performs a specific function and passes its results to the next via a shared state object.

### The Big Picture

Your agent will process a single authentication log file and produce an incident report. Here's the data flow:

```
auth.log → [Parse] → [Detect Anomalies] → [Enrich with Threat Intel] → [Generate Report] → incident_report.md
```

Each node updates a shared `SOCState` object that carries information forward to the next node.

### Node Implementation Details

You will need to implement the following nodes and wire them together:

#### **Node 1: The Log Parser**

**Input:** `state.log_file_path` (pointing to `data/auth.log`)  
**Output:** `state.parsed_logs` (list of structured log entries)

- Read the raw log file line by line
- Parse each line into structured data (timestamp, service, event type, IP, user, etc.)
- Handle different log formats (failed logins, successful logins, sudo commands, etc.)
- Store results in `state.parsed_logs` as a list of dictionaries

**Example parsed entry:**

```python
{
    "timestamp": "Aug 11 17:15:12",
    "hostname": "ubuntu-server",
    "service": "sshd",
    "event_type": "failed_login",
    "user": "admin",
    "source_ip": "203.0.113.55",
    "port": 48122
}
```

#### **Node 2: The Anomaly Detector**

**Input:** `state.parsed_logs` (structured log data)  
**Output:** `state.suspicious_events` (list of identified threats)

- Use the Ollama LLM to analyze parsed logs for suspicious patterns
- Look for: brute force attacks, invalid users, unusual login patterns
- Craft effective prompts that help the LLM identify security threats
- Parse LLM responses into structured suspicious events

**Example suspicious event:**

```python
{
    "source_ip": "203.0.113.55",
    "event_type": "brute_force",
    "description": "Multiple failed login attempts followed by success",
    "severity": "HIGH",
    "affected_accounts": ["admin", "root", "user"]
}
```

#### **Node 3: The Enrichment Engine (Tool-Using Node)**

**Input:** `state.suspicious_events` (list of threats to investigate)  
**Output:** `state.enriched_data` (threat intelligence for each IP)

- For each suspicious IP address found, use tools to gather context
- **Implement the IP Reputation Tool:** A function that reads `data/mock_api_responses.json` and returns threat intelligence
- Handle cases where IPs aren't found in the mock data
- Store enrichment results in `state.enriched_data`

**Your IP Reputation Tool should:**

```python
def ip_reputation_tool(ip_address: str) -> dict:
    # Read data/mock_api_responses.json
    # Look up the IP address
    # Return threat intelligence data or None
    return {
        "abuse_confidence_score": 100,
        "country": "China",
        "threat_type": "brute_force"
    }
```

#### **Node 4: The Report Generator**

**Input:** `state.suspicious_events` + `state.enriched_data`  
**Output:** `state.incident_report` (final Markdown report)

- Use the Ollama LLM to synthesize all findings into a professional report
- Include: Executive Summary, Technical Details, IoCs, Risk Assessment, Recommended Actions
- Format as clean, actionable Markdown that a human analyst can use
- Make recommendations specific and concrete (e.g., "Block IP 203.0.113.55")

### Key Implementation Notes

1. **State Object:** The `SOCState` class is already defined with all necessary fields. Each node should update the relevant fields and return a dictionary with the updates.

2. **LLM Integration:** Use the provided `get_ollama_llm(config)` function to get a configured ChatOllama instance. Design your prompts carefully!

3. **Error Handling:** Use the `state.processing_errors` field to track any issues. Decide whether to fail fast or continue processing.

4. **File I/O:** Read from the provided data files (`data/auth.log`, `data/mock_api_responses.json`). Make sure your paths work correctly.

5. **Testing:** You can test your agent by running `langgraph dev` and interacting with it, or by running the evaluation tests.

The template provides placeholder implementations and detailed TODOs to guide you. Focus on getting the core functionality working before adding extra features!

---

## 4. Advanced Challenges (Optional, but Encouraged)

**⏰ Time Note:** These are truly optional! Focus on the core 4 nodes first. If you have extra time or want to showcase additional skills, these are great extensions. If not, just document your approach in `DESIGN_CHOICES.md`.

- **Challenge A: Automated Mitigation & Response:** Implement a "Response Planner" node that suggests concrete response steps (e.g., firewall rule syntax like `iptables -A INPUT -s 203.0.113.55 -j DROP`).

- **Challenge B: Multi-Tool Enrichment:** Expand the Enrichment Engine's toolkit by adding a second mocked tool. For example, a tool that takes a domain name, looks it up in the mock data file, and returns a mock "VirusTotal" report with malware detection results.

- **Challenge C: Threat Actor Profiling:** Add a "Profiler" node that attempts to attribute the activity to a type of threat actor (e.g., "APT group", "Script kiddie", "Botnet") based on the enriched data patterns.

---

## 5. Evaluation: How Good is Your Agent?

Implement your evaluation framework using the `agent-evals` library in the `tests/` directory. This should run your agent and compare its findings against `data/ground_truth.json`.

You must define and calculate at least two metrics:

1.  **Detection Rate (Recall):** What percentage of the known malicious IPs did your agent identify?
2.  **Report Quality Score:** Use an LLM call to evaluate the clarity, structure, and actionability of the final report (score 1-10).

**Key Files:**

- `tests/test_soc_agent_evaluation.py` - Main evaluation test suite (implement the TODOs)
- `tests/evaluation_config.py` - Configuration and LLM-as-a-judge prompts

**Run Evaluations:**

```bash
# Make sure your virtual environment is activated first
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Run the evaluation tests
pytest tests/test_soc_agent_evaluation.py -v
```

---

## 6. Submission Guidelines

1.  Push all your code to your forked repository on GitHub and ensure it is public.
2.  Send the link to your repository back to us.
3.  **The Most Important Part:** Fill out the `DESIGN_CHOICES.md` file in detail. We want to understand your thought process, the trade-offs you made, and what you would do next.

**⏰ Time Management:** We respect your time! If you're approaching the 3-4 hour mark and haven't finished implementing everything, that's completely fine. Simply document what you would do next in the `DESIGN_CHOICES.md` file. We're more interested in your architectural thinking and problem-solving approach than a fully polished implementation.

Good luck!
