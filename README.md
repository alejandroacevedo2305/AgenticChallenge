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

You will need to implement the following nodes and wire them together:

- **Node 1: The Log Parser:** Reads `data/auth.log` and parses it into a structured format.
- **Node 2: The Anomaly Detector:** Uses an LLM to identify suspicious events from the structured log data.
- **Node 3: The Enrichment Engine (A Tool-Using Node):** For each suspicious indicator identified, it must use tools to gather external context. You will not use a live API. Instead, you will implement tools that read from the provided `data/mock_api_responses.json` file.
  - **IP Reputation Tool:** Implement a tool that takes an IP address as input, looks it up in the `mock_api_responses.json` file, and returns the corresponding mock data (e.g., abuse confidence score, country).
- **Node 4: The Report Generator:** Synthesizes all findings into a final, well-structured incident brief in Markdown format.

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
