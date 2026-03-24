# Getting Started

## Step 1: Set up environment variables (`.env` files)

**full-stack/nextjs/.env**
```
# Point to your local LangGraph dev server (playground-viewer/agent)
LANGGRAPH_DEPLOYMENT_URL=http://localhost:8000
# Must match the graph name in agent/langgraph.json and the frontend agent prop
LANGGRAPH_GRAPH_ID=cyber_risk

# Optional (for authentication)
# LANGSMITH_API_KEY=your-api-key
```

**full-stack/copilotkit/agent/.env**
```
OPENAI_API_KEY=
NEXT_PUBLIC_AGENT_TYPE=langgraph
# Base URL the LangGraph agent uses to call the Node API (stats / CVE list)
CYBER_RISK_API_BASE_URL=http://127.0.0.1:3001
```

## Step 2: Running the Langgraph Agent

a) Create and activate a Python 3.12 virtual environment:

```bash
cd agents/copilotkit/agent
python3.12 -m venv .venv
source .venv/bin/activate
```
*(Ensure you have Python 3.12 installed)*

b) Install base dependencies using Poetry:
```bash
poetry install
```

c) Install LangGraph API and CLI packages:
```bash
pip install -U langgraph-api
pip install "langgraph-cli[inmem]"
```

d) Run the LangGraph development server:
```bash
poetry run langgraph dev --host localhost --port 8000 --no-browser
```
