"""
Cyber risk dashboard assistant: shared CopilotKit state drives frontend filters
(severity, vendor) and can query the Node cyber-risk API for stats/lists.
"""

from __future__ import annotations

import asyncio
import json
import os
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Dict, Optional

from copilotkit import CopilotKitState
from copilotkit.langgraph import (
    copilotkit_customize_config,
    copilotkit_emit_state,
    copilotkit_exit,
)
from langchain_core.messages import SystemMessage
from langchain_core.runnables import RunnableConfig
from langchain_openai import ChatOpenAI
from langgraph.graph import END, START, StateGraph
from langgraph.types import Command

CYBER_RISK_API_BASE = os.getenv("CYBER_RISK_API_BASE_URL", "http://127.0.0.1:3001").rstrip(
    "/"
)

SET_DASHBOARD_FILTERS_TOOL = {
    "type": "function",
    "function": {
        "name": "set_dashboard_filters",
        "description": (
            "Update the vulnerability dashboard UI: severity and/or vendor filters. "
            "Call this whenever the user asks to filter, show only, or narrow CVEs by "
            "severity or vendor. Vendor must match an exact vendor string from the stats "
            "API (case-sensitive). Use empty string to clear a filter."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "severity_filter": {
                    "type": "string",
                    "description": (
                        "One of LOW, MEDIUM, HIGH, CRITICAL, UNKNOWN, or empty string for all"
                    ),
                },
                "vendor_filter": {
                    "type": "string",
                    "description": "Exact vendor name from the dataset, or empty string for all vendors",
                },
            },
            "required": ["severity_filter", "vendor_filter"],
        },
    },
}

GET_CYBER_RISK_SNAPSHOT_TOOL = {
    "type": "function",
    "function": {
        "name": "get_cyber_risk_snapshot",
        "description": (
            "Fetch live data from the cyber-risk backend: severity breakdown, vendors, "
            "totals, and optionally a filtered CVE list. Use for counts, summaries, or "
            "before picking an exact vendor name for filters."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "severity": {
                    "type": "string",
                    "description": "Optional severity filter for the list endpoint (LOW|MEDIUM|HIGH|CRITICAL|UNKNOWN)",
                },
                "vendor": {
                    "type": "string",
                    "description": "Optional exact vendor filter for the list endpoint",
                },
                "include_vulnerability_list": {
                    "type": "boolean",
                    "description": "If true, include /api/vulnerabilities rows (can be large)",
                },
            },
        },
    },
}


def _http_get_json(path: str) -> Dict[str, Any]:
    url = f"{CYBER_RISK_API_BASE}{path}"
    req = urllib.request.Request(url, headers={"Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=45) as resp:
        return json.loads(resp.read().decode())


async def _http_get_json_async(path: str) -> Dict[str, Any]:
    return await asyncio.to_thread(_http_get_json, path)


def _normalize_severity(raw: Optional[str]) -> str:
    if not raw:
        return ""
    u = str(raw).strip().upper()
    allowed = {"LOW", "MEDIUM", "HIGH", "CRITICAL", "UNKNOWN"}
    return u if u in allowed else ""


class AgentState(CopilotKitState):
    """Shared state with the React dashboard (via CopilotKit)."""

    severity_filter: str = ""
    vendor_filter: str = ""


async def start_flow(state: Dict[str, Any], config: RunnableConfig):
    if state.get("severity_filter") is None:
        state["severity_filter"] = ""
    if state.get("vendor_filter") is None:
        state["vendor_filter"] = ""
    await copilotkit_emit_state(config, state)
    return Command(
        goto="chat_node",
        update={
            "severity_filter": state["severity_filter"],
            "vendor_filter": state["vendor_filter"],
        },
    )


async def chat_node(state: Dict[str, Any], config: RunnableConfig):
    sev = state.get("severity_filter") or ""
    vend = state.get("vendor_filter") or ""

    system_prompt = f"""You are the cyber risk dashboard copilot for a vulnerability risk app.

The UI shows CVEs from a backend with columns: CVE ID, vendor, description, severity, risk score, date.
Users can ask you in natural language to filter the table.

Current dashboard filters:
- severity_filter: "{sev}" (empty means all severities)
- vendor_filter: "{vend}" (empty means all vendors)

When the user wants to change what they see, call set_dashboard_filters with the new values.
Vendor names must match exactly what the API returns (use get_cyber_risk_snapshot to list vendors if unsure).

When they ask how many CVEs, breakdowns, or what's in the data, call get_cyber_risk_snapshot.
After calling set_dashboard_filters, briefly confirm what you changed in one short sentence.
"""

    if config is None:
        config = RunnableConfig(recursion_limit=25)

    config = copilotkit_customize_config(config)

    model = ChatOpenAI(model="gpt-4o-mini", temperature=0.1)
    model_with_tools = model.bind_tools(
        [
            *state["copilotkit"]["actions"],
            SET_DASHBOARD_FILTERS_TOOL,
            GET_CYBER_RISK_SNAPSHOT_TOOL,
        ],
        parallel_tool_calls=False,
    )

    response = await model_with_tools.ainvoke(
        [SystemMessage(content=system_prompt), *state["messages"]],
        config,
    )
    messages = state["messages"] + [response]

    if not getattr(response, "tool_calls", None):
        await copilotkit_exit(config)
        return Command(
            goto=END,
            update={
                "messages": messages,
                "severity_filter": state.get("severity_filter", ""),
                "vendor_filter": state.get("vendor_filter", ""),
            },
        )

    tool_call = response.tool_calls[0]
    if isinstance(tool_call, dict):
        tool_call_id = tool_call["id"]
        tool_name = tool_call["name"]
        args = tool_call.get("args") or {}
    else:
        tool_call_id = tool_call.id
        tool_name = tool_call.name
        args = tool_call.args if isinstance(tool_call.args, dict) else {}
    if isinstance(args, str):
        args = json.loads(args) if args else {}

    if tool_name == "set_dashboard_filters":
        new_sev = _normalize_severity(args.get("severity_filter"))
        new_vend = (args.get("vendor_filter") or "").strip()
        state["severity_filter"] = new_sev
        state["vendor_filter"] = new_vend
        await copilotkit_emit_state(config, state)
        tool_message = {
            "role": "tool",
            "content": json.dumps(
                {
                    "ok": True,
                    "severity_filter": new_sev,
                    "vendor_filter": new_vend,
                }
            ),
            "tool_call_id": tool_call_id,
        }
        messages = messages + [tool_message]
        return Command(
            goto="chat_node",
            update={
                "messages": messages,
                "severity_filter": new_sev,
                "vendor_filter": new_vend,
            },
        )

    if tool_name == "get_cyber_risk_snapshot":
        include_list = bool(args.get("include_vulnerability_list", False))
        q_sev = _normalize_severity(args.get("severity"))
        q_vend = (args.get("vendor") or "").strip()
        try:
            stats = await _http_get_json_async("/api/stats")
            payload: Dict[str, Any] = {"stats": stats}
            if include_list:
                qs = []
                if q_sev:
                    qs.append(f"severity={urllib.parse.quote(q_sev)}")
                if q_vend:
                    qs.append(f"vendor={urllib.parse.quote(q_vend)}")
                path = "/api/vulnerabilities" + ("?" + "&".join(qs) if qs else "")
                payload["vulnerabilities"] = await _http_get_json_async(path)
        except urllib.error.HTTPError as e:
            payload = {"error": f"HTTP {e.code}", "details": e.reason}
        except urllib.error.URLError as e:
            payload = {"error": "request_failed", "details": str(e.reason)}
        except Exception as e:  # pylint: disable=broad-exception-caught
            payload = {"error": "unexpected", "details": str(e)}

        tool_message = {
            "role": "tool",
            "content": json.dumps(payload, default=str)[:120000],
            "tool_call_id": tool_call_id,
        }
        messages = messages + [tool_message]
        return Command(
            goto="chat_node",
            update={
                "messages": messages,
                "severity_filter": state.get("severity_filter", ""),
                "vendor_filter": state.get("vendor_filter", ""),
            },
        )

    # Unknown tool
    messages = messages + [
        {
            "role": "tool",
            "content": json.dumps({"error": "unknown_tool", "name": tool_name}),
            "tool_call_id": tool_call_id,
        }
    ]
    return Command(goto="chat_node", update={"messages": messages})


workflow = StateGraph(AgentState)
workflow.add_node("start_flow", start_flow)
workflow.add_node("chat_node", chat_node)
workflow.add_edge(START, "start_flow")
workflow.add_edge("start_flow", "chat_node")
workflow.add_edge("chat_node", END)

cyber_risk_graph = workflow.compile()
