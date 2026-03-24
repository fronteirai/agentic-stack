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
from typing import Any, Dict, List, Optional

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
            "totals, and optionally a filtered CVE list. Stats and list respect the same "
            "optional severity/vendor filters. Unfiltered stats describe the whole dataset "
            "only when no filters are passed. Prefer refresh_vulnerability_table_snapshot "
            "when summarizing what the user sees in the table."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "severity": {
                    "type": "string",
                    "description": "Optional severity filter for stats and list (LOW|MEDIUM|HIGH|CRITICAL|UNKNOWN)",
                },
                "vendor": {
                    "type": "string",
                    "description": "Optional exact vendor filter for stats and list",
                },
                "include_vulnerability_list": {
                    "type": "boolean",
                    "description": "If true, include /api/vulnerabilities rows (can be large)",
                },
            },
        },
    },
}

REFRESH_VULNERABILITY_TABLE_SNAPSHOT_TOOL = {
    "type": "function",
    "function": {
        "name": "refresh_vulnerability_table_snapshot",
        "description": (
            "Load CVE rows matching the CURRENT dashboard filters (severity_filter and "
            "vendor_filter already in shared LangGraph/CopilotKit state) from the API, "
            "write them into vulnerability_table_snapshot in shared state, and return "
            "exact counts and a severity breakdown for those rows only. Call "
            "set_dashboard_filters first if the user asked for a specific vendor or "
            "severity. When the user asks to summarize, list, or analyze the "
            "vulnerability table, you MUST call this tool (after filters are set) and "
            "base your answer only on this tool's payload—not on unfiltered global stats."
        ),
        "parameters": {"type": "object", "properties": {}},
    },
}

# Keep CopilotKit / websocket payloads reasonable; counts in the tool response stay exact.
_MAX_TABLE_SNAPSHOT_ROWS = 500


def _http_get_json(path: str) -> Dict[str, Any]:
    url = f"{CYBER_RISK_API_BASE}{path}"
    req = urllib.request.Request(url, headers={"Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=45) as resp:
        return json.loads(resp.read().decode())


async def _http_get_json_async(path: str) -> Dict[str, Any]:
    return await asyncio.to_thread(_http_get_json, path)


def _stats_path_for_filters(severity: str, vendor: str) -> str:
    qs: List[str] = []
    if severity:
        qs.append(f"severity={urllib.parse.quote(severity)}")
    if vendor:
        qs.append(f"vendor={urllib.parse.quote(vendor)}")
    return "/api/stats" + ("?" + "&".join(qs) if qs else "")


def _vulnerabilities_path_for_filters(severity: str, vendor: str) -> str:
    qs: List[str] = []
    if severity:
        qs.append(f"severity={urllib.parse.quote(severity)}")
    if vendor:
        qs.append(f"vendor={urllib.parse.quote(vendor)}")
    return "/api/vulnerabilities" + ("?" + "&".join(qs) if qs else "")


def _severity_breakdown_from_rows(rows: List[Any]) -> Dict[str, int]:
    out: Dict[str, int] = {}
    for row in rows:
        if not isinstance(row, dict):
            continue
        sev = str(row.get("severity") or "UNKNOWN").upper()
        out[sev] = out.get(sev, 0) + 1
    return out


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
    vulnerability_table_snapshot: List[Dict[str, Any]] = []
    vulnerability_table_total_count: int = 0


async def start_flow(state: Dict[str, Any], config: RunnableConfig):
    if state.get("severity_filter") is None:
        state["severity_filter"] = ""
    if state.get("vendor_filter") is None:
        state["vendor_filter"] = ""
    if state.get("vulnerability_table_snapshot") is None:
        state["vulnerability_table_snapshot"] = []
    if state.get("vulnerability_table_total_count") is None:
        state["vulnerability_table_total_count"] = 0
    await copilotkit_emit_state(config, state)
    return Command(
        goto="chat_node",
        update={
            "severity_filter": state["severity_filter"],
            "vendor_filter": state["vendor_filter"],
            "vulnerability_table_snapshot": state.get("vulnerability_table_snapshot", []),
            "vulnerability_table_total_count": state.get("vulnerability_table_total_count", 0),
        },
    )


async def chat_node(state: Dict[str, Any], config: RunnableConfig):
    sev = state.get("severity_filter") or ""
    vend = state.get("vendor_filter") or ""
    snap = state.get("vulnerability_table_snapshot") or []
    snap_n = state.get("vulnerability_table_total_count")
    if snap_n is None:
        snap_n = len(snap) if isinstance(snap, list) else 0

    system_prompt = f"""You are the cyber risk dashboard copilot for a vulnerability risk app.

The UI shows CVEs from a backend with columns: CVE ID, vendor, description, severity, risk score, date.
Users can ask you in natural language to filter the table.

Current dashboard filters:
- severity_filter: "{sev}" (empty means all severities)
- vendor_filter: "{vend}" (empty means all vendors)

Shared state may include vulnerability_table_snapshot (rows currently shown for those filters).
Reported total row count for that snapshot: {snap_n} (snapshot may be truncated for transport).

When the user wants to change what they see, call set_dashboard_filters with the new values.
Vendor names must match exactly what the API returns (use get_cyber_risk_snapshot with no filters to list vendors if unsure).

When they ask about global totals or all vendors, call get_cyber_risk_snapshot without filters.

When they ask to summarize, list, count, or analyze CVEs for the current or requested filters
(e.g. "summarize slackware vendor risks"), you MUST:
1) Call set_dashboard_filters so vendor_filter and/or severity_filter match the request (use exact vendor spelling).
2) Call refresh_vulnerability_table_snapshot so shared state and the tool result reflect the filtered table.
3) Answer using ONLY the refresh_vulnerability_table_snapshot result (severity_breakdown, row_count, rows)—never use unfiltered global stats for a vendor-specific summary.

After calling set_dashboard_filters, you may chain refresh_vulnerability_table_snapshot in the same turn before answering.
"""

    if config is None:
        config = RunnableConfig(recursion_limit=25)

    config = copilotkit_customize_config(config)

    # CopilotKit HTTP runs often send partial state (filters only). Frontend actions
    # arrive under state["copilotkit"]["actions"] once merged; default to [].
    ck = state.get("copilotkit") or {}
    frontend_actions = list(ck.get("actions") or [])

    model = ChatOpenAI(model="gpt-4o-mini", temperature=0.1)
    model_with_tools = model.bind_tools(
        [
            *frontend_actions,
            SET_DASHBOARD_FILTERS_TOOL,
            GET_CYBER_RISK_SNAPSHOT_TOOL,
            REFRESH_VULNERABILITY_TABLE_SNAPSHOT_TOOL,
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
                "vulnerability_table_snapshot": state.get("vulnerability_table_snapshot", []),
                "vulnerability_table_total_count": state.get("vulnerability_table_total_count", 0),
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
        state["vulnerability_table_snapshot"] = []
        state["vulnerability_table_total_count"] = 0
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
                "vulnerability_table_snapshot": [],
                "vulnerability_table_total_count": 0,
            },
        )

    if tool_name == "refresh_vulnerability_table_snapshot":
        q_sev = _normalize_severity(state.get("severity_filter"))
        q_vend = (state.get("vendor_filter") or "").strip()
        try:
            path = _vulnerabilities_path_for_filters(q_sev, q_vend)
            raw_rows = await _http_get_json_async(path)
            if not isinstance(raw_rows, list):
                raw_rows = []
            rows_typed = [r for r in raw_rows if isinstance(r, dict)]
            total = len(rows_typed)
            breakdown = _severity_breakdown_from_rows(rows_typed)
            truncated = total > _MAX_TABLE_SNAPSHOT_ROWS
            snapshot = rows_typed[:_MAX_TABLE_SNAPSHOT_ROWS]
            state["vulnerability_table_snapshot"] = snapshot
            state["vulnerability_table_total_count"] = total
            await copilotkit_emit_state(config, state)
            payload_out = {
                "ok": True,
                "filters": {"severity": q_sev or None, "vendor": q_vend or None},
                "row_count": total,
                "severity_breakdown": breakdown,
                "snapshot_truncated": truncated,
                "rows_in_response": min(total, _MAX_TABLE_SNAPSHOT_ROWS),
                "rows": snapshot,
            }
        except urllib.error.HTTPError as e:
            payload_out = {"ok": False, "error": f"HTTP {e.code}", "details": e.reason}
        except urllib.error.URLError as e:
            payload_out = {"ok": False, "error": "request_failed", "details": str(e.reason)}
        except Exception as e:  # pylint: disable=broad-exception-caught
            payload_out = {"ok": False, "error": "unexpected", "details": str(e)}

        tool_message = {
            "role": "tool",
            "content": json.dumps(payload_out, default=str)[:120000],
            "tool_call_id": tool_call_id,
        }
        messages = messages + [tool_message]
        return Command(
            goto="chat_node",
            update={
                "messages": messages,
                "severity_filter": state.get("severity_filter", ""),
                "vendor_filter": state.get("vendor_filter", ""),
                "vulnerability_table_snapshot": state.get("vulnerability_table_snapshot", []),
                "vulnerability_table_total_count": state.get("vulnerability_table_total_count", 0),
            },
        )

    if tool_name == "get_cyber_risk_snapshot":
        include_list = bool(args.get("include_vulnerability_list", False))
        q_sev = _normalize_severity(args.get("severity"))
        q_vend = (args.get("vendor") or "").strip()
        try:
            stats_path = _stats_path_for_filters(q_sev, q_vend)
            stats = await _http_get_json_async(stats_path)
            payload: Dict[str, Any] = {"stats": stats}
            if include_list:
                path = _vulnerabilities_path_for_filters(q_sev, q_vend)
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
                "vulnerability_table_snapshot": state.get("vulnerability_table_snapshot", []),
                "vulnerability_table_total_count": state.get("vulnerability_table_total_count", 0),
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
