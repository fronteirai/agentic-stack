import { CopilotRuntime } from "@copilotkit/runtime";
import { LangGraphAgent } from "@copilotkit/runtime/langgraph";
import { createCopilotEndpointSingleRouteExpress } from "@copilotkitnext/runtime/express";
import type { CopilotRuntime as CopilotRuntimeVNext } from "@copilotkitnext/runtime";
import type { Router } from "express";

/**
 * CopilotKit single-route handler backed by the LangGraph `cyber_risk` deployment.
 * Set LANGGRAPH_DEPLOYMENT_URL to your `langgraph dev` URL (see AGENTS_README.md).
 */
export function createCyberRiskCopilotRouter(): Router {
  const deploymentUrl = (process.env.LANGGRAPH_DEPLOYMENT_URL ?? "http://127.0.0.1:8000").replace(
    /\/$/,
    ""
  );
  const graphId = process.env.LANGGRAPH_GRAPH_ID ?? "cyber_risk";

  const agent = new LangGraphAgent({
    deploymentUrl,
    graphId,
    langsmithApiKey: process.env.LANGSMITH_API_KEY
  });

  const runtime = new CopilotRuntime({
    agents: { [graphId]: agent }
  });

  return createCopilotEndpointSingleRouteExpress({
    // @copilotkit/runtime nests a copy of @copilotkitnext/runtime; align types for the express helper.
    runtime: runtime.instance as unknown as CopilotRuntimeVNext,
    basePath: "/api/copilotkit"
  });
}
