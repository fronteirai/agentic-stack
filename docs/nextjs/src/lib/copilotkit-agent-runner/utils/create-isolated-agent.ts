import { LangGraphAgent } from "@copilotkit/runtime/langgraph";
import { Client } from "@langchain/langgraph-sdk";
import { DEFAULT_TIMEOUT } from "../runner/constants";

type ClientInternals = {
  apiUrl: string;
};

export interface CreateIsolatedAgentConfig {
  deploymentUrl: string;
  graphId: string;
  langsmithApiKey?: string;
  clientTimeoutMs?: number;
  debug?: boolean;
}

export function createIsolatedAgent(
  config: CreateIsolatedAgentConfig
): LangGraphAgent {
  const timeout = config.clientTimeoutMs ?? DEFAULT_TIMEOUT;

  const isolatedConfig = Object.freeze({
    deploymentUrl: String(config.deploymentUrl),
    graphId: String(config.graphId),
    langsmithApiKey: config.langsmithApiKey
      ? String(config.langsmithApiKey)
      : undefined,
    debug: Boolean(config.debug),
  });

  const agent = new LangGraphAgent(isolatedConfig);

  const clientInternals = agent.client as unknown as ClientInternals;
  const expectedUrl = config.deploymentUrl.replace(/\/$/, "");
  const actualUrl = clientInternals.apiUrl?.replace(/\/$/, "");
  const needsOurClient =
    actualUrl == null || actualUrl === "" || expectedUrl !== actualUrl;

  if (needsOurClient) {
    if (actualUrl != null && actualUrl !== "" && expectedUrl !== actualUrl) {
      console.warn(
        `[LangGraphHistory] URL mismatch detected! Expected: ${expectedUrl}, Got: ${actualUrl}. Replacing client.`
      );
    }

    const newClient = new Client({
      apiUrl: config.deploymentUrl,
      apiKey: config.langsmithApiKey,
      timeoutMs: timeout,
    });

    Object.assign(agent, { client: newClient });
  }

  return agent;
}

