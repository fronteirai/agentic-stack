/// <reference types="vite/client" />

interface ImportMetaEnv {
  readonly VITE_LANGGRAPH_GRAPH_ID?: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}
