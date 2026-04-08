/**
 * Enrich raw Postgres / pooler errors with actionable hints for local setup.
 */
export function formatSupabaseConnectionError(err: unknown): string {
  const message = err instanceof Error ? err.message : String(err);
  if (/tenant or user not found/i.test(message)) {
    return `${message} — In Supabase: Project Settings → Database → copy the pooler URI (Session mode is typical for a Node server). The username must be postgres.<your-project-ref>. If your password contains characters like , @ : $ #, URL-encode them in the URI. You may set DATABASE_URL instead of SUPABASE_URL.`;
  }
  if (/password authentication failed/i.test(message)) {
    return `${message} — Verify the database password in your Supabase dashboard and that it is URL-encoded inside the connection string.`;
  }
  return message;
}
