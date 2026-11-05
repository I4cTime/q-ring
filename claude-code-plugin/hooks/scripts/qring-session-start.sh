#!/usr/bin/env bash
# q-ring · SessionStart hook
#
# Claude Code plugins have no rules component and a plugin-root CLAUDE.md is
# not loaded, so this hook is the one always-on channel the plugin has. It
# injects, through hookSpecificOutput.additionalContext:
#
#   1. A one-line note: call `get_project_context` at the start of any
#      secret-related task, plus the slash commands.
#   2. When `.q-ring.json` exists in the project root, a nudge to call
#      `check_project`.
#   3. q-ring's always-on rules (secret hygiene + q-ring workflow), read from
#      ../qring-session-rules.md. That file is GENERATED from
#      cursor-plugin/rules/*.mdc by `pnpm run plugin:gen-skills`; do not edit it
#      by hand. The rules are skipped when they already load from a file: the
#      project-copy CLAUDE.md (`pnpm run plugin:sync:claude`), or the plugin's
#      rules/ copied into ~/.claude/rules/qring/ or <project>/.claude/rules/qring/.
#
# The hook has no matcher, so it fires for every SessionStart `source`
# (startup, resume, clear, compact). The rules are skipped on `resume`: the
# resumed transcript already carries the copy injected at startup. They are
# injected on startup, clear and compact (a compaction summary may have
# dropped them). Empty or non-JSON stdin is treated as startup. The note and
# the check_project nudge are injected for every source.
#
# Required tools: jq (builds the JSON, so quotes, backslashes and newlines in
# the rules are escaped safely). Always exits 0; never blocks the session.

set -u

if ! command -v jq >/dev/null 2>&1; then
  exit 0
fi

dir="${CLAUDE_PROJECT_DIR:-${PWD}}"
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" 2>/dev/null && pwd)"
rules_file="${script_dir}/../qring-session-rules.md"

# SessionStart payload on stdin; `source` is startup|resume|clear|compact.
# Missing or malformed input leaves it empty, which is handled as startup.
payload=""
if [ ! -t 0 ]; then
  payload="$(cat 2>/dev/null || true)"
fi
source_kind="$(printf '%s' "${payload}" | jq -r '.source? // empty | strings' 2>/dev/null || true)"

note="q-ring is wired into this project (see CLAUDE.md and .mcp.json). At the start of any secret-related task, call the \`get_project_context\` MCP tool for an up-to-date redacted view of secrets, environment, manifest, and policy. Available slash commands: /qring-scan-secrets, /qring-health-check, /qring-rotate-expired, /qring-setup-project, /qring-teleport-secrets, /qring-dashboard, /qring-exec-safe, /qring-analyze."

manifest=""
if [ -f "${dir}/.q-ring.json" ]; then
  manifest="Detected \`.q-ring.json\` in the project root — the agent should call \`check_project\` to verify required secrets are present, and surface anything missing/expired/stale."
fi

rules_loaded_elsewhere() {
  if [ -f "${dir}/CLAUDE.md" ] && grep -qF 'q-ring · Secret hygiene' "${dir}/CLAUDE.md" 2>/dev/null; then
    return 0
  fi
  for rules_dir in "${HOME:-/nonexistent}/.claude/rules/qring" "${dir}/.claude/rules/qring"; do
    if [ -f "${rules_dir}/secret-hygiene.md" ]; then
      return 0
    fi
  done
  return 1
}

rules=""
if [ "${source_kind}" != "resume" ] && [ -f "${rules_file}" ] && ! rules_loaded_elsewhere; then
  rules="$(cat "${rules_file}" 2>/dev/null || true)"
fi

jq -nc --arg note "${note}" --arg manifest "${manifest}" --arg rules "${rules}" '{
  hookSpecificOutput: {
    hookEventName: "SessionStart",
    additionalContext: ([$note, $manifest, $rules] | map(select(. != "")) | join("\n\n"))
  }
}' || true

exit 0
