#!/bin/bash
# Fixture: a small Python repo with a pass-pointer .envrc and one undeclared required variable.
set -euo pipefail
: "${EVAL_EVIDENCE_DIR:?Set EVAL_EVIDENCE_DIR to a trusted directory outside the eval workspace}"

mkdir -p claude-config/projects/fixture-app app/src app/tests

printf 'use_pass ANTHROPIC_API_KEY api/anthropic\nexport LOG_LEVEL=info\n' > app/.envrc

cat > app/src/app.py <<'EOF'
import os

API_KEY = os.environ["ANTHROPIC_API_KEY"]
DATABASE_URL = os.environ["DATABASE_URL"]
LOG_LEVEL = os.getenv("LOG_LEVEL", "info")
EOF

printf '[project]\nname = "app"\nversion = "0.1.0"\n\n[tool.ruff]\nline-length = 100\n' > app/pyproject.toml
printf 'def test_ok():\n    assert True\n' > app/tests/test_app.py

# One transcript record so the collector discovers ./app as a project Claude Code was used in.
printf '{"type":"user","cwd":"%s/app","message":{"content":"hi"}}\n' "$PWD" > claude-config/projects/fixture-app/session.jsonl

git -C app init -q

# Scaffold runs before the model; retain the baseline outside its workspace.
python3 "$(dirname "${BASH_SOURCE[0]}")/../helpers/check_quality.py" capture \
  --workspace "$PWD" --evidence-dir "$EVAL_EVIDENCE_DIR" \
  --case readiness-envrc-pointers
