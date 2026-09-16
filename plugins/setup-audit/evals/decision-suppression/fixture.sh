#!/bin/bash
set -euo pipefail
fixture_evidence_dir=${EVAL_EVIDENCE_DIR:-"$(dirname "${BASH_SOURCE[0]}")/../results/manifests"}
mkdir -p claude-config repo inputs
printf '{}\n' > claude-config/settings.json
git -C repo init -q
python3 "$(dirname "${BASH_SOURCE[0]}")/seed.py"
python3 "$(dirname "${BASH_SOURCE[0]}")/../helpers/check_quality.py" capture \
  --workspace "$PWD" --evidence-dir "$fixture_evidence_dir" --case decision-suppression
