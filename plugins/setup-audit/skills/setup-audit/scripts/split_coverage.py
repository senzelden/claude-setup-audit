"""Usage: coverage.py <repo> <backup.bak> — how much of the original CLAUDE.md survives in the repo's markdown."""
import glob, os, re, sys
repo, bak = sys.argv[1], sys.argv[2]
norm = lambda s: re.sub(r"[\W_]+", " ", s).lower().strip()
corpus = " ".join(norm(open(f, errors="replace").read())
                  for f in glob.glob(f"{repo}/**/*.md", recursive=True) + glob.glob(f"{repo}/.claude/**/*.md", recursive=True)
                  if "/.worktrees/" not in f and "node_modules" not in f and "/archive/CLAUDE-" not in f)
lines = [l for l in open(bak) if len(l.strip()) > 50]
missing = [l for l in lines if not any(" ".join(w[i:i+8]) in corpus
           for w in [norm(l).split()] for i in range(0, max(1, len(w)-7), 4))]
print(f"{repo}: {len(lines)} substantive lines, {len(lines)-len(missing)} found, {len(missing)} not found")
