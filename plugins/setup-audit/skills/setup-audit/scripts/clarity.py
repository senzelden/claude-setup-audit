"""Opt-in linguistic review candidates from bounded, already-redacted instruction excerpts.

These two local heuristics are not STE100 rules, a compliance checker, or automatic findings.
No configuration, instruction text, permissions, or scores are changed here.
"""
import re

MAX_FILES = 50
MAX_CANDIDATES = 20
MAX_CHARS = 32768


def paragraphs(text):
    """Yield prose paragraphs with original line numbers, excluding frontmatter and fences."""
    block, start, fence = [], 1, None
    frontmatter = text.startswith('---\n')
    for number, line in enumerate(text.splitlines(), 1):
        if frontmatter:
            if number > 1 and line.strip() == '---':
                frontmatter = False
            continue
        marker = re.match(r'^\s*(`{3,}|~{3,})', line)
        if marker:
            token = marker[1]
            if fence is None:
                fence = token
            elif token[0] == fence[0] and len(token) >= len(fence):
                fence = None
            if block:
                yield start, '\n'.join(block)
                block = []
            continue
        if fence:
            continue
        if not line.strip() or line.lstrip().startswith(('#', '|', '>')):
            if block:
                yield start, '\n'.join(block)
                block = []
            continue
        if not block:
            start = number
        block.append(line)
    if block:
        yield start, '\n'.join(block)


def candidates(text):
    found = []
    for line, paragraph in paragraphs(text[:MAX_CHARS]):
        prose = re.sub(r'`[^`]*`', '', paragraph)
        if (len(re.findall(r'\b(?:it|its)\b', prose, re.I)) >= 4 and len(prose.split()) >= 60
                and re.search(r'\b(?:read|query|edit|run|execute|open)\s+it\b', prose, re.I)):
            found.append(dict(check='CLR-referent', line=line, excerpt=paragraph[:1600],
                              excerpt_truncated=len(paragraph) > 1600,
                              review='Identify what each it/its refers to. Report only if two plausible referents change the required action.',
                              rewrite_guidance='Replace only ambiguous pronouns with the intended object; preserve conditions and permissions.'))
        if re.search(r'\b(?:quote|copy|print|include)\s+(?:the\s+)?(?:exact|verbatim)\s+(?:error|output|message)\b', prose, re.I):
            found.append(dict(check='CLR-exact-output', line=line, excerpt=paragraph[:1600],
                              excerpt_truncated=len(paragraph) > 1600,
                              review='Check whether exact output conflicts with a redaction rule. Reject when the source is explicitly public or fictional.',
                              rewrite_guidance='If redaction already applies, name the redacted output explicitly; otherwise ask which requirement controls.'))
    return found


def review(instructions, extension_inventory):
    entries = list(instructions.get('entries', []))
    entries += [e for p in extension_inventory.get('plugins', []) for e in p.get('components', [])
                if e.get('kind') in ('skills', 'commands', 'agents')]
    eligible = [e for e in entries if isinstance(e.get('excerpt'), str)]
    selected = eligible[:MAX_FILES]
    output, candidate_count = [], 0
    for entry in selected:
        for item in candidates(entry['excerpt']):
            candidate_count += 1
            if len(output) < MAX_CANDIDATES:
                output.append(dict(item, source=entry['source'], scope=entry.get('scope', 'plugin'),
                                   source_status=entry.get('status', 'unknown'), review_status='unreviewed'))
    return dict(enabled=True, purpose='communication_correctness', candidates=output,
                coverage=dict(eligible=len(eligible), scanned=len(selected), omitted=max(0, len(eligible)-len(selected)),
                              candidate_count=candidate_count, candidates_omitted=max(0, candidate_count-MAX_CANDIDATES)),
                limitations=['Candidate patterns require contextual review, not automatic findings or rewrites.',
                             'Only collected excerpts are inspected; code blocks, frontmatter, imports and runtime hook output are excluded.',
                             'No STE100 compliance, model-quality improvement, or token-saving claim.'])
