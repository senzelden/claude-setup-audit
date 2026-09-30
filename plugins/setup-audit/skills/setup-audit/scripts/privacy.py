"""Privacy helpers: contextual secret detection (both modes) and metadata-only masking. Stdlib only."""
import math
import re
from collections import Counter

CONTEXT_TOKEN = '[REDACTED:context]'
CONTEXT_MIN_LEN, CONTEXT_MAX_LEN, PASSWORD_MIN_LEN, ENTROPY_MIN = 16, 512, 6, 3.5
PASSWORD_WORDS = {'password', 'passwd', 'pwd', 'passphrase', 'pass'}
SECRET_WORDS = {'key', 'secret', 'token', 'auth', 'credential', 'credentials', 'creds', 'signature',
                'sig', 'cookie', 'session', 'pat', 'apikey'}
QUALIFIERS = {'id', 'ids', 'name', 'names', 'file', 'path', 'dir', 'url', 'uri', 'env', 'var', 'type',
              'kind', 'format', 'count', 'len', 'length', 'size', 'max', 'min', 'limit', 'ttl', 'sha',
              'hash', 'digest', 'commit', 'rev', 'checksum', 'fingerprint', 'etag', 'hint', 'header',
              'field', 'prefix', 'mode', 'source', 'ref', 'version', 'expiry', 'expires'}
VALUE_CHARS = r'A-Za-z0-9+/_.~=-'
CONTEXT_RE = re.compile(
    r'(?<![\w.-])(?:(?P<flag>--?[A-Za-z][\w.-]{0,63})(?:\s+|=)'
    r'|(?P<label>[A-Za-z][\w.-]{0,63})["\']?\s*[:=]\s*)'
    rf'["\']?(?P<value>[{VALUE_CHARS}]{{{PASSWORD_MIN_LEN},{CONTEXT_MAX_LEN}}})(?![:{VALUE_CHARS}])')
UUID_RE = re.compile(r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\Z')
SNAKE_RE = re.compile(r'[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+\Z')
FILE_END_RE = re.compile(r'\.[a-z]{1,5}\Z')


def shannon(s):
    """Shannon entropy in bits per character; the empty string gives 0.0."""
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in Counter(s).values()) if n else 0.0


def label_segments(label):
    """camelCase split, then `[_.-]+` split, lowercased, leading dashes stripped, empties dropped."""
    spaced = re.sub(r'([a-z0-9])([A-Z])', r'\1_\2', label.lstrip('-'))
    return [s for s in re.split(r'[_.\-]+', spaced.lower()) if s]


def _is_password_word(segment):
    return segment in PASSWORD_WORDS or segment.endswith(('password', 'passwd'))


def _label_class(label):
    segments = label_segments(label)
    if any(s in QUALIFIERS for s in segments):
        return None
    words = [s for s in segments if not s.isdigit()]
    if words and _is_password_word(words[-1]):
        return 'password'
    if any(s in SECRET_WORDS or s.endswith(('key', 'secret', 'token')) for s in segments):
        return 'secret'
    return None


def _excluded(value):
    # The next flag, a reference, a path, or a SCREAMING_SNAKE name (`$<{(` cannot occur in a value).
    return (value.startswith(('-', '_', '/', '~', '.')) or FILE_END_RE.search(value) is not None
            or SNAKE_RE.match(value) is not None)


def _word_like(value):
    parts = [p for p in re.split(r'[-_.]', value) if p]
    return (all(p.isdigit() or (p.isalpha() and p.islower()) for p in parts)
            and sum(p.isalpha() and len(p) >= 3 for p in parts) >= 2)


def contextual_secret(label, value):
    """True when `value` next to `label` looks like a literal secret (spec: contextual detector)."""
    kind = _label_class(label)
    if kind is None or _excluded(value):
        return False
    if kind == 'password':
        return len(value) >= PASSWORD_MIN_LEN
    if not CONTEXT_MIN_LEN <= len(value) <= CONTEXT_MAX_LEN or UUID_RE.match(value) or _word_like(value):
        return False
    has_digit = any(c.isdigit() for c in value)
    mixed_case = any(c.islower() for c in value) and any(c.isupper() for c in value)
    return (has_digit or mixed_case) and shannon(value) >= ENTROPY_MIN


def contextual_redact(text):
    """Replace the value of each labelled literal secret with CONTEXT_TOKEN, keeping the label.

    A candidate that is not a secret consumes only its label, so a label inside its value
    (`-e AWS_SECRET_ACCESS_KEY=...`) is examined next."""
    out, pos = [], 0
    while (m := CONTEXT_RE.search(text, pos)) is not None:
        if contextual_secret(m.group('flag') or m.group('label'), m.group('value')):
            out.append(text[pos:m.start('value')] + CONTEXT_TOKEN)
            pos = m.end()
        else:
            out.append(text[pos:m.start('value')])
            pos = m.start('value')
    return ''.join(out) + text[pos:]


def contextual_search(text):
    return contextual_redact(text) != text
