import re
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

SENSITIVE_KEYS = re.compile(r"token|secret|key|pass|auth|session|email|phone|tel", re.I)
EMAIL = re.compile(r"[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}")
PHONE = re.compile(r"(?<!\w)(?:\+?\d[\d .()-]{7,}\d)")
TOKEN = re.compile(r"(?i)(bearer\s+)[A-Za-z0-9._~-]+|((?:token|secret|api[_-]?key)\s*[:=]\s*)[^\s&;]+")


def redact_text(value: str, limit: int = 280) -> str:
    value = EMAIL.sub("[EMAIL_MASQUÉ]", value)
    value = PHONE.sub("[TÉLÉPHONE_MASQUÉ]", value)
    value = TOKEN.sub(lambda m: (m.group(1) or m.group(2) or "") + "[MASQUÉ]", value)
    value = re.sub(r"(?i)(cookie|set-cookie)\s*:\s*[^\r\n]+", r"\1: [MASQUÉ]", value)
    return " ".join(value.split())[:limit]


def redact_url(url: str) -> str:
    parts = urlsplit(url)
    query = [(k, "[MASQUÉ]" if SENSITIVE_KEYS.search(k) else v) for k, v in parse_qsl(parts.query, keep_blank_values=True)]
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(query), ""))
