"""Minimal YAML subset parser (fallback when PyYAML is unavailable).

Understands exactly what SIBAT's own files use:
  - nested mappings via 2-space indentation
  - sequences of scalars ("- item")
  - scalar values, '#' comments, blank lines
If you need real YAML, install PyYAML — SIBAT prefers it when present.
"""

from __future__ import annotations

def _parse_scalar(raw: str):
    s = raw.strip()
    if s == "[]":
        return []
    if s == "{}":
        return {}
    if len(s) >= 2 and s[0] == s[-1] and s[0] in "\"'":
        return s[1:-1]
    if s in ("true", "True"):
        return True
    if s in ("false", "False"):
        return False
    if s == "null" or s == "~":
        return None
    try:
        return int(s)
    except ValueError:
        return s


def _strip_comment(line: str) -> str:
    out, quote = [], None
    for ch in line:
        if quote:
            out.append(ch)
            if ch == quote:
                quote = None
            continue
        if ch in "\"'":
            quote = ch
            out.append(ch)
            continue
        if ch == "#":
            break
        out.append(ch)
    return "".join(out).rstrip()


def loads(text: str):
    """Parse the SIBAT YAML subset into dict/list structures."""
    lines: list[tuple[int, str]] = []
    for raw in text.splitlines():
        line = _strip_comment(raw)
        if not line.strip():
            continue
        indent = len(line) - len(line.lstrip(" "))
        lines.append((indent, line.strip()))

    if not lines:
        return {}

    def parse_block(idx: int, indent: int):
        """Parse items at >= indent starting at idx. Returns (value, next_idx)."""
        # sequence?
        if lines[idx][1].startswith("- "):
            items = []
            i = idx
            while i < len(lines) and lines[i][0] >= indent and lines[i][1].startswith("- "):
                if lines[i][0] != indent:
                    break
                items.append(_parse_scalar(lines[i][1][2:]))
                i += 1
            return items, i
        # mapping?
        mapping = {}
        i = idx
        while i < len(lines) and lines[i][0] >= indent:
            ind, content = lines[i]
            if ind != indent or content.startswith("- "):
                break
            if ":" not in content:
                raise ValueError(f"bad line: {content!r}")
            key, _, val = content.partition(":")
            key = key.strip()
            val = val.strip()
            if val:
                mapping[key] = _parse_scalar(val)
                i += 1
            else:
                # value is nested block (or empty)
                if i + 1 < len(lines) and lines[i + 1][0] > indent:
                    value, i = parse_block(i + 1, lines[i + 1][0])
                    mapping[key] = value
                elif i + 1 < len(lines) and lines[i + 1][0] == indent and lines[i + 1][1].startswith("- "):
                    value, i = parse_block(i + 1, indent)
                    mapping[key] = value
                else:
                    mapping[key] = None
                    i += 1
        return mapping, i

    value, next_idx = parse_block(0, lines[0][0])
    if next_idx < len(lines):
        raise ValueError(f"unparsed content at line: {lines[next_idx][1]!r}")
    return value


def safe_load(text: str):
    """PyYAML-compatible entry point."""
    return loads(text)
