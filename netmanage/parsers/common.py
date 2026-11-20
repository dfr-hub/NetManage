"""Shared helpers for indentation-based configs (Cisco, Huawei)."""
from __future__ import annotations


def clean_lines(text: str, comment_prefixes: tuple[str, ...] = ("!", "#")) -> list[str]:
    """Drop blank lines, comments and pager noise. Indentation is kept."""
    out = []
    for raw in text.replace("\r", "").split("\n"):
        line = raw.rstrip()
        stripped = line.strip()
        if not stripped:
            continue
        if stripped.startswith(comment_prefixes) or stripped in ("return", "quit"):
            continue
        if "--More--" in stripped or stripped.startswith("---- More"):
            continue
        out.append(line)
    return out


def vrp_blocks(text: str) -> list[tuple[str, list[str]]]:
    """Blocks for Huawei/H3C output.

    Global commands are often printed with one leading space (' sysname R1'), the same
    indent as block children. A '#' in column 0 ends the current block, so an indented
    line right after it is a new top-level command, not a child.
    """
    result: list[tuple[str, list[str]]] = []
    head_indent = 0
    fresh = True
    for raw in text.replace("\r", "").split("\n"):
        line = raw.rstrip()
        stripped = line.strip()
        if not stripped or "--More--" in stripped or stripped.startswith("---- More"):
            continue
        if line.startswith(("#", "!")):
            fresh = True
            continue
        if stripped.startswith(("#", "!")) or stripped in ("return", "quit"):
            continue
        indent = len(line) - len(line.lstrip())
        if indent == 0 or fresh or not result or indent <= head_indent:
            result.append((stripped, []))
            head_indent = indent
        else:
            result[-1][1].append(stripped)
        fresh = False
    return result


def blocks(lines: list[str]) -> list[tuple[str, list[str]]]:
    """Group lines into (top-level line, [indented child lines])."""
    result: list[tuple[str, list[str]]] = []
    for line in lines:
        if line[0] in (" ", "\t") and result:
            result[-1][1].append(line.strip())
        else:
            result.append((line.strip(), []))
    return result
