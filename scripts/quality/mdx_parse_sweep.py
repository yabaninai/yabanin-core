#!/usr/bin/env python3
"""MDX parse sweep over docs/** — lane-time signal for MDX compile failures.

Origin: the docs quality gate checked links + language only and never
parsed MDX, so a docs/*.md merge carrying a raw `<` table hazard broke the
public site build post-merge with no lane-time signal; this sweep was
added so `make docs-mdx` catches the same failure classes before merge.

Honest scope:

* Dependency-free structural parse of docs/**/*.md and docs/**/*.mdx that
  reproduces the MDX/JSX *parse-failure* classes the Docusaurus build hits
  (micromark-extension-mdx-jsx): raw `<` that cannot start a tag name (a
  registered site-breaking class, including the GFM table cell-splitting
  mechanism that exposed it), unclosed JSX tags (the `<verdict>` class),
  unclosed `{` expression containers, unclosed HTML comments. These are
  FATAL: the public site build fails to compile on them.
* It is NOT a full MDX compiler. Parse-valid hazards observed in this
  corpus — balanced `{...}` expression containers that JS-evaluate at
  build/render (`{pkg/guardhooks/...}` was "syntactically valid JS") — are
  reported as MDX005 WARN, widenable per-line through the content-keyed
  allowlist (docs-lang convention), never silently dropped.
* docs/strategy/** is excluded from the public site (docusaurus
  `exclude: ['strategy/**']`), so its findings are reported with an explicit
  site-excluded label and stay non-fatal. Nothing is skipped silently: every
  discovered file gets a ledger line, and unreadable files fail the gate
  (docs-lang precedent).

Exit 1 iff at least one FATAL finding or an unreadable file. Deterministic:
sorted files, line-major findings, no timestamps, no network, stdlib only.
"""
import argparse
import hashlib
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
ALLOWLIST = ROOT / "scripts" / "quality" / "mdx_sweep_allowlist.txt"

SCAN_DIR = ROOT / "docs"
SCAN_SUFFIXES = (".md", ".mdx")
# Public-site compile domain: docusaurus.config.ts docs preset exclude list.
SITE_EXCLUDED_PARTS = ("docs/strategy/",)

# Fenced code block opening: up to 3 spaces indent, 3+ backticks or tildes.
FENCE_OPEN = re.compile(r"^ {0,3}(`{3,}|~{3,})")
# GFM table delimiter row: | --- | :---: | ...
TABLE_DELIM = re.compile(r"^\s{0,3}\|?\s*:?-{1,}:?\s*(\|\s*:?-{1,}:?\s*)+\|?\s*$")
# Docusaurus heading anchors (`## Id {#Id}`) — stripped before MDX sees them
# (site-green precedent: docs/runbooks/alerts.md, 12 anchors).
HEADING_ANCHOR = re.compile(r"^(#{1,6}\s+.*?)\s*\{#[A-Za-z0-9_-]+\}\s*$")
# JSX tag names start with a letter (micromark mdx-jsx name-start rule).
TAG_NAME = re.compile(r"[A-Za-z][A-Za-z0-9._:-]*")


class Finding:
    __slots__ = ("rel", "line", "col", "code", "message", "fatal")

    def __init__(self, rel, line, col, code, message, fatal):
        self.rel = rel
        self.line = line
        self.col = col
        self.code = code
        self.message = message
        self.fatal = fatal


def scan_targets(scan_dir=None):
    scan_dir = scan_dir if scan_dir is not None else SCAN_DIR
    if not scan_dir.is_dir():
        return []
    return sorted(p for p in scan_dir.rglob("*")
                  if p.is_file() and p.suffix in SCAN_SUFFIXES)


def site_excluded(rel: str) -> bool:
    return rel.startswith(SITE_EXCLUDED_PARTS)


def load_allowlist():
    entries = set()
    if not ALLOWLIST.is_file():
        return entries
    for raw in ALLOWLIST.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if line and not line.startswith("#"):
            entries.add(line)
    return entries


def line_key(rel: str, content: str) -> str:
    digest = hashlib.sha256(content.encode("utf-8")).hexdigest()[:16]
    return f"{rel}:{digest}"


def _code_span_boundaries(text):
    """Sorted (start, end) ranges covered by inline code spans in one buffer.
    CommonMark: a run of N backticks closes at the next run of exactly N
    backticks; an unmatched run is a literal backtick (no span) and scanning
    resumes after the run."""
    spans = []
    i, n = 0, len(text)
    while i < n:
        if text[i] != "`":
            i += 1
            continue
        j = i
        while j < n and text[j] == "`":
            j += 1
        run = j - i
        k = j
        close = None
        while k < n:
            if text[k] == "`":
                m = k
                while m < n and text[m] == "`":
                    m += 1
                if m - k == run:
                    close = m
                    break
                k = m
            else:
                k += 1
        if close is None:
            i = j
        else:
            # `close` is already the exclusive end (one past the closing
            # backtick run) — the span covers both delimiter runs exactly;
            # +1 here would swallow the character right after the closing
            # backtick (the historical table-cell hazard position).
            spans.append((i, close))
            i = close
    return spans


def _in_spans(pos, spans):
    for s, e in spans:
        if s <= pos < e:
            return True
        if s > pos:
            break
    return False


def _escaped(text, pos):
    """True if text[pos] is preceded by an odd number of backslashes."""
    run = 0
    k = pos - 1
    while k >= 0 and text[k] == "\\":
        run += 1
        k -= 1
    return run % 2 == 1


def _split_table_row(line):
    """Split a GFM table row into cells on unescaped pipes. Backslash-escaped
    pipes (\\|) do not split — the exact mechanism of the original
    site-breaking case."""
    cells, buf = [], []
    i, n = 0, len(line)
    while i < n:
        ch = line[i]
        if ch == "\\" and i + 1 < n:
            buf.append(line[i:i + 2])
            i += 2
            continue
        if ch == "|":
            cells.append("".join(buf))
            buf = []
            i += 1
            continue
        buf.append(ch)
        i += 1
    cells.append("".join(buf))
    if cells and cells[0].strip() == "":
        cells = cells[1:]
    if cells and cells[-1].strip() == "":
        cells = cells[:-1]
    return cells


class _Scanner:
    """One file. Line-level state (fences, comments, tables, paragraphs) plus
    a linear buffer pass for inline constructs; JSX tag balance and brace
    expression depth live at file level (MDX flow constructs may span
    paragraphs)."""

    def __init__(self, rel, fatal_domain):
        self.rel = rel
        self.fatal_domain = fatal_domain
        self.findings = []   # fatal-class findings (MDX000-004)
        self.warnings = []   # (line, col, snippet, why) MDX005-class
        self.fence = None        # (char, length) while inside a fenced block
        self.in_comment = False  # inside <!-- ... -->
        self.comment_open = None  # (line, col) of the unterminated '<!--'
        self.para = []           # [(buffer-line-text, source-line-no)]
        self.tag_stack = []      # [(name, line, col)]
        self.brace_depth = 0
        self.brace_open = None   # (buf-pos, line, col) of outermost open '{'
        self.in_table = False

    # -- helpers -----------------------------------------------------------
    def _fatal(self, line, col, code, message):
        self.findings.append(Finding(self.rel, line, col, code, message,
                                     self.fatal_domain))

    def _warn(self, line, col, snippet, why):
        self.warnings.append((line, col, snippet, why))

    # -- the linear buffer pass ---------------------------------------------
    def _scan_buffer(self, buf, offsets, at_pipe_boundary=False):
        """Scan a paragraph buffer (or single table cell) for MDX hazards.
        `offsets` maps buffer positions back to (line, col) source coords:
        a list of (buf-start, line-no). Code spans are stripped first; every
        hazard position is reported at its true source line/column.
        `at_pipe_boundary`: True when this buffer is a non-final GFM table
        cell, so an end-of-buffer '<' is immediately followed by the pipe
        separator in the source stream — the registered site-breaking
        class."""
        spans = _code_span_boundaries(buf)
        line_starts = [(off, ln) for off, ln in offsets]

        def locate(pos):
            src_line = 1
            col = 1
            for off, ln in line_starts:
                if pos >= off:
                    src_line = ln
                    col = pos - off + 1
            return src_line, col

        def src_snippet(pos, limit=14):
            src_line, col = locate(pos)
            for off, ln in reversed(line_starts):
                if pos >= off:
                    return src_line, col, buf[pos:pos + limit]
            return src_line, col, buf[pos:pos + limit]

        i, n = 0, len(buf)
        while i < n:
            if _in_spans(i, spans):
                i += 1
                continue
            ch = buf[i]
            if ch == "\\" and i + 1 < n:
                i += 2
                continue
            if ch == "<":
                nxt = buf[i + 1] if i + 1 < n else ""
                if nxt == "" or nxt == "\n":
                    if at_pipe_boundary:
                        # '<' ends this cell; the next source byte is the
                        # pipe separator — raw '<|' cannot start a JSX tag
                        # (registered site-breaking failure class).
                        ln, col = locate(i)
                        self._fatal(ln, col, "MDX001",
                                    "raw '<' at a table cell boundary (the "
                                    "pipe separator truncates the cell, so "
                                    "the code span no longer protects it) — "
                                    "escape the inner pipes as \\| or "
                                    "restructure the cell")
                        return
                    # End of line after '<': MDX allows a tag name to
                    # continue on the next line, so this is not determinate
                    # from one line; treated as literal text (corpus has no
                    # end-of-line '<' instances).
                    i += 1
                    continue
                if nxt.isspace():
                    # Whitespace after '<' is literal text (corpus-proven:
                    # '< 60 min', '< 25%', '< 14d' all compile green).
                    i += 1
                    continue
                if buf.startswith("<!--", i):
                    end = buf.find("-->", i + 4)
                    if end == -1:
                        ln, col = locate(i)
                        self._fatal(ln, col, "MDX004",
                                    "unclosed HTML comment '<!--' without "
                                    "'-->' — micromark 'unexpected eof' class")
                        return
                    i = end + 3
                    continue
                if nxt == ">":
                    self.tag_stack.append(("#fragment", *locate(i)))
                    i += 2
                    continue
                if nxt == "/":
                    nm = TAG_NAME.match(buf[i + 2:])
                    if nm:
                        self._close_tag(nm.group(0), locate(i))
                        i += 2 + len(nm.group(0))
                    else:
                        i += 2
                    continue
                nm = TAG_NAME.match(buf[i + 1:])
                if nm:
                    end = self._tag_end(buf, spans, i)
                    if end is None:
                        ln, col = locate(i)
                        self._fatal(ln, col, "MDX002",
                                    f"unclosed JSX tag '<{nm.group(0)}>' (no "
                                    f"'>' before end of input) — micromark "
                                    f"'unexpected eof' class")
                        return
                    self_closed = (buf[end - 1] == "/"
                                   and not _escaped(buf, end - 1)
                                   and not _in_spans(end - 1, spans))
                    if not self_closed:
                        self.tag_stack.append((nm.group(0), *locate(i)))
                    i = end + 1
                    continue
                ln, col = locate(i)
                _, _, tail = src_snippet(i)
                self._fatal(ln, col, "MDX001",
                            f"raw '<' cannot start a JSX tag (next: "
                            f"{tail[:12].strip()[:12]!r}); micromark mdx-jsx "
                            f"class 'expected a character that can start a "
                            f"name' — escape as \\<, code-span it, or fix "
                            f"the table cell (escape inner pipes as \\|)")
                i += 1
                continue
            if ch == "{":
                if self.brace_depth == 0:
                    self.brace_open = (i, *locate(i))
                self.brace_depth += 1
                i += 1
                continue
            if ch == "}":
                # A bare '}' outside any '{' is character data in MDX
                # (parse-valid; site-green proof: escaped-brace glob
                # lines compile and render) — not a hazard.
                if self.brace_depth > 0:
                    self.brace_depth -= 1
                    if self.brace_depth == 0 and self.brace_open:
                        open_pos, ln, col = self.brace_open
                        snippet = buf[open_pos:i + 1].strip()
                        self._warn(ln, col, snippet[:60],
                                   "brace expression container — MDX "
                                   "evaluates it as JavaScript at build/"
                                   "render (SSR hazard class, parse-valid); "
                                   "code-span literal "
                                   "text or allowlist intentional expressions")
                        self.brace_open = None
                i += 1
                continue
            i += 1

    def _tag_end(self, buf, spans, start):
        """Position of the '>' closing the tag opened at `start`, honoring
        quoted attribute values; None if the tag never terminates."""
        quote = None
        k = start + 1
        n = len(buf)
        while k < n:
            c = buf[k]
            if quote:
                if c == quote:
                    quote = None
            elif c in ('"', "'"):
                quote = c
            elif c == ">" and not _in_spans(k, spans) and not _escaped(buf, k):
                return k
            k += 1
        return None

    def _close_tag(self, name, loc):
        for idx in range(len(self.tag_stack) - 1, -1, -1):
            if self.tag_stack[idx][0] == name:
                del self.tag_stack[idx:]
                return
        self._fatal(loc[0], loc[1], "MDX002",
                    f"closing tag '</{name}>' with no matching open tag")

    # -- line loop -----------------------------------------------------------
    def feed(self, line_no, line):
        m = FENCE_OPEN.match(line)
        if self.fence is None:
            if m:
                self.fence = (m.group(1)[0], len(m.group(1)))
                self._flush_para()
                return
        else:
            if (m and m.group(1)[0] == self.fence[0]
                    and len(m.group(1)) >= self.fence[1]
                    and line.strip() == m.group(1)):
                self.fence = None
            return
        if self.in_comment:
            if "-->" in line:
                self.in_comment = False
            return
        stripped = line.strip()
        if not stripped:
            self._flush_para()
            self.in_table = False
            return
        if "<!--" in line and "-->" not in line:
            self._flush_para()
            self.in_comment = True
            self.comment_open = (line_no, line.index("<!--") + 1)
            return
        hm = HEADING_ANCHOR.match(line)
        if hm:
            line = hm.group(1)
        is_delim = bool(TABLE_DELIM.match(line)) and "|" in line
        row_like = "|" in line
        if is_delim and self.para and not self.in_table:
            header = self.para[:]
            self.para = []
            for t, ln in header:
                self._table_row(t, ln)
            self.in_table = True
            return
        if self.in_table:
            if row_like and not is_delim:
                self._table_row(line, line_no)
            else:
                self.in_table = False
                self.para.append((line, line_no))
            return
        self.para.append((line, line_no))

    def _flush_para(self):
        if not self.para:
            return
        buf = "\n".join(t for t, _ in self.para)
        offsets = []
        acc = 0
        for t, ln in self.para:
            offsets.append((acc, ln))
            acc += len(t) + 1
        self._scan_buffer(buf, offsets)
        self.para = []

    def _table_row(self, line, line_no):
        """Cell-split first (the registered site-breaking mechanism), then scan
        each cell: an unescaped pipe truncates the cell, so `` `<|x|> `` in a
        table code span exposes raw `<` exactly as micromark does."""
        cells = _split_table_row(line)
        for idx, cell in enumerate(cells):
            self._scan_buffer(cell, [(0, line_no)],
                              at_pipe_boundary=idx < len(cells) - 1)

    def finish(self):
        self._flush_para()
        if self.in_comment and self.comment_open:
            ln, col = self.comment_open
            self._fatal(ln, col, "MDX004",
                        "unclosed HTML comment '<!--' with no '-->' before "
                        "end of file — micromark 'unexpected eof' class")
        if self.brace_depth > 0 and self.brace_open:
            _, ln, col = self.brace_open
            self._fatal(ln, col, "MDX003",
                        "unclosed '{' expression container (no matching '}' "
                        "before end of file) — micromark 'unexpected eof in "
                        "expression' class")
        for name, ln, col in self.tag_stack:
            label = "fragment <>" if name == "#fragment" else f"'<{name}>'"
            self._fatal(ln, col, "MDX002",
                        f"unclosed JSX tag {label} at end of file — micromark "
                        f"'unexpected eof' class")
        return self.findings, self.warnings


def scan_file(path, rel):
    """Scan one file. Returns (fatal_or_nonfatal findings, warnings, domain
    note). Unreadable/undecodable files are an honest fatal finding
    (docs-lang precedent), never a skip."""
    fatal_domain = not site_excluded(rel)
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        return ([Finding(rel, 0, 0, "MDX000", f"unreadable: {exc}", True)],
                [], None)
    sc = _Scanner(rel, fatal_domain)
    for i, line in enumerate(text.splitlines(), start=1):
        sc.feed(i, line)
    findings, warnings = sc.finish()
    note = "site-excluded (strategy/**)" if site_excluded(rel) else None
    return findings, warnings, note


def main() -> int:
    ap = argparse.ArgumentParser(
        description="MDX parse sweep over docs/** (gate: make docs-mdx)")
    ap.add_argument("--root", type=Path, default=None,
                    help="scan root override (default: <repo>/docs); "
                    "allowlist stays the repo one; used by tests and "
                    "mutation demos")
    args = ap.parse_args()
    scan_dir = args.root.resolve() if args.root else SCAN_DIR
    allow = load_allowlist()
    n_pass = n_warn_files = 0
    fatal = []
    for path in scan_targets(scan_dir):
        # Repo run: scan_dir = ROOT/docs -> rel "docs/...". Test/mutation
        # roots: prefixed with the root dir's own name so site_excluded and
        # allowlist keys keep the docs/ shape.
        rel = f"{scan_dir.name}/{path.relative_to(scan_dir).as_posix()}"
        findings, warnings, note = scan_file(path, rel)
        tag = f"  [{note}]" if note else ""
        fatal_f = [f for f in findings if f.fatal]
        soft_f = [f for f in findings if not f.fatal]
        if fatal_f:
            fatal.extend(fatal_f)
            print(f"FAIL {rel}{tag}")
            for f in findings:
                loc = f"{f.rel}:{f.line}:{f.col}" if f.line else f.rel
                print(f"  {loc} {f.code}: {f.message}")
            continue
        if soft_f or warnings:
            n_warn_files += 1
            print(f"WARN {rel}{tag}")
            for f in soft_f:
                print(f"  {f.rel}:{f.line}:{f.col} {f.code}: {f.message}")
            src_cache = None
            for (line, col, snippet, why) in warnings:
                if src_cache is None:
                    src_cache = path.read_text(encoding="utf-8").splitlines()
                src = src_cache[line - 1] if 0 <= line - 1 < len(src_cache) else ""
                key = line_key(rel, src)
                if key in allow:
                    print(f"  {rel}:{line}:{col} MDX005 (allowlisted {key}): "
                          f"{why} — {snippet!r}")
                else:
                    print(f"  {rel}:{line}:{col} MDX005: {why} — {snippet!r}\n"
                          f"    allowlist entry (scripts/quality/"
                          f"mdx_sweep_allowlist.txt): {key}")
            continue
        n_pass += 1
        print(f"PASS {rel}{tag}")
    print(f"mdx-sweep: docs/**/*.md+mdx: {n_pass} clean, {n_warn_files} with "
          f"warnings, {len(fatal)} fatal; strategy/** parsed and labeled "
          f"site-excluded (no silent skips)")
    if fatal:
        print(f"mdx-sweep: FAIL ({len(fatal)} fatal finding(s)) — the public "
              f"site build would fail to compile MDX in the named files")
        return 1
    print("mdx-sweep: OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
