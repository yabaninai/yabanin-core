#!/usr/bin/env python3
"""NEXT-22 alert-hygiene checker (no external tools pinned).

(1) Every metric referenced in alert expressions is DECLARED in the scanned
    Go packages (pkg/metrics + pkg/shadow canonical registry, plus the
    cross-package declaration sites named by inventory gap G-7: pkg/cache,
    pkg/tracing, services/admin/handlers; namespace/subsystem construction
    is matched statically, including inline Subsystem: "x" literals).
(2) Every alert carries a runbook_url annotation and the anchor EXISTS in
    one of the runbook files: docs/runbooks/alerts.md,
    docs/runbooks/budget-reservations-alerts.md,
    docs/observability/otel-export.md (gap G-3 resolution — the R064
    receipt names otel-export.md as the anchor for the export-drop alert).
(3) SLO surface present: latency histogram, error counter, queue gauges.
(4) Notification routing verified (N13-P04-T04, machine half of the
    test-firing card): Alertmanager root/child routes resolve to real
    receivers, every rule severity routes (critical keeps its Telegram
    fan-out), the compose entrypoint renders every __X__ placeholder
    (an unrendered placeholder ships a literal URL / unquoted chat_id and
    kills the delivery path), and the documented test-fire procedure in
    docs/runbooks/alerts.md matches the actual routing config.
(5) Noise bounds verified (N13-P04-T04): every alert has a positive `for:`
    (absent()-style alerts exempt), group_wait/group_interval/
    repeat_interval exist and are ordered (group_wait <= group_interval,
    group_wait < repeat_interval >= 10m floor), and the documented
    critical-inhibits-warning rule equalizes on alertname.
Parse error or missing piece = exit 1/2, never a silent pass.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
RULES = ROOT / "deploy/prometheus/alert-rules.yml"
ALERTMANAGER = ROOT / "deploy/alertmanager/alertmanager.yml"
COMPOSE = ROOT / "deploy/docker-compose.prod.yml"
TESTFIRE_RUNBOOK = ROOT / "docs/runbooks/alerts.md"
RUNBOOKS = [
    ROOT / "docs/runbooks/alerts.md",
    ROOT / "docs/runbooks/budget-reservations-alerts.md",
    ROOT / "docs/observability/otel-export.md",
]
DECL_DIRS = [
    ROOT / "pkg/metrics",
    ROOT / "pkg/shadow",
    ROOT / "pkg/cache",
    ROOT / "pkg/tracing",
    ROOT / "services/admin/handlers",
]


def parse_rules(text):
    """Minimal structural parse: alerts with expr + annotations.

    expr may be a single line or a YAML block scalar (| or >); block
    continuation lines are deeper-indented than the expr key and are
    folded back into one expression so their metrics get checked too
    (previously a multi-line expr parsed as "|" and its metrics were
    never verified).
    """
    alerts, cur = [], None
    for line in text.splitlines():
        m = re.match(r"\s*- alert: (\S+)", line)
        if m:
            cur = {"name": m.group(1), "expr": "", "annotations": {},
                   "expr_indent": -1}
            alerts.append(cur)
            continue
        if cur is None:
            continue
        ws = len(line) - len(line.lstrip())
        stripped = line.strip()
        if cur["expr_indent"] >= 0:
            if stripped and ws > cur["expr_indent"]:
                cur["expr"] += " " + stripped
                continue
            cur["expr_indent"] = -1  # dedent: block scalar ended
        em = re.match(r"(\s*)expr:\s*(.+)$", line)
        if em:
            val = em.group(2).strip()
            if val in ("|", ">", "|-", ">-", "|+", ">+"):
                cur["expr"] = ""
                cur["expr_indent"] = len(em.group(1))
            else:
                cur["expr"] = val
            continue
        am = re.match(r"\s*(\w+):\s*\"?(.+?)\"?,?\s*$", line)
        if am and am.group(1) in ("summary", "description", "runbook_url",
                                  "for", "severity"):
            cur["annotations"][am.group(1)] = am.group(2).strip()
    return alerts


def declared_metric_names():
    """All metric names the code can expose: subsystem prefix + Name fields."""
    names = set()
    src = ""
    for d in DECL_DIRS:
        if not d.is_dir():
            continue
        for go in sorted(d.glob("*.go")):
            if go.name.endswith("_test.go"):
                continue
            src += go.read_text(errors="replace")
    subsystems = {"gateway", "yabanin_shadow"}
    subsystems |= set(re.findall(r'const subsystem = "(\w+)"', src))
    # Inline Subsystem: "x" literals (e.g. pkg/metrics/budget.go declares
    # the budget family with Subsystem: "budget") — G-7 widening.
    subsystems |= {s for s in re.findall(r'Subsystem:\s*"(\w+)"', src) if s}
    for name in re.findall(r'Name:\s*"([a-z_0-9]+)"', src):
        for sub in subsystems:
            names.add(f"{sub}_{name}")
        names.add(name)  # some metrics carry the prefix in the name itself
    # histogram children
    out = set(names)
    for n in names:
        out |= {n + "_bucket", n + "_count", n + "_sum"}
    return out


def expr_metrics(expr):
    # strip label matchers {...} and range/duration selectors [5m] first
    cleaned = re.sub(r"\{[^}]*\}", " ", expr)
    cleaned = re.sub(r"\[[^\]]*\]", " ", cleaned)
    # strip grouping-label lists (by/without/on/...): the identifiers in
    # parens are label names (le, scope_kind, ...), not metrics
    cleaned = re.sub(
        r"\b(?:by|without|on|ignoring|group_left|group_right)\s*\([^)]*\)",
        " ", cleaned)
    ids = re.findall(r"[a-zA-Z_][a-zA-Z_0-9]*", cleaned)
    # PromQL function vocabulary — a bare identifier that names a Prometheus
    # function is never a metric reference. Keep in sync with functions the
    # rules actually use; the standard range-function family is included so
    # range selectors (`*_over_time`, changes/delta/resets) do not false-flag.
    skip = {"sum", "rate", "histogram_quantile", "by", "without", "avg",
            "count", "max", "min", "and", "or", "unless", "ignoring",
            # union of both keyword lists (keywords can never be metric
            # names; metrics in this repo are word-prefixed)
            "abs", "absent", "absent_over_time", "atan2", "avg_over_time", "bool", "bottomk", "ceil", "changes", "clamp_max", "clamp_min", "count_over_time", "day_of_month", "day_of_week", "days_in_month", "delta", "deriv", "exp", "floor", "group_left", "group_right", "holt_winters", "hour", "idelta", "ignoring", "increase", "inf", "irate", "label_join", "label_replace", "last_over_time", "ln", "log10", "log2", "max_over_time", "min_over_time", "minute", "month", "nan", "offset", "on", "pi", "predict_linear", "present_over_time", "quantile", "quantile_over_time", "resets", "round", "scalar", "sgn", "sort", "sort_desc", "sqrt", "stddev", "stddev_over_time", "stdvar", "stdvar_over_time", "sum_over_time", "time", "timestamp", "topk", "vector",
            "year"}
    return {i for i in ids if i not in skip and not i.replace(".", "").isdigit() and "." not in i}


def duration_seconds(val):
    """Parse a Prometheus/Alertmanager duration (30s / 10m / 1h) to seconds.

    Returns None for anything that is not a plain unit duration — callers
    treat None as 'unparseable' and report it.
    """
    m = re.match(r"^(\d+(?:\.\d+)?)(s|m|h)$", (val or "").strip())
    if not m:
        return None
    return float(m.group(1)) * {"s": 1, "m": 60, "h": 3600}[m.group(2)]


def parse_alertmanager(text):
    """Minimal structural parse of the Alertmanager routing config.

    Same no-external-YAML policy as parse_rules: regex + indentation only.
    Returns root receiver, child routes (match key/value -> receiver),
    receiver names, timing values, inhibition facts and the __X__
    placeholder set.
    """
    info = {
        "root_receiver": None,
        "children": [],  # (match_key, match_value, receiver)
        "receivers": [],
        "timings": {},  # group_wait / group_interval / repeat_interval / resolve_timeout
        "inhibit_critical_warning": False,
        "inhibit_equal_alertname": False,
        "placeholders": set(),
    }
    info["receivers"] = re.findall(r"^\s*- name:\s*\"?([\w-]+)", text, re.M)
    root = re.search(r"^  receiver:\s*\"?([\w-]+)", text, re.M)
    if root:
        info["root_receiver"] = root.group(1)
    for m in re.finditer(
            r"- match:\s*\n\s*(\w+):\s*([\w-]+)\s*\n\s*receiver:\s*\"?([\w-]+)",
            text):
        info["children"].append((m.group(1), m.group(2), m.group(3)))
    for key in ("group_wait", "group_interval", "repeat_interval",
                "resolve_timeout"):
        tm = re.search(rf"^  {key}:\s*(\S+)\s*$", text, re.M)
        if tm:
            info["timings"][key] = tm.group(1)
    if (re.search(r"source_matchers:\s*\n\s*-\s*'severity=\"critical\"'",
                  text)
            and re.search(r"target_matchers:\s*\n\s*-\s*'severity=\"warning\"'",
                          text)):
        info["inhibit_critical_warning"] = True
    em = re.search(r"^\s*equal:\s*\[(.+)\]\s*$", text, re.M)
    if em and "alertname" in em.group(1):
        info["inhibit_equal_alertname"] = True
    info["placeholders"] = set(re.findall(r"__([A-Z0-9_]+)__", text))
    return info


def compose_alertmanager_block(text):
    """The alertmanager service block of docker-compose.prod.yml (env
    defaults + entrypoint sed rendering). Scoped so ALERT_* env keys of
    other services can never satisfy the rendering check."""
    start = re.search(r"^  alertmanager:\s*$", text, re.M)
    if not start:
        return None
    rest = text[start.start() + 1:]
    nxt = re.search(r"^  [\w-]+:\s*$", rest, re.M)
    return rest[:nxt.start()] if nxt else rest


def testfire_section(text):
    """The `## Test-firing` runbook section body (up to the next ##)."""
    start = re.search(r"^## Test-firing.*$", text, re.M)
    if not start:
        return None
    rest = text[start.end():]
    nxt = re.search(r"^## ", rest, re.M)
    return rest[:nxt.start()] if nxt else rest


def notify_noise_problems(alerts, am, compose_text, testfire_md):
    """Routing + noise checks (N13-P04-T04). Returns problem strings."""
    problems = []

    # -- routing integrity: every route resolves to a real receiver
    receivers = set(am["receivers"])
    if am["root_receiver"] is None:
        problems.append(
            "alertmanager: root route receiver not found "
            "(notifications have no default destination)")
    elif am["root_receiver"] not in receivers:
        problems.append(
            f"alertmanager: root route receiver {am['root_receiver']!r} "
            "has no matching receiver block")
    for key, val, recv in am["children"]:
        if recv not in receivers:
            problems.append(
                f"alertmanager: child route {key}={val} routes to unknown "
                f"receiver {recv!r}")

    # -- every alert carries a severity (routing cannot classify otherwise)
    for a in alerts:
        if not a["annotations"].get("severity"):
            problems.append(
                f"{a['name']}: missing severity label (notification "
                "routing cannot classify it)")

    # -- critical severity keeps its dedicated child route (Telegram fan-out)
    child_severities = {val for key, val, _ in am["children"] if key == "severity"}
    used = {a["annotations"].get("severity") for a in alerts} - {None}
    if "critical" in used and "critical" not in child_severities:
        problems.append(
            "notification: rules use severity=critical but no child route "
            "matches severity=critical (critical fan-out silently degrades "
            "to the default receiver)")

    # -- rendering consistency: placeholders <-> compose sed <-> env defaults
    if not am["placeholders"]:
        problems.append(
            "rendering: no __X__ placeholders in alertmanager.yml (the "
            "compose entrypoint renders nothing — env vars are ignored)")
    else:
        block = compose_alertmanager_block(compose_text or "")
        seds = set(re.findall(r"s\|__([A-Z0-9_]+)__\|", block)) if block else set()
        envs = set(re.findall(r"^\s*([A-Z][A-Z0-9_]*):\s*", block, re.M)) if block else set()
        if block is None:
            problems.append(
                "rendering: alertmanager service block not found in "
                "deploy/docker-compose.prod.yml")
        for ph in sorted(am["placeholders"]):
            if block is not None and ph not in seds:
                problems.append(
                    f"rendering: placeholder __{ph}__ has no sed in the "
                    "compose alertmanager entrypoint (ships as a literal; "
                    "unquoted chat_id would fail config load)")
            if block is not None and ph not in envs:
                problems.append(
                    f"rendering: no env default for {ph} in the compose "
                    "alertmanager environment block")
        for ph in sorted(seds - am["placeholders"]):
            problems.append(
                f"rendering: compose sed renders __{ph}__ which no longer "
                "exists in alertmanager.yml (drift)")

    # -- noise bound: every alert persists (for:) before firing
    for a in alerts:
        fv = a["annotations"].get("for")
        if fv is None:
            if "absent(" not in a["expr"]:
                problems.append(
                    f"{a['name']}: missing for: duration (fires on a "
                    "single scrape blip — notification noise)")
        else:
            secs = duration_seconds(fv)
            if secs is None or secs <= 0:
                problems.append(f"{a['name']}: unparseable for: value {fv!r}")

    # -- noise bound: routing timers exist and are ordered sanely
    for key in ("group_wait", "group_interval", "repeat_interval"):
        if key not in am["timings"]:
            problems.append(
                f"alertmanager: route {key} missing (notification "
                "grouping/repeat noise unbounded)")
    gw = duration_seconds(am["timings"].get("group_wait"))
    gi = duration_seconds(am["timings"].get("group_interval"))
    rp = duration_seconds(am["timings"].get("repeat_interval"))
    if rp is not None and rp < 600:
        problems.append(
            f"alertmanager: repeat_interval "
            f"{am['timings'].get('repeat_interval')} is below the 10m "
            "re-notification floor (storm)")
    if gw is not None and rp is not None and gw >= rp:
        problems.append(
            "alertmanager: group_wait >= repeat_interval (notifications "
            "would repeat before the first delivery completes)")
    if gw is not None and gi is not None and gi < gw:
        problems.append(
            "alertmanager: group_interval < group_wait (group churn)")

    # -- inhibition: critical suppresses its warning twin for same alertname
    if not am["inhibit_critical_warning"]:
        problems.append(
            "alertmanager: no severity=critical source / severity=warning "
            "target inhibit rule (critical+warning twins double-notify)")
    if not am["inhibit_equal_alertname"]:
        problems.append(
            "alertmanager: inhibit rule does not equalize on alertname "
            "(inhibition cannot suppress the warning twin)")

    # -- documented test-fire procedure matches the real routing config
    if testfire_md is None:
        problems.append(
            "runbook: test-firing procedure section missing in "
            "docs/runbooks/alerts.md (operators cannot verify delivery)")
    else:
        if "/api/v2/alerts" not in testfire_md:
            problems.append(
                "runbook: test-firing procedure does not POST to the "
                "Alertmanager API (/api/v2/alerts)")
        if '"severity": "critical"' not in testfire_md:
            problems.append(
                "runbook: test-firing procedure has no critical-severity "
                "test (the Telegram fan-out path stays unverified)")

    return problems


def _notify_summary(am):
    """One-line routing/noise digest for the OK output."""
    child = ",".join(f"{k}={v}->{r}" for k, v, r in am["children"]) or "none"
    t = am["timings"]
    timings = " ".join(f"{k}={t[k]}" for k in
                       ("group_wait", "group_interval", "repeat_interval")
                       if k in t)
    return (f"routing: root={am['root_receiver']}; children: {child}; "
            f"receivers: {len(am['receivers'])}; "
            f"inhibit critical->warning(alertname): "
            f"{'on' if am['inhibit_critical_warning'] and am['inhibit_equal_alertname'] else 'OFF'}; "
            f"{timings or 'timings: none'}")


def main() -> int:
    try:
        text = RULES.read_text()
        alerts = parse_rules(text)
        runbook = "\n".join(
            p.read_text(errors="replace") for p in RUNBOOKS if p.exists())
        am_text = ALERTMANAGER.read_text()
        compose_text = COMPOSE.read_text()
        testfire_md = testfire_section(TESTFIRE_RUNBOOK.read_text())
    except OSError as exc:
        print(f"scanner error: {exc}", file=sys.stderr)
        return 2
    if not alerts:
        print("scanner error: no alerts parsed", file=sys.stderr)
        return 2
    am = parse_alertmanager(am_text)

    declared = declared_metric_names()
    problems = []
    for a in alerts:
        for metric in sorted(expr_metrics(a["expr"])):
            if metric == "up" or metric.startswith("node_"):
                continue  # synthetic scrape-health metric from Prometheus itself
            if metric not in declared:
                problems.append(
                    f"{a['name']}: metric {metric!r} not declared in scanned packages")
        rb = a["annotations"].get("runbook_url", "")
        if not rb:
            problems.append(f"{a['name']}: missing runbook_url annotation")
        else:
            anchor = rb.split("#", 1)[-1]
            if f"## {anchor}" not in runbook:
                problems.append(
                    f"{a['name']}: runbook anchor #{anchor} missing in runbook set "
                    "(alerts.md / budget-reservations-alerts.md / otel-export.md)")

    # SLO surface
    for slo in ("gateway_http_request_duration_seconds", "gateway_http_requests_total", "gateway_loggerd_events_in_flight"):
        if slo not in declared:
            problems.append(f"SLO metric missing: {slo}")

    # Notification routing + noise bounds (N13-P04-T04)
    problems.extend(notify_noise_problems(alerts, am, compose_text, testfire_md))

    print(f"alert check: {len(alerts)} alerts, {len(problems)} problem(s)")
    for p in problems:
        print(f"  ✗ {p}")
    if not problems:
        print(f"  ✓ {_notify_summary(am)}")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
