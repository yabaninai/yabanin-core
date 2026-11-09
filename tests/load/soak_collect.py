#!/usr/bin/env python3
"""N12-P04-T02 soak metrics collector — prometheus-API client for the soak stand.

Reads the stack's existing exposition (jobs gateway/admin/loggerd per
deploy/prometheus/prometheus.yml, which this tool never edits) through the
Prometheus HTTP API and produces the packet's observable set: raw admission /
limiter / upstream counters, consumer in-flight, settlement backlog, and
process saturation (RSS / CPU / goroutines). Stdlib only.

Subcommands
  snapshot  instant scrape of all tracked series -> JSON
  baseline  short backlog sampling window -> baseline range JSON
  watch     poll backlog until it returns into the baseline range (or timeout);
            packet acceptance: «backlog возвращается к baseline ≤5 минут ... либо
            фиксируется провал цели» — the failure case is recorded, not hidden
  range     saturation timeline over [start,end] with min/avg/max/first/last

Exit codes: 0 = ok / recovered, 1 = timeout / not recovered, 2 = usage/HTTP error.
"""

import argparse
import json
import sys
import time
import urllib.parse
import urllib.request

# (report_key, promql, comment). Counters are summed across instances; gauges
# keep per-job resolution where the consumer side (loggerd) matters.
# Names below are the RENDERED exposition names — the gateway registry
# registers with Subsystem "gateway", so e.g. Go's reservations_denied_total
# is scraped as gateway_reservations_denied_total (verified against live
# /metrics of every job). Deny-family counters are lazy CounterVecs: absent
# until the first event, so an absent series here means "no such event", NOT
# zero — the report treats those deltas as inconclusive rather than 0.
SERIES = [
    ("gateway_rss_bytes", 'process_resident_memory_bytes{job="gateway"}', "gateway saturation"),
    ("gateway_cpu_seconds", 'process_cpu_seconds_total{job="gateway"}', "gateway saturation"),
    ("gateway_goroutines", 'go_goroutines{job="gateway"}', "gateway saturation"),
    ("gateway_http_requests_total", 'sum(gateway_http_requests_total{job="gateway"})', "received requests"),
    ("gateway_reservations_denied_total", 'sum(gateway_reservations_denied_total{job="gateway"})', "admission refusals (enforce; lazy)"),
    ("gateway_reservations_would_deny_total", 'sum(gateway_reservations_would_deny_total{job="gateway"})', "admission refusals (shadow; lazy)"),
    ("budget_local_admit_total", 'sum(budget_local_admit_total{job="gateway"})', "admission decisions (lazy; may not materialize in this profile)"),
    ("gateway_key_ratelimit_denied_total", 'sum(gateway_key_ratelimit_denied_total{job="gateway"})', "limiter denials (lazy)"),
    ("gateway_upstream_requests_total", 'sum(gateway_upstream_requests_total{job="gateway"})', "upstream outcomes"),
    ("gateway_upstream_tokens_total", 'sum(gateway_upstream_tokens_total{job="gateway"})', "token accounting"),
    ("gateway_silent_failures_total", 'sum(gateway_silent_failures_total)', "publish/backlog drops"),
    ("gateway_settlement_backlog", 'sum(gateway_settlement_jobs_backlog)', "settlement backlog (all states; loggerd publisher)"),
    ("gateway_loggerd_events_in_flight", 'gateway_loggerd_events_in_flight{job="loggerd"}', "consumer queue"),
    ("gateway_loggerd_events_consumed_total", 'sum(gateway_loggerd_events_consumed_total{job="loggerd"})', "consumer throughput"),
    ("loggerd_rss_bytes", 'process_resident_memory_bytes{job="loggerd"}', "loggerd saturation"),
    ("loggerd_goroutines", 'go_goroutines{job="loggerd"}', "loggerd saturation"),
]

BACKLOG_QUERY = 'sum(gateway_settlement_jobs_backlog)'


def prom_query(prom, q, at=None, timeout=15):
    """Instant query -> {series_labels: value} (empty dict when no series)."""
    params = {"query": q}
    if at is not None:
        params["time"] = f"{at:.3f}"
    url = f"{prom.rstrip('/')}/api/v1/query?" + urllib.parse.urlencode(params)
    with urllib.request.urlopen(url, timeout=timeout) as resp:
        payload = json.load(resp)
    if payload.get("status") != "success":
        raise RuntimeError(f"prom query failed: {payload}")
    out = {}
    for item in payload["data"]["result"]:
        label = item["metric"].get("job", "")
        value = float(item["value"][1])
        key = label
        # sum() queries collapse to one series; keep raw series distinguishable
        out[key] = out.get(key, 0.0) + value
    return out


def collect_snapshot(prom, at=None):
    ts = at if at is not None else time.time()
    snap = {"captured_at_unix": ts, "captured_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ts))}
    metrics = {}
    for key, q, _purpose in SERIES:
        try:
            series = prom_query(prom, q, at=ts)
        except Exception as exc:  # noqa: BLE001 — report per-series, never abort a soak on one scrape
            metrics[key] = {"error": str(exc)}
            continue
        total = sum(series.values())
        metrics[key] = {"value": total, "series": series}
    metrics["_backlog_states"] = try_backlog_states(prom, ts)
    snap["metrics"] = metrics
    return snap


def try_backlog_states(prom, ts):
    try:
        return prom_query(prom, 'gateway_settlement_jobs_backlog', at=ts)
    except Exception as exc:  # noqa: BLE001
        return {"error": str(exc)}


def cmd_snapshot(args):
    snap = collect_snapshot(args.prom, at=args.at)
    emit(snap, args.out)
    return 0


def cmd_baseline(args):
    """Sample the settlement backlog a few times pre-load -> baseline range."""
    samples = []
    for i in range(args.samples):
        if i:
            time.sleep(args.interval)
        res = prom_query(args.prom, BACKLOG_QUERY)
        val = sum(res.values()) if res else 0.0
        samples.append({"at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "sum": val})
    vals = [s["sum"] for s in samples]
    baseline = {
        "captured_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "samples": samples,
        "min": min(vals),
        "max": max(vals),
        "query": BACKLOG_QUERY,
    }
    emit(baseline, args.out)
    return 0


def cmd_watch(args):
    """Poll backlog until it returns into the baseline range, else record the
    goal failure (packet acceptance wording — the failure path is a first-class
    outcome, not a silent pass)."""
    with open(args.baseline_file, encoding="utf-8") as fh:
        baseline = json.load(fh)
    lo = baseline["min"]
    hi = max(baseline["max"], baseline["min"]) * args.slack + args.slack_abs
    started = time.time()
    timeline = []
    recovered = False
    seen_series = False
    stable = 0
    while (time.time() - started) < args.timeout:
        try:
            res = prom_query(args.prom, BACKLOG_QUERY)
        except Exception as exc:  # noqa: BLE001 — a lost scrape is not recovery evidence
            timeline.append({"at_utc": now_utc(), "error": str(exc)})
            stable = 0
            time.sleep(args.interval)
            continue
        if not res:
            # Series absent (e.g. gateway job down / registry not yet
            # scraped): this is NOT evidence of an empty backlog — it must
            # never count toward recovery stability.
            timeline.append({"at_utc": now_utc(), "series_absent": True})
            stable = 0
            time.sleep(args.interval)
            continue
        seen_series = True
        val = sum(res.values())
        in_range = lo <= val <= hi
        stable = stable + 1 if in_range else 0
        timeline.append({"at_utc": now_utc(), "sum": val, "in_range": in_range})
        if stable >= args.stable:
            recovered = True
            break
        time.sleep(args.interval)
    verdict = {
        "baseline": {"min": baseline["min"], "max": baseline["max"]},
        "recovery_range": [lo, hi],
        "timeout_s": args.timeout,
        "interval_s": args.interval,
        "stable_required": args.stable,
        "recovered": recovered,
        "series_ever_observed": seen_series,
        "elapsed_s": round(time.time() - started, 1),
        "timeline": timeline,
    }
    emit(verdict, args.out)
    return 0 if recovered else 1


def cmd_range(args):
    """Saturation timeline over the measured window (prom query_range)."""
    summary = {"start": args.start, "end": args.end, "step_s": args.step, "metrics": {}}
    for key, q, _purpose in SERIES:
        params = {
            "query": q,
            "start": args.start,
            "end": args.end,
            "step": f"{args.step}s",
        }
        url = f"{args.prom.rstrip('/')}/api/v1/query_range?" + urllib.parse.urlencode(params)
        with urllib.request.urlopen(url, timeout=30) as resp:
            payload = json.load(resp)
        if payload.get("status") != "success":
            summary["metrics"][key] = {"error": str(payload)}
            continue
        points = []
        for series in payload["data"]["result"]:
            points.extend(float(v[1]) for v in series["values"] if v[1] != "NaN")
        if not points:
            summary["metrics"][key] = {"absent": True}
            continue
        summary["metrics"][key] = {
            "n": len(points),
            "min": min(points),
            "max": max(points),
            "avg": sum(points) / len(points),
            "first": points[0],
            "last": points[-1],
            "delta_last_minus_first": points[-1] - points[0],
        }
    emit(summary, args.out)
    return 0


def now_utc():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def emit(obj, out):
    text = json.dumps(obj, indent=2, sort_keys=False)
    if out:
        with open(out, "w", encoding="utf-8") as fh:
            fh.write(text + "\n")
    else:
        print(text)


def parse_ts(s):
    # unix epoch seconds or RFC3339-lite «YYYY-MM-DDTHH:MM:SSZ»
    try:
        return float(s)
    except ValueError:
        return time.mktime(time.strptime(s, "%Y-%m-%dT%H:%M:%SZ"))


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--prom", default="http://127.0.0.1:39090", help="prometheus base URL (soak stand host port)")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("snapshot", help="instant scrape of tracked series")
    p.add_argument("--at", type=parse_ts, default=None)
    p.add_argument("--out", default="")
    p.set_defaults(func=cmd_snapshot)

    p = sub.add_parser("baseline", help="pre-load backlog baseline range")
    p.add_argument("--samples", type=int, default=5)
    p.add_argument("--interval", type=float, default=3.0)
    p.add_argument("--out", default="")
    p.set_defaults(func=cmd_baseline)

    p = sub.add_parser("watch", help="poll backlog until back in baseline range")
    p.add_argument("--baseline-file", required=True)
    p.add_argument("--timeout", type=float, default=300.0)
    p.add_argument("--interval", type=float, default=10.0)
    p.add_argument("--stable", type=int, default=2)
    p.add_argument("--slack", type=float, default=1.05, help="multiplicative tolerance on baseline max")
    p.add_argument("--slack-abs", type=float, default=2.0, help="absolute tolerance on baseline max")
    p.add_argument("--out", default="")
    p.set_defaults(func=cmd_watch)

    p = sub.add_parser("range", help="saturation timeline over [start,end]")
    p.add_argument("--start", required=True, type=parse_ts)
    p.add_argument("--end", required=True, type=parse_ts)
    p.add_argument("--step", type=int, default=30)
    p.add_argument("--out", default="")
    p.set_defaults(func=cmd_range)

    args = ap.parse_args(argv)
    try:
        return args.func(args)
    except Exception as exc:  # noqa: BLE001 — CLI boundary
        print(f"soak_collect: fatal: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
