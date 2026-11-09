#!/usr/bin/env python3
"""Prometheus collector for the N12-P04-T03 load profiles. Stdlib only.

Subcommands (all against the stand's Prometheus at --prom):
  snapshot   instant values of the observed metric set -> JSON
  baseline   sample the settlement backlog N times -> {min,max,samples}
  watch      poll until the backlog returns inside the baseline range
             (packet goal: <=5 min after the bursts; a miss or an absent
             series is RECORDED, never hidden) -> timeline + rc
  range      query_range of saturation/counters over the run window -> JSON

Metric set per T01 INVENTORY.md section 2.2 (contract §15 line 137):
launch/admission (http, reservations, ratelimit), upstream (requests, tokens,
first-token), pipeline (events in flight/consumed, settlement backlog,
silent failures), saturation (RSS/CPU/goroutines for gateway and loggerd).
"""

import argparse
import json
import time
import urllib.parse
import urllib.request

# Metric names verified against the source (pkg/metrics/metrics.go registers
# everything under Subsystem "gateway" → exported names carry the gateway_
# prefix; loggerd sets the settlement gauge on its own endpoint):
#   gateway_http_requests_total            (metrics.go, subsystem gateway)
#   gateway_reservations_denied_total      (metrics.go:386)
#   gateway_reservations_would_deny_total  (metrics.go:373)
#   gateway_key_ratelimit_denied_total     (pkg/gateway/ratelimit.go:73)
#   gateway_upstream_requests_total        (pkg/metrics/upstream.go:25)
#   gateway_upstream_tokens_total          (pkg/metrics/upstream.go)
#   gateway_silent_failures_total          (pkg/metrics/silent_failures.go:45)
#   gateway_loggerd_events_in_flight       (metrics.go:48)
#   gateway_loggerd_events_consumed_total  (metrics.go:58)
#   gateway_settlement_jobs_backlog        (metrics.go:316, set by loggerd
#                                           consumer/settlement.go:1026)
# job="gateway"/"loggerd" pinning is load-bearing: both binaries register the
# shared package registry, so unpinned sums would double-count zeros.
METRICS = {
    "gateway_http_requests_total":
        'sum(gateway_http_requests_total{job="gateway"})',
    "gateway_reservations_denied_total":
        'sum(gateway_reservations_denied_total{job="gateway"})',
    "gateway_reservations_would_deny_total":
        'sum(gateway_reservations_would_deny_total{job="gateway"})',
    "gateway_key_ratelimit_denied_total":
        'sum(gateway_key_ratelimit_denied_total{job="gateway"})',
    "gateway_upstream_requests_total":
        'sum(gateway_upstream_requests_total{job="gateway"})',
    "gateway_upstream_tokens_total":
        'sum(gateway_upstream_tokens_total{job="gateway"})',
    "gateway_silent_failures_total":
        'sum(gateway_silent_failures_total{job="gateway"})',
    "gateway_loggerd_events_in_flight":
        'max(gateway_loggerd_events_in_flight{job="loggerd"})',
    "gateway_loggerd_events_consumed_total":
        'sum(gateway_loggerd_events_consumed_total{job="loggerd"})',
    "settlement_jobs_backlog":
        'max(gateway_settlement_jobs_backlog{job="loggerd"})',
}

SATURATION = {
    "gateway_rss_bytes": 'max(process_resident_memory_bytes{job="gateway"})',
    "gateway_cpu_seconds": 'max(process_cpu_seconds_total{job="gateway"})',
    "gateway_goroutines": 'max(go_goroutines{job="gateway"})',
    "loggerd_rss_bytes": 'max(process_resident_memory_bytes{job="loggerd"})',
    "loggerd_cpu_seconds": 'max(process_cpu_seconds_total{job="loggerd"})',
    "loggerd_goroutines": 'max(go_goroutines{job="loggerd"})',
    "settlement_jobs_backlog_timeline":
        'sum by (state) (gateway_settlement_jobs_backlog{job="loggerd"})',
}


def prom_get(prom, endpoint, params):
    url = f"{prom.rstrip('/')}/{endpoint}?" + urllib.parse.urlencode(params)
    with urllib.request.urlopen(url, timeout=15) as resp:
        payload = json.load(resp)
    if payload.get("status") != "success":
        raise RuntimeError(f"prom query failed: {payload}")
    return payload.get("data", {}).get("result", [])


def instant(prom, query):
    result = prom_get(prom, "api/v1/query", {"query": query})
    vals = []
    for series in result:
        if series.get("value"):
            vals.append(float(series["value"][1]))
    return sum(vals)


def collect_snapshot(prom):
    out = {}
    for name, query in METRICS.items():
        try:
            out[name] = {"value": instant(prom, query), "query": query}
        except Exception as exc:  # metric absent / scrape gap: recorded, not hidden
            out[name] = {"value": None, "query": query, "error": str(exc)}
    return {"metrics": out, "captured_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}


def sample_backlog(prom):
    try:
        return instant(prom, METRICS["settlement_jobs_backlog"])
    except Exception:
        return None


def cmd_snapshot(args):
    data = collect_snapshot(args.prom)
    with open(args.out, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2)
    print(json.dumps(data, indent=2))


def cmd_baseline(args):
    samples = []
    for i in range(args.samples):
        v = sample_backlog(args.prom)
        samples.append(v)
        if i < args.samples - 1:
            time.sleep(args.interval)
    observed = [s for s in samples if s is not None]
    out = {
        "samples": samples,
        "min": min(observed) if observed else None,
        "max": max(observed) if observed else None,
        "series_observed": bool(observed),
        "captured_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    with open(args.out, "w", encoding="utf-8") as fh:
        json.dump(out, fh, indent=2)
    print(json.dumps(out, indent=2))
    if not observed:
        return 1
    return 0


def cmd_watch(args):
    with open(args.baseline_file, encoding="utf-8") as fh:
        baseline = json.load(fh)
    lo, hi = baseline.get("min"), baseline.get("max")
    deadline = time.time() + args.timeout
    timeline = []
    stable_run = 0
    recovered = False
    series_ever = False
    recovered_at = None
    start = time.time()
    while time.time() < deadline:
        v = sample_backlog(args.prom)
        point = {"t": round(time.time() - start, 1), "backlog": v}
        timeline.append(point)
        if v is not None:
            series_ever = True
            if lo is not None and hi is not None and lo <= v <= hi:
                stable_run += 1
                if stable_run >= args.stable:
                    recovered = True
                    recovered_at = point["t"]
                    break
            else:
                stable_run = 0
        time.sleep(args.interval)
    out = {
        "baseline": [lo, hi],
        "recovered": recovered,
        "recovered_after_s": recovered_at,
        "series_ever_observed": series_ever,
        "timeout_s": args.timeout,
        "stable_required": args.stable,
        "timeline": timeline,
    }
    with open(args.out, "w", encoding="utf-8") as fh:
        json.dump(out, fh, indent=2)
    print(json.dumps({k: out[k] for k in ("baseline", "recovered", "recovered_after_s", "series_ever_observed")}, indent=2))
    return 0 if recovered else 1


def cmd_range(args):
    out = {"metrics": {}, "start": args.start, "end": args.end, "step": args.step}
    queries = dict(SATURATION)
    for name, query in queries.items():
        try:
            result = prom_get(args.prom, "api/v1/query_range", {
                "query": query, "start": args.start, "end": args.end, "step": args.step})
        except Exception as exc:
            out["metrics"][name] = {"error": str(exc)}
            continue
        vals = []
        for series in result:
            for ts, v in series.get("values", []):
                vals.append(float(v))
        if vals:
            out["metrics"][name] = {
                "min": min(vals), "max": max(vals),
                "first": vals[0], "last": vals[-1],
                "delta_last_minus_first": vals[-1] - vals[0],
                "points": len(vals),
            }
        else:
            out["metrics"][name] = {"error": "no series in window"}
    # backlog timeline over the whole window (per-gap recovery evidence)
    result = prom_get(args.prom, "api/v1/query_range", {
        "query": METRICS["settlement_jobs_backlog"], "start": args.start, "end": args.end, "step": args.step})
    backlog = []
    for series in result:
        for ts, v in series.get("values", []):
            backlog.append({"ts": ts, "backlog": float(v)})
    out["metrics"]["settlement_jobs_backlog_timeline"] = {"points": len(backlog), "series": backlog[:500]}
    with open(args.out, "w", encoding="utf-8") as fh:
        json.dump(out, fh, indent=2)
    print(json.dumps({k: v for k, v in out["metrics"].items() if k != "settlement_jobs_backlog_timeline"}, indent=2))


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--prom", default="http://127.0.0.1:39190", help="prometheus base URL")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("snapshot")
    p.add_argument("--out", required=True)
    p.set_defaults(func=cmd_snapshot)

    p = sub.add_parser("baseline")
    p.add_argument("--samples", type=int, default=5)
    p.add_argument("--interval", type=float, default=3)
    p.add_argument("--out", required=True)
    p.set_defaults(func=cmd_baseline)

    p = sub.add_parser("watch")
    p.add_argument("--baseline-file", required=True)
    p.add_argument("--timeout", type=float, default=300)
    p.add_argument("--interval", type=float, default=10)
    p.add_argument("--stable", type=int, default=2)
    p.add_argument("--out", required=True)
    p.set_defaults(func=cmd_watch)

    p = sub.add_parser("range")
    p.add_argument("--start", type=int, required=True, help="epoch seconds")
    p.add_argument("--end", type=int, required=True, help="epoch seconds")
    p.add_argument("--step", type=int, default=30)
    p.add_argument("--out", required=True)
    p.set_defaults(func=cmd_range)

    args = ap.parse_args()
    raise SystemExit(args.func(args))


if __name__ == "__main__":
    main()
