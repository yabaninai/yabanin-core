#!/usr/bin/env python3
"""P5 kill criterion: measure combined cache + routing savings from request_logs.

Usage:
    pip install psycopg2-binary  # or use Docker
    python scripts/measure_savings.py --org-id=<uuid> [--days=7]

Reads cost_in_usd and counterfactual_cost_usd from the request_logs table
and reports whether the combined savings meet the P5 kill criterion (≥45%).

Requires DATABASE_URL env var or --db-uri flag.
"""

import argparse
import json
import os
import sys
from datetime import datetime, timedelta


def parse_args():
    parser = argparse.ArgumentParser(description="Measure P5 savings from request_logs")
    parser.add_argument("--org-id", help="Organization UUID to filter (default: all orgs)")
    parser.add_argument("--days", type=int, default=7, help="Lookback window in days (default: 7)")
    parser.add_argument("--db-uri", help="Postgres connection string (overrides DATABASE_URL)")
    return parser.parse_args()


def connect(db_uri):
    try:
        import psycopg2
    except ImportError:
        print("ERROR: psycopg2 not installed. Run: pip install psycopg2-binary", file=sys.stderr)
        sys.exit(1)

    conn = psycopg2.connect(db_uri, connect_timeout=10)
    conn.autocommit = True
    return conn


def measure_savings(conn, org_id=None, days=7):
    cur = conn.cursor()

    cutoff = datetime.utcnow() - timedelta(days=days)

    where_clauses = ["created_at > %s"]
    params = [cutoff]

    if org_id:
        where_clauses.append("org_id::text = %s")
        params.append(org_id)

    where_sql = " AND ".join(where_clauses)

    # Total cost analysis
    cur.execute(f"""
        SELECT
            COUNT(*) AS total_requests,
            COALESCE(SUM(cost_in_usd), 0) AS actual_cost,
            COALESCE(SUM(counterfactual_cost_usd), 0) AS counterfactual_cost,
            CASE WHEN SUM(counterfactual_cost_usd) > 0
                 THEN ROUND((SUM(counterfactual_cost_usd) - SUM(cost_in_usd)) / SUM(counterfactual_cost_usd) * 100, 2)
                 ELSE 0 END AS combined_savings_pct
        FROM request_logs
        WHERE {where_sql}
    """, params)

    total_row = cur.fetchone()
    total_requests, actual_cost, counterfactual_cost, combined_savings_pct = total_row

    # Cache savings: requests with cache_hit_type IS NOT NULL
    cache_where = f"{where_sql} AND cache_hit_type IS NOT NULL"

    cur.execute(f"""
        SELECT
            COUNT(*) AS cache_hits,
            COALESCE(SUM(counterfactual_cost_usd), 0) AS cache_counterfactual,
            COALESCE(SUM(cost_in_usd), 0) AS cache_actual,
            CASE WHEN SUM(counterfactual_cost_usd) > 0
                 THEN ROUND((SUM(counterfactual_cost_usd) - SUM(cost_in_usd)) / SUM(counterfactual_cost_usd) * 100, 2)
                 ELSE 0 END AS cache_savings_pct
        FROM request_logs
        WHERE {cache_where}
    """, params)

    cache_row = cur.fetchone()
    cache_hits, cache_counterfactual, cache_actual, cache_savings_pct = cache_row

    # Routing savings: requests that went through classifier with tier_used set
    routing_where = f"{where_sql} AND tier_used IS NOT NULL AND classifier_class IS NOT NULL"

    cur.execute(f"""
        SELECT
            COUNT(*) AS routed_requests,
            COALESCE(SUM(counterfactual_cost_usd), 0) AS routing_counterfactual,
            COALESCE(SUM(cost_in_usd), 0) AS routing_actual,
            CASE WHEN SUM(counterfactual_cost_usd) > 0
                 THEN ROUND((SUM(counterfactual_cost_usd) - SUM(cost_in_usd)) / SUM(counterfactual_cost_usd) * 100, 2)
                 ELSE 0 END AS routing_savings_pct
        FROM request_logs
        WHERE {routing_where}
    """, params)

    routing_row = cur.fetchone()
    routed_requests, routing_counterfactual, routing_actual, routing_savings_pct = routing_row

    # Per-model breakdown (top 10 by cost)
    cur.execute(f"""
        SELECT model_requested, COUNT(*) AS cnt,
               ROUND(COALESCE(SUM(cost_in_usd), 0)::numeric, 6) AS actual_cost,
               ROUND(COALESCE(SUM(counterfactual_cost_usd), 0)::numeric, 6) AS counterfactual_cost
        FROM request_logs
        WHERE {where_sql}
        GROUP BY model_requested
        ORDER BY COALESCE(SUM(counterfactual_cost_usd), 0) DESC
        LIMIT 10
    """, params)

    top_models = []
    for row in cur.fetchall():
        model, cnt, actual, counterfactual = row
        savings = 0.0
        if counterfactual > 0:
            savings = round((counterfactual - actual) / counterfactual * 100, 2)
        top_models.append({
            "model": model,
            "requests": cnt,
            "actual_cost_usd": float(actual),
            "counterfactual_cost_usd": float(counterfactual),
            "savings_pct": savings,
        })

    # By-day breakdown
    cur.execute(f"""
        SELECT DATE(created_at) AS day, COUNT(*) AS cnt,
               ROUND(COALESCE(SUM(cost_in_usd), 0)::numeric, 6) AS actual_cost,
               ROUND(COALESCE(SUM(counterfactual_cost_usd), 0)::numeric, 6) AS counterfactual_cost
        FROM request_logs
        WHERE {where_sql}
        GROUP BY DATE(created_at)
        ORDER BY day DESC
    """, params)

    daily = []
    for row in cur.fetchall():
        day, cnt, actual, counterfactual = row
        savings = 0.0
        if counterfactual > 0:
            savings = round((counterfactual - actual) / counterfactual * 100, 2)
        daily.append({
            "date": str(day),
            "requests": cnt,
            "actual_cost_usd": float(actual),
            "counterfactual_cost_usd": float(counterfactual),
            "savings_pct": savings,
        })

    return {
        "period": f"last_{days}_days",
        "total_requests": total_requests,
        "actual_cost_usd": round(float(actual_cost), 6),
        "counterfactual_cost_usd": round(float(counterfactual_cost), 6),
        "combined_savings_pct": float(combined_savings_pct),
        "kill_criterion_met": float(combined_savings_pct) >= 45.0,
        # Cache savings (cache_hit_type IS NOT NULL)
        "cache_hits": cache_hits,
        "cache_savings_pct": float(cache_savings_pct),
        # Routing savings (tier_used IS NOT NULL AND classifier_class IS NOT NULL)
        "routed_requests": routed_requests,
        "routing_savings_pct": float(routing_savings_pct),
        "top_models_by_cost": top_models,
        "daily_breakdown": daily,
    }


def main():
    args = parse_args()
    db_uri = args.db_uri or os.environ.get("DATABASE_URL")
    if not db_uri:
        print("ERROR: No DATABASE_URL env var and no --db-uri flag.", file=sys.stderr)
        sys.exit(1)

    conn = connect(db_uri)
    try:
        result = measure_savings(conn, org_id=args.org_id, days=args.days)
    finally:
        conn.close()

    # Print JSON to stdout (for CI / Makefile parsing)
    print(json.dumps(result, indent=2))

    # Also print a human-readable summary to stderr
    print(f"\n=== P5 Savings Report ({result['period']}) ===", file=sys.stderr)
    print(f"Total requests: {result['total_requests']}", file=sys.stderr)
    print(f"Actual cost:     ${result['actual_cost_usd']:.6f}", file=sys.stderr)
    print(f"Counterfactual:  ${result['counterfactual_cost_usd']:.6f}", file=sys.stderr)
    print(f"Combined savings: {result['combined_savings_pct']}%", file=sys.stderr)
    print(f"Cache hits:      {result['cache_hits']} ({result['cache_savings_pct']}% savings)", file=sys.stderr)
    print(f"Routed requests: {result['routed_requests']} ({result['routing_savings_pct']}% routing savings)", file=sys.stderr)
    print(f"P5 KILL CRITERION (≥45%): {'✅ MET' if result['kill_criterion_met'] else '❌ NOT MET'}", file=sys.stderr)

    if result["top_models_by_cost"]:
        print(f"\nTop models by counterfactual cost:", file=sys.stderr)
        for m in result["top_models_by_cost"][:5]:
            print(f"  {m['model']:30s} {m['requests']:6d} reqs  ${m['actual_cost_usd']:.4f}/${m['counterfactual_cost_usd']:.4f} ({m['savings_pct']}%)", file=sys.stderr)

    if result["kill_criterion_met"]:
        sys.exit(0)
    else:
        # Exit non-zero so CI can detect failure
        sys.exit(1)


if __name__ == "__main__":
    main()
