#!/usr/bin/env bash
# PDB selector / drain / rollout-strategy invariants
# over the RENDERED charts (helm template + grep/awk — same harness idea as
# scripts/lint_helm.sh, which only checks that templates render).
#
# Catches the two found defects and the unpinned-strategy defect:
#   D1 gateway PDB selected `app: yabinin` but gateway pods are labeled
#      `app: yabinin-gateway` → PDB matched ZERO pods (protected nothing).
#   D2 admin PDB minAvailable: 1 against a 1-replica Deployment → every
#      voluntary eviction (node drain) blocked forever.
#   D3 no Deployment pinned strategy.rollingUpdate → unpinned 25/25 defaults
#      could take all replicas down during one helm upgrade.
#
# Assertions per chart x values variant:
#   A1 every rendered PodDisruptionBudget selector matches >=1 Deployment
#      pod-template label set (no "protects nothing" PDB);
#   A2 every PDB->Deployment match allows >=1 voluntary eviction at the
#      rendered replica count (minAvailable < replicas, or maxUnavailable >= 1);
#   A3 every Deployment pins strategy.type=RollingUpdate with BOTH
#      rollingUpdate.maxUnavailable and maxSurge.
#   A4 (N11-P02-T02) every topologySpreadConstraints labelSelector matches its
#      OWN Deployment pod-template labels (a selector matching zero pods
#      vacuously satisfies every spread constraint);
#   A5 (N11-P02-T02) a hard spread (whenUnsatisfiable=DoNotSchedule) at
#      replicas<2 leaves zero serving replicas after one node loss (I42/I43).
#
# Usage: bash deploy/helm/ha_selector_test.sh   (from repo root; helm required)
set -euo pipefail
cd "$(dirname "$0")/../.."

command -v helm >/dev/null 2>&1 || { echo "FAIL: helm is required" >&2; exit 2; }

fail=0
pass() { echo "PASS: $1"; }
bad() { echo "FAIL: $1" >&2; fail=1; }

# render_docs <chart-dir> <values-file|-> : one record line per rendered doc:
#   DEP|<name>|<replicas>|<k=v,... pod-template labels>|<strategy type>|<maxUnavailable>|<maxSurge>
#   PDB|<name>|<k=v,... selector labels>|<minAvailable or ->|<maxUnavailable or ->
#   TSC|<deployment name>|<topologyKey>|<whenUnsatisfiable>|<k=v,... selector labels or ->
render_docs() { # render_docs <chart-dir> <values-file|-> [extra helm args...]
  local chart="$1" values="$2"; shift 2
  local args=(template gate-ha "$chart" --kube-version 1.25.0)
  [ "$values" = "-" ] || args+=(-f "$values")
  if [ $# -gt 0 ]; then args+=("$@"); fi
  helm "${args[@]}" | awk -v RS='---\n' '
    function val(line) { # value after "key: " with surrounding space trimmed
      match(line, /: */)
      v = substr(line, RSTART + RLENGTH)
      gsub(/^[ \t]+|[ \t]+$/, "", v)
      return v
    }
    function key(line) {
      k = line
      sub(/:.*$/, "", k)
      gsub(/^[ \t]+/, "", k)
      return k
    }
    NF {
      kind=""; name=""; replicas=0; tpl=""; stype=""; mu=""; ms=""; sel=""; mn=""; mx=""
      tkey=""; twhen=""; tsel=""
      section=""
      n = split($0, line, "\n")
      for (i=1; i<=n; i++) {
        l = line[i]
        if (l ~ /^      topologySpreadConstraints:/ && section=="podspec") {
          section="tsc"; tkey=""; twhen=""; tsel=""
        }
        else if (section=="tsc" || section=="tsclabel" || section=="tsclabels") {
          # N11-P02-T02: parse topologySpreadConstraints fields (>=8-space
          # indented) and close the constraint at the first shorter-indented
          # line; a 6-space list item starts another constraint.
          if (l ~ /^          topologyKey: /) tkey = val(l)
          else if (l ~ /^          whenUnsatisfiable: /) twhen = val(l)
          else if (l ~ /^          labelSelector:/) section="tsclabel"
          else if (l ~ /^            matchLabels:/) section="tsclabels"
          else if (l ~ /^              [A-Za-z0-9_.\/-]+: /) { tsel = tsel (tsel==""?"":",") key(l) "=" val(l) }
          else if (l !~ /^        / || l ~ /^        - /) {
            # rendered layout (gateway-deployment.yaml): constraint fields at
            # 10sp under an 8sp "- " item; a shorter-indented line ends the
            # constraint, another 8sp "- " item starts the next one.
            if (kind=="Deployment" && tkey != "")
              printf "TSC|%s|%s|%s|%s\n", name, tkey, twhen, (tsel==""?"-":tsel)
            tkey=""; twhen=""; tsel=""
            section = (l ~ /^        - /) ? "tsc" : "podspec"
          }
        }
        else if (l ~ /^kind: /) { kind = val(l) }
        else if (l ~ /^metadata:/) section="meta"
        else if (l ~ /^spec:/) section="spec"
        else if (l ~ /^  name: /) { if (section=="meta") name = val(l) }
        else if (l ~ /^  replicas: /) { if (section=="spec") replicas = val(l) + 0 }
        else if (l ~ /^  strategy:/) section="strategy"
        else if (l ~ /^    type: /) { if (section=="strategy") stype = val(l) }
        else if (l ~ /^      maxUnavailable: /) { if (section=="strategy") mu = val(l) }
        else if (l ~ /^      maxSurge: /) { if (section=="strategy") ms = val(l) }
        else if (l ~ /^  minAvailable: /) { if (section=="spec") mn = val(l) }
        else if (l ~ /^  maxUnavailable: /) { if (section=="spec") mx = val(l) }
        else if (l ~ /^  template:/) { if (section!="podspec") section="tplmeta" }
        else if (l ~ /^  selector:/) { if (section!="podspec") section="sel" }
        else if (l ~ /^    metadata:/) { if (section=="tplmeta") section="tplmeta2" }
        else if (l ~ /^    spec:/) { if (section=="tpllabels") section="podspec" }
        else if (l ~ /^    matchLabels:/) { if (section=="sel") section="selmatch" }
        else if (l ~ /^      labels:/) { if (section=="tplmeta2") section="tpllabels" }
        else if (l ~ /^        [A-Za-z0-9_.\/-]+: /) {
          if (section=="tpllabels") { tpl = tpl (tpl==""?"":",") key(l) "=" val(l) }
        }
        else if (l ~ /^      [A-Za-z0-9_.\/-]+: /) {
          if (section=="selmatch") { sel = sel (sel==""?"":",") key(l) "=" val(l) }
        }
      }
      # flush a constraint that runs to the end of the doc (no following
      # shorter-indented line, e.g. admin TSC is the last block)
      if (kind=="Deployment" && tkey != "")
        printf "TSC|%s|%s|%s|%s\n", name, tkey, twhen, (tsel==""?"-":tsel)
      if (kind=="Deployment") printf "DEP|%s|%d|%s|%s|%s|%s\n", name, replicas, tpl, stype, mu, ms
      else if (kind=="PodDisruptionBudget") printf "PDB|%s|%s|%s|%s\n", name, sel, (mn==""?"-":mn), (mx==""?"-":mx)
    }
  '
}

label_subset() { # label_subset "k=v,k2=v2" "k=v,k2=v2,k3=v3" -> 0 if arg1 is a subset of arg2
  local want="$1" have="$2" pair rest
  [ -z "$want" ] && return 0
  rest="$want"
  while [ -n "$rest" ]; do
    pair="${rest%%,*}"
    case ",$have," in
      *",$pair,"*) ;;
      *) return 1 ;;
    esac
    if [[ "$rest" == *,* ]]; then rest="${rest#*,}"; else rest=""; fi
  done
  return 0
}

check_chart() { # check_chart <chart-dir> <variant-label> <values-file|-> [min-tsc] [extra helm args...]
  local chart="$1" variant="$2" values="$3" min_tsc=0
  if [ $# -gt 3 ] && [[ "${4:-}" =~ ^[0-9]+$ ]]; then min_tsc="$4"; shift 4; else shift 3; fi
  local out
  out="$(render_docs "$chart" "$values" "$@")"
  local ndep npdb
  ndep=$(grep -c '^DEP|' <<< "$out" || true)
  npdb=$(grep -c '^PDB|' <<< "$out" || true)
  if [ "$ndep" -eq 0 ] || [ -z "$ndep" ]; then
    bad "$chart $variant: no Deployments rendered"
    return
  fi

  # A3: strategy pinned on every Deployment.
  while IFS='|' read -r _ name _replicas _tpl stype mu ms; do
    [ -n "${name:-}" ] || continue
    if [ "${stype:-}" != "RollingUpdate" ] || [ -z "${mu:-}" ] || [ -z "${ms:-}" ]; then
      bad "$chart $variant: Deployment $name does not pin strategy.rollingUpdate (type=${stype:-missing} maxUnavailable=${mu:-missing} maxSurge=${ms:-missing})"
    else
      pass "$chart $variant: $name strategy RollingUpdate maxUnavailable=$mu maxSurge=$ms"
    fi
  done < <(grep '^DEP|' <<< "$out")

  # A1+A2: every PDB selects >=1 Deployment pod template and allows >=1
  # voluntary eviction at the rendered replica count.
  while IFS='|' read -r _ pname sel mn mx; do
    [ -n "${pname:-}" ] || continue
    local matched=0
    while IFS='|' read -r _ dname drep _dtpl _a _b _c; do
      [ -n "${dname:-}" ] || continue
      if label_subset "$sel" "$_dtpl"; then
        matched=1
        if [ "$mn" != "-" ]; then
          if [ "$mn" -ge "$drep" ] 2>/dev/null && [ "$drep" -ge 1 ]; then
            bad "$chart $variant: PDB $pname minAvailable=$mn >= replicas=$drep of $dname — blocks every voluntary eviction (undrainable)"
          else
            pass "$chart $variant: PDB $pname -> $dname minAvailable=$mn < replicas=$drep"
          fi
        elif [ "$mx" != "-" ]; then
          if [ "$mx" -lt 1 ] 2>/dev/null; then
            bad "$chart $variant: PDB $pname maxUnavailable=$mx allows zero evictions"
          else
            pass "$chart $variant: PDB $pname -> $dname maxUnavailable=$mx (replicas=$drep)"
          fi
        else
          bad "$chart $variant: PDB $pname has neither minAvailable nor maxUnavailable"
        fi
      fi
    done < <(grep '^DEP|' <<< "$out")
    if [ "$matched" -eq 0 ]; then
      bad "$chart $variant: PDB $pname selector {$sel} matches NO Deployment pod template — protects nothing (R056 D1 defect class)"
    fi
  done < <(grep '^PDB|' <<< "$out")

  # A4+A5: topologySpreadConstraints (N11-P02-T02 failure-domain placement).
  while IFS='|' read -r _ dname tkey twhen tsel; do
    [ -n "${dname:-}" ] || continue
    local dep_replicas=-1 matched_tpl=""
    while IFS='|' read -r _ dn drep dtpl _a _b _c; do
      [ -n "${dn:-}" ] || continue
      if [ "$dn" = "$dname" ]; then
        dep_replicas="$drep"
        matched_tpl="$dtpl"
      fi
    done < <(grep '^DEP|' <<< "$out")
    if [ -z "$tsel" ] || [ "$tsel" = "-" ]; then
      bad "$chart $variant: TSC on $dname has no labelSelector — spreads nothing"
    elif label_subset "$tsel" "$matched_tpl"; then
      pass "$chart $variant: TSC $dname key=$tkey selector {$tsel} matches own pod template"
    else
      bad "$chart $variant: TSC $dname selector {$tsel} matches NO labels of its own pod template {$matched_tpl} — spreads nothing"
    fi
    if [ "$twhen" = "DoNotSchedule" ] && [ "$dep_replicas" -lt 2 ] 2>/dev/null; then
      bad "$chart $variant: $dname hard topology spread (DoNotSchedule) with replicas=$dep_replicas — one node loss leaves no serving replica"
    else
      pass "$chart $variant: $dname spread key=$tkey when=$twhen tolerable at replicas=$dep_replicas"
    fi
  done < <(grep '^TSC|' <<< "$out")

  # anti-vacuity guard: a variant that must carry the documented HA profile
  # (min_tsc>0) fails loudly if its TSC wiring regresses to zero records.
  local ntsc
  ntsc="$(grep -c '^TSC|' <<< "$out" || true)"
  ntsc="${ntsc:-0}"
  if [ "$ntsc" -lt "$min_tsc" ]; then
    bad "$chart $variant: expected >=$min_tsc topology spread constraints, got $ntsc — A4/A5 ran vacuous"
  fi

  echo "-- $chart $variant: ${ndep} Deployments, ${npdb:-0} PDBs, $ntsc topology-spread constraints checked"
}

echo "== R056 HA selector/strategy regression test =="
for chart in deploy/helm/yabanin deploy/helm/yabanin-onprem; do
  check_chart "$chart" "default" "-"
  for values in "$chart"/values*.yaml; do
    [ -f "$values" ] || continue
    check_chart "$chart" "$(basename "$values")" "$values"
  done
done

# N11-P02-T02: the documented HA profile (deploy/helm/yabanin/HA-TOPOLOGY.md):
# hard failure-domain spread on for gateway AND admin. min-tsc=2 keeps the
# A4/A5 assertions from passing vacuously if ha.* template wiring regresses.
check_chart deploy/helm/yabanin "ha-enabled" "-" 2 --set ha.enabled=true

if [ "$fail" -ne 0 ]; then
  echo "== RESULT: FAIL" >&2
  exit 1
fi
echo "== RESULT: PASS"
