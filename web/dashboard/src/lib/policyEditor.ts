// guard and the version-history selection model.
//
// The server has NO optimistic-concurrency token on PUT (contract D2; no
// backend change in this packet), so the guard is client-side over the
// existing GET: before every mutation the editor re-reads the detail and
// compares against the baseline it loaded/edited from. The comparison is
// field-scoped because the two PUT shapes differ:
//  - saving a NEW draft yaml is stale when the LATEST version moved
//    (someone appended/activated a version the editor never saw);
//  - activating/rolling back is stale when the ACTIVE version moved
//    (operator B activated v3 while operator A still edits from v2).

import type { PolicyDetail, PolicyVersion } from '../api/policyPipelines'

/** The version coordinates the editor loaded. */
export interface PolicyBaseline {
  latestVersion: number
  activeVersion: number
}

export function baselineFromDetail(detail: PolicyDetail): PolicyBaseline {
  const versions = detail.versions ?? []
  return {
    // versions arrive newest first; 0 = no versions yet
    latestVersion: versions[0]?.version ?? 0,
    activeVersion: detail.policy?.current_version ?? 0,
  }
}

/** Stale for a yaml save: the latest version moved underneath the editor. */
export function isStaleForYaml(loaded: PolicyBaseline, current: PolicyBaseline): boolean {
  return loaded.latestVersion !== current.latestVersion
}

/** Stale for activate/rollback: the active version moved. */
export function isStaleForActivate(loaded: PolicyBaseline, current: PolicyBaseline): boolean {
  return loaded.activeVersion !== current.activeVersion || loaded.latestVersion !== current.latestVersion
}

/** The version a draft-save diffs against in the preview: the newest stored
    version (what the runtime would replace once activated). */
export function newestVersion(detail: PolicyDetail): PolicyVersion | null {
  return detail.versions?.[0] ?? null
}

/** The version the runtime currently evaluates. */
export function activeVersionDetail(detail: PolicyDetail): PolicyVersion | null {
  const active = detail.policy?.current_version ?? 0
  if (active <= 0) return null
  return (detail.versions ?? []).find(v => v.version === active) ?? null
}

/** Default diff pair for the history view: the two newest versions. */
export function defaultDiffPair(versions: PolicyVersion[]): { a: number; b: number } | null {
  if (versions.length < 2) return null
  return { a: versions[1].version, b: versions[0].version }
}

/** Rollback = activating anything older than the current active version. */
export function isRollback(targetVersion: number, activeVersion: number): boolean {
  return activeVersion > 0 && targetVersion < activeVersion
}
