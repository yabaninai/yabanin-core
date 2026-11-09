// Package auditlog provides tamper-evident audit log writing and verification.
// Each row's row_hash = sha256(prev_hash || payload), forming a hash-chain
// where any modification to a historical row breaks the chain at that point.
package auditlog
