package auditlog

import "github.com/google/uuid"

// LOGIN/CREATE_ORG call-site pattern: a short upper-case action, a resource
// naming the decision surface, and machine-parsable details carrying the
// actor's identity (AdminID/AdminName), source IP and the immutable request
// digest the decision was bound to.
const (
	// ActionApprove records a granted approval decision (APPROVE).
	ActionApprove = "APPROVE"
	// ActionDeny records a refusal: an explicit deny, or a rejected
	// approval attempt (self-approval, non-root approver, digest mismatch,
	// replay of a decided request).
	ActionDeny = "DENY"
)

// ResourceJITAccess is the resource value recorded for JIT elevation
// decisions (the jit_access state machine).
const ResourceJITAccess = "jit_access"

// ApprovalEntry builds an APPROVE audit row: the deciding actor, source IP
// and the bound request digest in Details.
func ApprovalEntry(adminID, adminName, ip, requestID, requestDigest string) Entry {
	return Entry{
		ID:        uuid.NewString(),
		Action:    ActionApprove,
		Resource:  ResourceJITAccess,
		Details:   decisionDetails(requestID, requestDigest, ""),
		AdminID:   adminID,
		AdminName: adminName,
		IP:        ip,
	}
}

// DenyEntry builds a DENY audit row. reason may carry the refusal cause
// (explicit deny note, or the rejection reason of a failed approval
// attempt); it is appended verbatim to Details.
func DenyEntry(adminID, adminName, ip, requestID, requestDigest, reason string) Entry {
	return Entry{
		ID:        uuid.NewString(),
		Action:    ActionDeny,
		Resource:  ResourceJITAccess,
		Details:   decisionDetails(requestID, requestDigest, reason),
		AdminID:   adminID,
		AdminName: adminName,
		IP:        ip,
	}
}

// decisionDetails renders the stable details payload: the request id, the
// digest that pins the immutable request content and an optional reason.
func decisionDetails(requestID, requestDigest, reason string) string {
	d := "request=" + requestID + " digest=" + requestDigest
	if reason != "" {
		d += " reason=" + reason
	}
	return d
}
