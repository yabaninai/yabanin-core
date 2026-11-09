// Package run hosts the in-process service runners (admin, gateway, loggerd,
// mcp) so the unified binary dispatches them directly instead of exec-ing
// sibling binaries. The per-service cmd/ mains are thin wrappers around these
// runners.
package run
