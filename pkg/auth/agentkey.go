package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

// AgentKeyPrefix marks an agent-principal key (G1). Agent keys are distinct
// from org api_keys and resolve to an AgentID.
const AgentKeyPrefix = "yag_"

// GenerateAgentKey returns a new agent key: "yag_" + 32 hex chars (16 random
// bytes). The plaintext is returned once; only its sha256 is stored.
func GenerateAgentKey() (string, error) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("generate agent key: %w", err)
	}
	return AgentKeyPrefix + hex.EncodeToString(buf), nil
}

// HashKey returns the lowercase hex sha256 of a plaintext key. Both api_keys
// and agent_keys are stored hash-only (sha256-only), so this is the single
// source of truth for the hash format.
func HashKey(plaintext string) string {
	h := sha256.Sum256([]byte(plaintext))
	return hex.EncodeToString(h[:])
}

// IsAgentKey reports whether a plaintext key carries the agent prefix.
func IsAgentKey(key string) bool {
	return len(key) > len(AgentKeyPrefix) && key[:len(AgentKeyPrefix)] == AgentKeyPrefix
}
