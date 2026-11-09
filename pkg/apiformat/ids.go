package apiformat

import (
	"crypto/rand"
	"encoding/hex"
	"strconv"
	"time"
)

// NewID returns prefix plus 24 hexadecimal characters from 12 crypto/rand bytes.
// Prefixes used by the translators are resp_, msg_, fc_, ctc_, rs_, call_, toolu_.
// When an upstream already supplied a tool-call id, callers must keep that id.
func NewID(prefix string) string {
	var b [12]byte
	if _, err := rand.Read(b[:]); err != nil {
		return prefix + strconv.FormatInt(time.Now().UnixNano(), 16)
	}
	return prefix + hex.EncodeToString(b[:])
}
