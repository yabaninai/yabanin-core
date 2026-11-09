package license

import (
	"encoding/json"
	"fmt"
	"os"
	"time"
)

// RevokeIntermediate adds an intermediate serial to the CRL.
func RevokeIntermediate(crlPath string, serial string) error {
	var crl CRL

	data, err := readLocalFile(crlPath)
	if err == nil {
		// A readable-but-corrupt CRL must not overwrite existing revocations.
		if uerr := json.Unmarshal(data, &crl); uerr != nil {
			return fmt.Errorf("parse crl: %w", uerr)
		}
	}

	for _, s := range crl.RevokedSerials {
		if s == serial {
			return nil // already revoked
		}
	}

	crl.RevokedSerials = append(crl.RevokedSerials, serial)
	crl.UpdatedAt = time.Now()

	out, _ := json.MarshalIndent(crl, "", "  ")
	// CRL is non-secret (revoked serials only) and shared between services via volume.
	return os.WriteFile(crlPath, out, 0644) //nolint:gosec // G306: non-secret internal artifact
}

// IsRevoked checks if a serial is in the CRL.
func IsRevoked(crlPath string, serial string) (bool, error) {
	data, err := readLocalFile(crlPath)
	if err != nil {
		return false, fmt.Errorf("read crl: %w", err)
	}

	var crl CRL
	if err := json.Unmarshal(data, &crl); err != nil {
		return false, fmt.Errorf("parse crl: %w", err)
	}

	for _, s := range crl.RevokedSerials {
		if s == serial {
			return true, nil
		}
	}

	return false, nil
}
