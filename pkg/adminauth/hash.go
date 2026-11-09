package adminauth

import (
	"golang.org/x/crypto/bcrypt"
)

const bcryptCost = 12

// HashPassword generates a bcrypt hash of the given plaintext password.
func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcryptCost)
	return string(bytes), err
}

// VerifyPassword checks a plaintext password against a bcrypt hash.
func VerifyPassword(password, hash string) error {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
}

// dummyBcryptHash is a precomputed bcrypt(cost 12) hash of a throwaway
// random string. It is not a credential: it exists only so that a login for
// a non-existent email burns the same bcrypt work as a wrong password
// for timing parity. Verification against it always fails.
const dummyBcryptHash = "$2a$12$QFoCsdrYxyaNq1mV/kpV2OXNzBVq6rr0F0Eoo5p3bHWHEHk.80qR6"

// BurnBcryptWork verifies the candidate password against the dummy hash and
// always returns an error. Call it on the unknown-user path so both login
// failure modes take the same crypto path.
func BurnBcryptWork(password string) {
	_ = VerifyPassword(password, dummyBcryptHash)
}
