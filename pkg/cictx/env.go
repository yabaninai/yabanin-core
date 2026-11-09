package cictx

import "os"

// Env reads process environment. Tests pass a map; yb passes OSEnv.
type Env interface {
	Getenv(string) string
	LookupEnv(string) (string, bool)
}

// OSEnv reads the real process environment.
type OSEnv struct{}

// Getenv returns the variable or an empty string.
func (OSEnv) Getenv(key string) string { return os.Getenv(key) }

// LookupEnv reports whether the variable is set.
func (OSEnv) LookupEnv(key string) (string, bool) { return os.LookupEnv(key) }

// MapEnv is an Env backed by a string map.
type MapEnv map[string]string

// Getenv returns the mapped value.
func (m MapEnv) Getenv(key string) string {
	if m == nil {
		return ""
	}
	return m[key]
}

// LookupEnv reports whether the key is present, including an empty value.
func (m MapEnv) LookupEnv(key string) (string, bool) {
	if m == nil {
		return "", false
	}
	v, ok := m[key]
	return v, ok
}
