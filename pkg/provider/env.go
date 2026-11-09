package provider

import "os"

// osGetenv is a package-level indirection so tests can swap env reads
// without touching the global os.Environ. Keep here to avoid import cycles.
var osGetenv = os.Getenv
