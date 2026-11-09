package builtins

import "github.com/reireirei/yabanin/pkg/pipeline"

// Step name constants — THE CONTRACT for policies (YAML detector/mutator
// fields) and for the OP-8 wiring. The names are frozen: policies reference
// them by string, renames are breaking changes.
const (
	NameNationalPII        = "builtin/national-pii"
	NameSecrets            = "builtin/secrets"
	NameInjection          = "builtin/injection"
	NameWordCount          = "builtin/word-count"
	NameCharCount          = "builtin/char-count"
	NameSentenceCount      = "builtin/sentence-count"
	NameContains           = "builtin/contains"
	NameRegex              = "builtin/regex"
	NameJSONSchema         = "builtin/json-schema"
	NameJSONKeys           = "builtin/json-keys"
	NameURLCheck           = "builtin/url-check"
	NameCodeDetect         = "builtin/code-detect"
	NameLanguage           = "builtin/language"
	NameModelWhitelist     = "builtin/model-whitelist"
	NameMetadataRequired   = "builtin/metadata-required"
	NameRedact             = "builtin/redact"
	NamePseudonymize       = "builtin/pseudonymize"
	NameHeaderRewrite      = "builtin/header-rewrite"
	NameModelRewrite       = "builtin/model-rewrite"
	NamePartialsSubstitute = "builtin/partials-substitute"
	NameCompress           = "builtin/compress"
)

// Registry returns the builtin step factories by name. It builds a fresh
// map on every call — no package state, no init side effects; OP-8 owns
// wiring these into engine step registries (pipeline.Registry.Register).
func Registry() map[string]pipeline.StepFactory {
	return map[string]pipeline.StepFactory{
		NameNationalPII:        NewNationalPII,
		NameSecrets:            NewSecrets,
		NameInjection:          NewInjection,
		NameWordCount:          NewWordCount,
		NameCharCount:          NewCharCount,
		NameSentenceCount:      NewSentenceCount,
		NameContains:           NewContains,
		NameRegex:              NewRegex,
		NameJSONSchema:         NewJSONSchema,
		NameJSONKeys:           NewJSONKeys,
		NameURLCheck:           NewURLCheck,
		NameCodeDetect:         NewCodeDetect,
		NameLanguage:           NewLanguage,
		NameModelWhitelist:     NewModelWhitelist,
		NameMetadataRequired:   NewMetadataRequired,
		NameRedact:             NewRedact,
		NamePseudonymize:       NewPseudonymize,
		NameHeaderRewrite:      NewHeaderRewrite,
		NameModelRewrite:       NewModelRewrite,
		NamePartialsSubstitute: NewPartialsSubstitute,
		NameCompress:           NewCompress,
	}
}
