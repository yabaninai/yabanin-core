package clientconfig

import "github.com/reireirei/yabanin/pkg/labels"

// Params is the desired client setup. The API key itself is never included.
type Params struct {
	BaseURL           string
	KeyEnv            string
	Model             string
	AutocompleteModel string
	Labels            labels.Set
	KeyMode           string
	ProviderID        string
}

func (p Params) providerID() string {
	if p.ProviderID == "" {
		return "yabanin"
	}
	return p.ProviderID
}

func (p Params) keyEnv() string {
	if p.KeyEnv == "" {
		return "YABANIN_API_KEY"
	}
	return p.KeyEnv
}

func (p Params) helper() bool { return p.KeyMode == "helper" }
