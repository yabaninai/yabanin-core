package provider

import "fmt"

// New returns the Provider adapter for the given canonical name.
//
// Accepted names:
//   - "" / "openai" / "openai-compat" → OpenAI adapter
//   - "anthropic"                     → Anthropic adapter (P3.5)
//   - PB4.2 sovereign: sakana / sarvam / krutrim / naver / falcon / jais / mistral
//   - PB4.3 RU:        yandex / sber
//   - PB3.5 local:     vllm / ollama / tgi / llamacpp
//   - zai-coding:      Z.AI GLM Coding Plan (pinned OpenAI-compat endpoint)
//   - azure-openai:    Azure OpenAI (Entra ID client-credentials)
//   - vertex:          Google Vertex AI (native, ADC auth; N08-P03-T02)
//
// Unknown names return an error so misconfigured models fail fast at the
// factory boundary instead of silently routing to the wrong API.
//
// When a model catalog is installed (SetModelCatalog), a provider carrying a
// withdrawal record whose date has passed is rejected here too: new traffic
// never reaches an adapter the catalog has delisted. With no catalog
// installed the factory behaves exactly as before.
//
// "sber" returns a *Sber (stateful: mTLS client + access-token cache),
// "azure-openai" a *AzureOpenAI (stateful: Entra token cache) and "vertex"
// a *Vertex (stateful: ADC chain + token cache). All other adapters are
// stateless value types.
func New(name string) (Provider, error) {
	if !ProviderAdmitted(name) {
		return nil, fmt.Errorf("provider %q is withdrawn in the installed model catalog and no longer admitted", name)
	}
	switch name {
	case "", "openai", "openai-compat":
		return OpenAI{}, nil
	case "anthropic":
		return NewAnthropic(), nil
	case "sakana":
		return Sakana{}, nil
	case "sarvam":
		return Sarvam{}, nil
	case "krutrim":
		return Krutrim{}, nil
	case "naver":
		return Naver{}, nil
	case "falcon":
		return Falcon{}, nil
	case "jais":
		return Jais{}, nil
	case "mistral":
		return Mistral{}, nil
	case "yandex":
		return Yandex{}, nil
	case "sber":
		return NewSber()
	case "vllm":
		return VLLM{}, nil
	case "ollama":
		return Ollama{}, nil
	case "tgi":
		return TGI{}, nil
	case "llamacpp":
		return LlamaCPP{}, nil
	case "zai-coding":
		return ZAICoding{}, nil
	case "azure-openai":
		return NewAzureOpenAI(), nil
	case "vertex":
		// N08-P03-T02: native Google Vertex AI adapter (ADC auth,
		// project/location endpoint, model/region capability matrix).
		return NewVertex(), nil
	case "bedrock":
		return NewBedrock(), nil
	default:
		return nil, fmt.Errorf("unknown provider %q", name)
	}
}
