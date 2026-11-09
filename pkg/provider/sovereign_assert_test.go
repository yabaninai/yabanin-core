package provider

// Compile-time guarantees that every sovereign adapter satisfies Provider.
// If any adapter drifts from the interface, this file fails to compile.
var (
	_ Provider = Sakana{}
	_ Provider = Sarvam{}
	_ Provider = Krutrim{}
	_ Provider = Naver{}
	_ Provider = Falcon{}
	_ Provider = Jais{}
	_ Provider = Mistral{}
	_ Provider = Yandex{}
	_ Provider = (*Sber)(nil)
)
