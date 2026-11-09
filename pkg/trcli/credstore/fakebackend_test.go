package credstore

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
)

// errFakeMissing mirrors the not-found failure of both helper CLIs.
var errFakeMissing = errors.New("fake helper: entry not found")

// fakeCall is one recorded helper invocation, kept verbatim so tests can
// assert the argv/stdin contract after the fact.
type fakeCall struct {
	name  string
	args  []string
	stdin string
}

func (c fakeCall) argv() string {
	return c.name + " " + strings.Join(c.args, " ")
}

// fakeFlagValue returns the argv element after flag, or "" when absent.
func fakeFlagValue(args []string, flag string) string {
	for i, arg := range args {
		if arg == flag && i+1 < len(args) {
			return args[i+1]
		}
	}
	return ""
}

// securityFake emulates the macOS security CLI in memory: -i scripts store
// values, find-generic-password reads them, delete-generic-password removes
// them. Script values arrive double-quoted with backslash escapes, the same
// shape escapeQuoted produces, so round-trips exercise the real encoding.
// Every entry lives in a map; no real keychain is touched on any platform.
type securityFake struct {
	entries map[string]string
	calls   []fakeCall
	fail    map[string]error // first argv element -> injected failure
}

func (f *securityFake) Run(_ context.Context, stdin []byte, name string, args ...string) (string, error) {
	call := fakeCall{name: name, args: append([]string(nil), args...), stdin: string(stdin)}
	f.calls = append(f.calls, call)
	if name != "security" {
		return "", fmt.Errorf("securityFake: unexpected helper %q", name)
	}
	if len(args) == 0 {
		return "", errors.New("securityFake: missing subcommand")
	}
	if err, ok := f.fail[args[0]]; ok {
		return "", err
	}
	switch args[0] {
	case "-i":
		account, value, err := parseKeychainScript(call.stdin)
		if err != nil {
			return "", err
		}
		if f.entries == nil {
			f.entries = map[string]string{}
		}
		f.entries[account] = value
		return "", nil
	case "find-generic-password":
		value, ok := f.entries[fakeFlagValue(args, "-a")]
		if !ok {
			return "", errFakeMissing
		}
		return value + "\n", nil
	case "delete-generic-password":
		account := fakeFlagValue(args, "-a")
		if _, ok := f.entries[account]; !ok {
			return "", errFakeMissing
		}
		delete(f.entries, account)
		return "", nil
	default:
		return "", fmt.Errorf("securityFake: unknown subcommand %q", args[0])
	}
}

func (f *securityFake) LookPath(file string) (string, error) {
	return "/usr/bin/" + file, nil
}

// splitKeychainScript tokenizes a security -i script the way the CLI parses
// it: whitespace separates tokens, double quotes group them, and a backslash
// escapes the character that follows, inside or outside quotes.
func splitKeychainScript(script string) ([]string, error) {
	var (
		tokens  []string
		current strings.Builder
		started bool
		inQuote bool
	)
	for i := 0; i < len(script); i++ {
		c := script[i]
		switch {
		case c == '\\' && i+1 < len(script):
			current.WriteByte(script[i+1])
			i++
			started = true
		case c == '"':
			inQuote = !inQuote
			started = true
		case (c == ' ' || c == '\t' || c == '\n' || c == '\r') && !inQuote:
			if started {
				tokens = append(tokens, current.String())
				current.Reset()
				started = false
			}
		default:
			current.WriteByte(c)
			started = true
		}
	}
	if inQuote {
		return nil, errors.New("securityFake: unterminated quote in script")
	}
	if started {
		tokens = append(tokens, current.String())
	}
	return tokens, nil
}

// parseKeychainScript reads the add-generic-password script the keychain
// store feeds to security -i: add-generic-password -U -s yabanin -a ACCOUNT
// -w VALUE, with ACCOUNT and VALUE double-quoted and backslash-escaped.
func parseKeychainScript(script string) (account, value string, err error) {
	tokens, err := splitKeychainScript(script)
	if err != nil {
		return "", "", err
	}
	head := []string{"add-generic-password", "-U", "-s", "yabanin", "-a"}
	if len(tokens) != len(head)+3 || tokens[len(head)+1] != "-w" {
		return "", "", fmt.Errorf("securityFake: unexpected script %q", script)
	}
	for i, want := range head {
		if tokens[i] != want {
			return "", "", fmt.Errorf("securityFake: unexpected script %q", script)
		}
	}
	return tokens[len(head)], tokens[len(head)+2], nil
}

func TestKeychainRoundTripThroughFakeBackend(t *testing.T) {
	fake := &securityFake{entries: map[string]string{}}
	store := keychain{run: fake}
	ctx := context.Background()
	name := `client "prod"`  // quotes and spaces exercise escapeQuoted
	value := `p@ss"wo\rd #1` // quotes, backslashes and spaces round-trip

	ref, warning, err := store.Put(ctx, name, value)
	if err != nil || warning != "" || ref != "keychain:"+name {
		t.Fatalf("put: ref %q warning %q err %v", ref, warning, err)
	}
	got, err := store.Get(ctx, name)
	if err != nil || got != value {
		t.Fatalf("get after put: %q %v", got, err)
	}
	for i, call := range fake.calls {
		if strings.Contains(call.argv(), value) {
			t.Fatalf("call %d carried the value in argv: %q", i, call.argv())
		}
	}
	if len(fake.calls) != 2 {
		t.Fatalf("calls %#v", fake.calls)
	}
	put := fake.calls[0]
	if put.name != "security" || !slices.Equal(put.args, []string{"-i"}) {
		t.Fatalf("put call %#v", put)
	}
	if !strings.Contains(put.stdin, "add-generic-password") || !strings.Contains(put.stdin, `\"`) {
		t.Fatalf("put stdin %q", put.stdin)
	}
	get := fake.calls[1]
	if get.name != "security" || !slices.Equal(get.args, KeychainGetArgs(name)) {
		t.Fatalf("get call %#v", get)
	}
	if err := store.Delete(ctx, name); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if want := []string{"delete-generic-password", "-s", "yabanin", "-a", name}; !slices.Equal(fake.calls[2].args, want) {
		t.Fatalf("delete args %#v", fake.calls[2].args)
	}
	if _, err := store.Get(ctx, name); !errors.Is(err, errFakeMissing) {
		t.Fatalf("get after delete: %v", err)
	}
}

func TestKeychainErrorPaths(t *testing.T) {
	boom := errors.New("security: injected failure")
	ctx := context.Background()

	putStore := keychain{run: &securityFake{fail: map[string]error{"-i": boom}}}
	ref, warning, err := putStore.Put(ctx, "default", "v")
	if !errors.Is(err, boom) || ref != "" || warning != "" {
		t.Fatalf("put error path: ref %q warning %q err %v", ref, warning, err)
	}

	getStore := keychain{run: &securityFake{fail: map[string]error{"find-generic-password": boom}}}
	if got, err := getStore.Get(ctx, "default"); !errors.Is(err, boom) || got != "" {
		t.Fatalf("get error path: got %q err %v", got, err)
	}

	deleteStore := keychain{run: &securityFake{fail: map[string]error{"delete-generic-password": boom}}}
	if err := deleteStore.Delete(ctx, "default"); !errors.Is(err, boom) {
		t.Fatalf("delete error path: %v", err)
	}

	missing := keychain{run: &securityFake{}}
	if _, err := missing.Get(ctx, "absent"); !errors.Is(err, errFakeMissing) {
		t.Fatalf("get missing entry: %v", err)
	}
	if err := missing.Delete(ctx, "absent"); !errors.Is(err, errFakeMissing) {
		t.Fatalf("delete missing entry: %v", err)
	}
}

// secretToolFake emulates the secret-tool CLI in memory: store writes the
// stdin payload under the account name, lookup returns it, clear removes it.
// The payload travels on stdin only; no real keyring is touched.
type secretToolFake struct {
	entries map[string]string
	calls   []fakeCall
	fail    map[string]error // first argv element -> injected failure
}

func (f *secretToolFake) Run(_ context.Context, stdin []byte, name string, args ...string) (string, error) {
	call := fakeCall{name: name, args: append([]string(nil), args...), stdin: string(stdin)}
	f.calls = append(f.calls, call)
	if name != "secret-tool" {
		return "", fmt.Errorf("secretToolFake: unexpected helper %q", name)
	}
	if len(args) == 0 {
		return "", errors.New("secretToolFake: missing subcommand")
	}
	if err, ok := f.fail[args[0]]; ok {
		return "", err
	}
	account := args[len(args)-1]
	switch args[0] {
	case "store":
		if f.entries == nil {
			f.entries = map[string]string{}
		}
		f.entries[account] = call.stdin
		return "", nil
	case "lookup":
		value, ok := f.entries[account]
		if !ok {
			return "", errFakeMissing
		}
		return value + "\n", nil
	case "clear":
		if _, ok := f.entries[account]; !ok {
			return "", errFakeMissing
		}
		delete(f.entries, account)
		return "", nil
	default:
		return "", fmt.Errorf("secretToolFake: unknown subcommand %q", args[0])
	}
}

func (f *secretToolFake) LookPath(file string) (string, error) {
	return "/usr/bin/" + file, nil
}

func TestSecretToolRoundTripKeepsValueOffArgv(t *testing.T) {
	fake := &secretToolFake{entries: map[string]string{}}
	store := secretTool{run: fake}
	ctx := context.Background()

	ref, warning, err := store.Put(ctx, "default", "stored-secret")
	if err != nil || warning != "" || ref != "secret-tool:default" {
		t.Fatalf("put: ref %q warning %q err %v", ref, warning, err)
	}
	got, err := store.Get(ctx, "default")
	if err != nil || got != "stored-secret" {
		t.Fatalf("get after put: %q %v", got, err)
	}
	if err := store.Delete(ctx, "default"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if len(fake.calls) != 3 {
		t.Fatalf("calls %#v", fake.calls)
	}
	if want := SecretToolStoreArgs("default"); !slices.Equal(fake.calls[0].args, want) {
		t.Fatalf("store args %#v", fake.calls[0].args)
	}
	if fake.calls[0].stdin != "stored-secret" {
		t.Fatalf("store stdin %q", fake.calls[0].stdin)
	}
	if want := SecretToolLookupArgs("default"); !slices.Equal(fake.calls[1].args, want) {
		t.Fatalf("lookup args %#v", fake.calls[1].args)
	}
	if want := []string{"clear", "service", "yabanin", "account", "default"}; !slices.Equal(fake.calls[2].args, want) {
		t.Fatalf("clear args %#v", fake.calls[2].args)
	}
	for i, call := range fake.calls {
		if strings.Contains(call.argv(), "stored-secret") {
			t.Fatalf("call %d carried the value in argv: %q", i, call.argv())
		}
	}
	if _, err := store.Get(ctx, "default"); !errors.Is(err, errFakeMissing) {
		t.Fatalf("get after delete: %v", err)
	}
}

func TestSecretToolErrorPaths(t *testing.T) {
	boom := errors.New("secret-tool: injected failure")
	ctx := context.Background()

	putStore := secretTool{run: &secretToolFake{fail: map[string]error{"store": boom}}}
	ref, warning, err := putStore.Put(ctx, "default", "v")
	if !errors.Is(err, boom) || ref != "" || warning != "" {
		t.Fatalf("put error path: ref %q warning %q err %v", ref, warning, err)
	}

	getStore := secretTool{run: &secretToolFake{fail: map[string]error{"lookup": boom}}}
	if got, err := getStore.Get(ctx, "default"); !errors.Is(err, boom) || got != "" {
		t.Fatalf("get error path: got %q err %v", got, err)
	}

	deleteStore := secretTool{run: &secretToolFake{fail: map[string]error{"clear": boom}}}
	if err := deleteStore.Delete(ctx, "default"); !errors.Is(err, boom) {
		t.Fatalf("delete error path: %v", err)
	}
}
