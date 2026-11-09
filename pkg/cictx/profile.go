package cictx

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/reireirei/yabanin/pkg/labels"
	"gopkg.in/yaml.v3"
)

// Profile is a .yabanin.yml document (version 1).
type Profile struct {
	Version   int            `yaml:"version"`
	Labels    ProfileLabels  `yaml:"labels"`
	Require   []string       `yaml:"require"`
	OnMissing string         `yaml:"on_missing"`
	Session   ProfileSession `yaml:"session"`
}

// ProfileLabels is the labels section of a profile.
type ProfileLabels struct {
	Static       map[string]string `yaml:"static"`
	FromEnv      map[string]string `yaml:"from_env"`
	Extract      []ExtractRule     `yaml:"extract"`
	IncludeActor bool              `yaml:"include_actor"`
}

// ExtractRule pulls one label from a text source.
type ExtractRule struct {
	Label    string   `yaml:"label"`
	From     []string `yaml:"from"`
	Regex    string   `yaml:"regex"`
	Template string   `yaml:"template"`
}

// ProfileSession is the optional session budget block.
type ProfileSession struct {
	TTL        string  `yaml:"ttl"`
	MaxTokens  int64   `yaml:"max_tokens"`
	MaxCostUSD float64 `yaml:"max_cost_usd"`
}

// ExitError is a client-side failure that yb should surface with Code.
type ExitError struct {
	Code    int
	Missing []string
}

func (e *ExitError) Error() string {
	return "missing required labels: " + strings.Join(e.Missing, ",")
}

// FindProfile resolves --profile, then YABANIN_PROFILE, then <git root>/.yabanin.yml.
// An empty path means no profile. A named path that is missing is an error.
func FindProfile(env Env, dir, flagPath string) (string, error) {
	if flagPath != "" {
		if _, err := os.Stat(flagPath); err != nil {
			return "", err
		}
		return flagPath, nil
	}
	if env != nil {
		if path := env.Getenv("YABANIN_PROFILE"); path != "" {
			if _, err := os.Stat(path); err != nil {
				return "", err
			}
			return path, nil
		}
	}
	root, ok := gitRoot(dir)
	if !ok {
		return "", nil
	}
	candidate := filepath.Join(root, ".yabanin.yml")
	if _, err := os.Stat(candidate); err == nil {
		return candidate, nil
	}
	return "", nil
}

// LoadProfile parses a profile. Unknown fields and a bad extract regex are errors.
func LoadProfile(path string) (*Profile, error) {
	f, err := os.Open(path) //nolint:gosec // G304: path is the profile selected by flag, env, or git root
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	dec := yaml.NewDecoder(f)
	dec.KnownFields(true)
	var profile Profile
	if err := dec.Decode(&profile); err != nil {
		return nil, err
	}
	if err := profile.validate(); err != nil {
		return nil, err
	}
	return &profile, nil
}

func (p Profile) validate() error {
	if p.Version != 1 {
		return fmt.Errorf("profile version %d is not supported", p.Version)
	}
	switch p.OnMissing {
	case "", "warn", "fail":
	default:
		return fmt.Errorf("on_missing: %q", p.OnMissing)
	}
	if p.Session.TTL != "" {
		d, err := time.ParseDuration(p.Session.TTL)
		if err != nil {
			return fmt.Errorf("session.ttl: %w", err)
		}
		if d < time.Minute || d > 12*time.Hour {
			return fmt.Errorf("session.ttl %s is outside 1m…12h", p.Session.TTL)
		}
	}
	for _, rule := range p.Labels.Extract {
		if len(rule.Regex) > 256 {
			return fmt.Errorf("extract regex longer than 256")
		}
		if _, err := regexp.Compile(rule.Regex); err != nil {
			return fmt.Errorf("extract regex: %w", err)
		}
		if _, ok := labels.NormalizeKey(rule.Label); !ok {
			return fmt.Errorf("extract label: %q", rule.Label)
		}
	}
	return nil
}

// Build layers CI context, profile, and --label flags. Flags win.
// Texts are used only as regex sources.
func Build(c Context, p *Profile, env Env, flags labels.Set) (labels.Set, []labels.Dropped, []string, error) {
	if env == nil {
		env = MapEnv{}
	}
	out := labels.Set{}
	for key, value := range c.Labels {
		out[key] = value
	}
	var dropped []labels.Dropped
	if p != nil && p.Labels.IncludeActor {
		actor := actorFor(c.System, env)
		if actor != "" {
			setLabel(out, &dropped, "ci.actor", actor)
		}
	}
	if p != nil {
		for key, value := range p.Labels.Static {
			setLabel(out, &dropped, key, value)
		}
		for key, envName := range p.Labels.FromEnv {
			value, ok := env.LookupEnv(envName)
			if !ok || strings.TrimSpace(value) == "" {
				continue
			}
			setLabel(out, &dropped, key, value)
		}
		seen := map[string]bool{}
		for _, rule := range p.Labels.Extract {
			key, ok := labels.NormalizeKey(rule.Label)
			if !ok || seen[key] {
				continue
			}
			value, ok := extractRule(rule, c.Texts, env)
			if !ok {
				continue
			}
			setLabel(out, &dropped, key, value)
			seen[key] = true
		}
	}
	for key, value := range flags {
		setLabel(out, &dropped, key, value)
	}
	var missing []string
	if p != nil {
		for _, key := range p.Require {
			norm, ok := labels.NormalizeKey(key)
			if !ok {
				continue
			}
			if _, exists := out[norm]; !exists {
				missing = append(missing, norm)
			}
		}
		if len(missing) > 0 && p.OnMissing == "fail" {
			return out, dropped, missing, &ExitError{Code: 3, Missing: missing}
		}
	}
	return out, dropped, missing, nil
}

func actorFor(system string, env Env) string {
	switch system {
	case "gitlab":
		return gitlabActor(env)
	case "github":
		return githubActor(env)
	default:
		return ""
	}
}

func setLabel(out labels.Set, dropped *[]labels.Dropped, key, value string) {
	normKey, ok := labels.NormalizeKey(key)
	if !ok {
		*dropped = append(*dropped, labels.Dropped{Key: key, Reason: labels.DropInvalidKey})
		return
	}
	normVal, reason := labels.NormalizeValue(value)
	if reason != "" {
		*dropped = append(*dropped, labels.Dropped{Key: normKey, Reason: reason})
		return
	}
	out[normKey] = normVal
}

func extractRule(rule ExtractRule, texts map[string]string, env Env) (string, bool) {
	re, err := regexp.Compile(rule.Regex)
	if err != nil {
		return "", false
	}
	template := rule.Template
	if template == "" {
		template = "$1"
	}
	for _, source := range rule.From {
		text := sourceText(source, texts, env)
		if text == "" {
			continue
		}
		idx := re.FindStringSubmatchIndex(text)
		if idx == nil {
			continue
		}
		value := re.ExpandString(nil, template, text, idx)
		if string(value) != "" {
			return string(value), true
		}
	}
	return "", false
}

func sourceText(source string, texts map[string]string, env Env) string {
	if name, ok := strings.CutPrefix(source, "trailers:"); ok {
		return trailer(texts, name)
	}
	if name, ok := strings.CutPrefix(source, "env:"); ok {
		if env == nil {
			return ""
		}
		return env.Getenv(name)
	}
	return texts[source]
}

func gitRoot(dir string) (string, bool) {
	if dir == "" {
		dir = "."
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		return "", false
	}
	for {
		gitPath := filepath.Join(abs, ".git")
		if st, err := os.Stat(gitPath); err == nil && (st.IsDir() || st.Mode().IsRegular()) {
			return abs, true
		}
		parent := filepath.Dir(abs)
		if parent == abs {
			return "", false
		}
		abs = parent
	}
}
