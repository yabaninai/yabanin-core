package trcli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/reireirei/yabanin/pkg/cictx"
	"github.com/reireirei/yabanin/pkg/trcli/credstore"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

func loginCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "login",
		Short: "Store a gateway API key",
		RunE: func(cmd *cobra.Command, _ []string) error {
			url, _ := cmd.Flags().GetString("gateway-url")
			name, _ := cmd.Flags().GetString("name")
			fromStdin, _ := cmd.Flags().GetBool("key-stdin")
			if strings.TrimSpace(url) == "" {
				return errors.New("--gateway-url is required")
			}
			if name == "" {
				name = "default"
			}
			key, err := readAPIKey(cmd, fromStdin)
			if err != nil {
				return err
			}
			if strings.TrimSpace(key) == "" {
				return errors.New("API key is empty")
			}
			warning, err := checkGatewayKey(cmd.Context(), url, key)
			if err != nil {
				return err
			}
			if warning != "" {
				_, _ = fmt.Fprintln(cmd.ErrOrStderr(), warning)
			}
			home, err := credentialHome()
			if err != nil {
				return err
			}
			store, err := credentialOpen(home)
			if err != nil {
				return err
			}
			ref, storeWarning, err := store.Put(cmd.Context(), name, key)
			if err != nil {
				return err
			}
			if storeWarning != "" {
				_, _ = fmt.Fprintln(cmd.ErrOrStderr(), storeWarning)
			}
			return saveProfile(home, name, gatewayProfile{GatewayURL: url, KeyRef: ref})
		},
	}
	cmd.Flags().String("gateway-url", "", "Gateway base URL")
	cmd.Flags().String("name", "default", "Profile name")
	cmd.Flags().Bool("key-stdin", false, "Read the API key from stdin")
	return cmd
}

func logoutCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "logout",
		Short: "Delete a stored API key and profile",
		RunE: func(cmd *cobra.Command, _ []string) error {
			name, _ := cmd.Flags().GetString("name")
			if name == "" {
				name = "default"
			}
			home, err := credentialHome()
			if err != nil {
				return err
			}
			store, err := credentialOpen(home)
			if err != nil {
				return err
			}
			if err := store.Delete(cmd.Context(), name); err != nil && !os.IsNotExist(err) {
				return err
			}
			_ = os.RemoveAll(filepath.Join(home, ".yabanin", "sessions"))
			return deleteProfile(home, name)
		},
	}
	cmd.Flags().String("name", "default", "Profile name")
	return cmd
}

func keyPrintCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "print",
		Short: "Print the API key without a trailing newline",
		RunE:  printAPIKey,
	}
	cmd.Flags().String("name", "default", "Profile name")
	return cmd
}

func printAPIKey(cmd *cobra.Command, _ []string) error {
	key := cictx.OSEnv{}.Getenv("YABANIN_API_KEY")
	if key != "" {
		_, err := io.WriteString(cmd.OutOrStdout(), key)
		return err
	}
	name, _ := cmd.Flags().GetString("name")
	if name == "" {
		name = "default"
	}
	home, err := credentialHome()
	if err != nil {
		return err
	}
	store, err := credentialOpen(home)
	if err != nil {
		return err
	}
	key, err = store.Get(cmd.Context(), name)
	if err != nil {
		return err
	}
	_, err = io.WriteString(cmd.OutOrStdout(), key)
	return err
}

func keyCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "key", Short: "Print the stored API key"}
	cmd.AddCommand(keyPrintCmd())
	return cmd
}

var credentialHome = os.UserHomeDir

var credentialOpen = func(home string) (credstore.Store, error) {
	return credstore.Open(home, nil)
}

func readAPIKey(cmd *cobra.Command, fromStdin bool) (string, error) {
	in := cmd.InOrStdin()
	if fromStdin {
		body, err := io.ReadAll(in)
		if err != nil {
			return "", err
		}
		return strings.TrimRight(string(body), "\r\n"), nil
	}
	file, ok := in.(*os.File)
	if !ok || !term.IsTerminal(int(file.Fd())) {
		return "", errors.New("pass the API key with --key-stdin")
	}
	_, _ = fmt.Fprint(cmd.ErrOrStderr(), "API key: ")
	body, err := term.ReadPassword(int(file.Fd()))
	_, _ = fmt.Fprintln(cmd.ErrOrStderr())
	if err != nil {
		return "", err
	}
	return string(body), nil
}

func checkGatewayKey(ctx context.Context, base, key string) (string, error) {
	status, err := gatewayStatus(ctx, strings.TrimRight(base, "/")+"/v1/models", key)
	if err != nil {
		return "", err
	}
	switch status {
	case http.StatusOK:
		return "", nil
	case http.StatusUnauthorized:
		return "", errors.New("invalid API key")
	case http.StatusNotFound:
		health, err := gatewayStatus(ctx, strings.TrimRight(base, "/")+"/healthz", key)
		if err != nil {
			return "", err
		}
		if health == http.StatusOK {
			return "gateway without /v1/models (RM-13)", nil
		}
		return "", fmt.Errorf("gateway health check returned %d", health)
	default:
		return "", fmt.Errorf("gateway returned %d", status)
	}
}

func gatewayStatus(ctx context.Context, endpoint, key string) (int, error) {
	if ctx == nil {
		return 0, errors.New("nil context")
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return 0, err
	}
	if key != "" {
		req.Header.Set("Authorization", "Bearer "+key)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, err
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, nil
}

type gatewayProfile struct {
	GatewayURL string            `json:"gateway_url"`
	KeyRef     string            `json:"key_ref"`
	Labels     map[string]string `json:"labels,omitempty"`
}

type harnessToolConfig struct {
	Session bool   `json:"session"`
	TTL     string `json:"ttl,omitempty"`
}

type clientConfig struct {
	Version  int                          `json:"version"`
	Profiles map[string]gatewayProfile    `json:"profiles"`
	Harness  map[string]harnessToolConfig `json:"harness,omitempty"`
}

func configPath(home string) string {
	return filepath.Join(home, ".yabanin", "config.json")
}

func loadConfig(home string) (clientConfig, error) {
	body, err := os.ReadFile(configPath(home))
	if err != nil {
		if os.IsNotExist(err) {
			return clientConfig{Version: 1, Profiles: map[string]gatewayProfile{}}, nil
		}
		return clientConfig{}, err
	}
	var cfg clientConfig
	if err := json.Unmarshal(body, &cfg); err != nil {
		return clientConfig{}, err
	}
	if cfg.Profiles == nil {
		cfg.Profiles = map[string]gatewayProfile{}
	}
	return cfg, nil
}

func saveProfile(home, name string, profile gatewayProfile) error {
	cfg, err := loadConfig(home)
	if err != nil {
		return err
	}
	cfg.Version = 1
	cfg.Profiles[name] = profile
	return writeConfig(home, cfg)
}

// GatewayURL returns YABANIN_GATEWAY_URL when set, otherwise the stored URL.
func GatewayURL(stored string) string {
	env := (cictx.OSEnv{}).Getenv("YABANIN_GATEWAY_URL")
	if env != "" {
		return env
	}
	return stored
}

func deleteProfile(home, name string) error {
	cfg, err := loadConfig(home)
	if err != nil {
		return err
	}
	delete(cfg.Profiles, name)
	return writeConfig(home, cfg)
}

func writeConfig(home string, cfg clientConfig) error {
	dir := filepath.Join(home, ".yabanin")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	body, err := json.Marshal(cfg)
	if err != nil {
		return err
	}
	return os.WriteFile(configPath(home), body, 0o600)
}
