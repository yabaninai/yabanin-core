package trcli

import (
	"fmt"
	"os"
	"time"

	"github.com/reireirei/yabanin/pkg/cictx"
	"github.com/reireirei/yabanin/pkg/labels"
	"github.com/spf13/cobra"
)

func saveHarnessSession(home string, tools []string, ttl string) error {
	cfg, err := loadConfig(home)
	if err != nil {
		return err
	}
	if cfg.Harness == nil {
		cfg.Harness = map[string]harnessToolConfig{}
	}
	for _, tool := range tools {
		cfg.Harness[tool] = harnessToolConfig{Session: true, TTL: ttl}
	}
	return writeConfig(home, cfg)
}

func harnessKey(cmd *cobra.Command, tool string) (string, error) {
	parent, err := lookupAPIKey(cmd.Context(), "default")
	if err != nil {
		return "", err
	}
	home, err := credentialHome()
	if err != nil {
		return "", err
	}
	cfg, err := loadConfig(home)
	if err != nil {
		return "", err
	}
	spec, ok := cfg.Harness[tool]
	if !ok || !spec.Session {
		return parent, nil
	}
	now := time.Now().UTC()
	sweepSessionCache(home, now)
	dir, err := os.Getwd()
	if err != nil {
		return parentKeyFallback(cmd, parent, "session labels unavailable; using the parent key")
	}
	set, err := harnessSessionLabels(cmd, dir, cfg.Profiles["default"])
	if err != nil {
		return parentKeyFallback(cmd, parent, "session labels unavailable; using the parent key")
	}
	gateway := GatewayURL(cfg.Profiles["default"].GatewayURL)
	if gateway == "" {
		gateway = os.Getenv("YABANIN_GATEWAY_URL")
	}
	path, err := sessionCachePath(home, tool, gateway, set)
	if err != nil {
		return parentKeyFallback(cmd, parent, "session cache unavailable; using the parent key")
	}
	if cached, ok := readSessionCache(path, now); ok {
		return cached.Key, nil
	}
	ttl := spec.TTL
	if ttl == "" {
		ttl = "8h"
	}
	seconds, err := parseTTLSeconds(ttl)
	if err != nil {
		return parentKeyFallback(cmd, parent, "session ttl invalid; using the parent key")
	}
	minted, err := mintSessionKey(cmd.Context(), gateway, parent, sessionMintBody{
		Name: tool, TTL: seconds, Labels: set, Lock: true,
	})
	if err != nil {
		return parentKeyFallback(cmd, parent, "session key mint failed; using the parent key")
	}
	_ = writeSessionCache(path, cachedSession{
		ID: minted.ID, Key: minted.Key, ExpiresAt: minted.ExpiresAt, Labels: minted.Labels,
	})
	return minted.Key, nil
}

func parentKeyFallback(cmd *cobra.Command, parent, msg string) (string, error) {
	_, _ = fmt.Fprintln(cmd.ErrOrStderr(), msg)
	return parent, nil
}

func harnessSessionLabels(cmd *cobra.Command, dir string, profile gatewayProfile) (labels.Set, error) {
	env := cictx.OSEnv{}
	detected, err := cictx.Detect(cmd.Context(), env, cictx.ExecRunner{}, dir)
	if err != nil {
		return nil, err
	}
	found, err := cictx.FindProfile(env, dir, "")
	if err != nil {
		return nil, err
	}
	var loaded *cictx.Profile
	if found != "" {
		loaded, err = cictx.LoadProfile(found)
		if err != nil {
			return nil, err
		}
	}
	flags := labels.Set{}
	for key, value := range profile.Labels {
		flags[key] = value
	}
	set, _, _, err := cictx.Build(detected, loaded, env, flags)
	return set, err
}
