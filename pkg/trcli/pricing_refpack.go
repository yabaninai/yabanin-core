package trcli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/reireirei/yabanin/pkg/pricing"
)

// CORE-REF-03 offline reference-pack tooling. Every subcommand is
// hermetic: local files only, no network. pack wraps a sealed catalog in
// the pack envelope, verify re-checks both digests and the schema rules
// fail-closed, diff renders the canonical promotion diff, chain verifies
// a successor's supersedes pointer against a predecessor pack.

func pricingRefPackCmd() *cobra.Command {
	var catalogPath, outPath string
	var notices []string
	cmd := &cobra.Command{
		Use:   "pack",
		Short: "Wrap a sealed reference catalog into a verifiable pack envelope",
		RunE: func(cmd *cobra.Command, _ []string) error {
			body, err := os.ReadFile(catalogPath) //nolint:gosec // G304: path is the operator's --catalog snapshot, not a secret or a remote path
			if err != nil {
				return err
			}
			pack, err := pricing.BuildRefPack(body, notices)
			if err != nil {
				return err
			}
			envelope, err := pricing.MarshalRefPack(pack)
			if err != nil {
				return err
			}
			if outPath == "" {
				if _, err := cmd.OutOrStdout().Write(envelope); err != nil {
					return err
				}
				return nil
			}
			if err := os.WriteFile(outPath, envelope, 0o600); err != nil { //nolint:gosec // G703: outPath is the operator's --out path from a local CLI flag, not request input
				return err
			}
			_, cat, err := pricing.LoadRefPack(envelope)
			if err != nil {
				return err
			}
			_, err = fmt.Fprintf(cmd.ErrOrStderr(),
				"pack: version=%s catalog_digest=%s pack_sha256=%s bytes=%d\n",
				cat.Version, pack.CatalogDigest, pack.PackSHA256, len(envelope))
			return err
		},
	}
	cmd.Flags().StringVar(&catalogPath, "catalog", "", "sealed reference catalog JSON path")
	cmd.Flags().StringVar(&outPath, "out", "", "pack path (stdout when empty)")
	cmd.Flags().StringArrayVar(&notices, "notice", nil, "build notice, repeatable (sorted and deduped into the envelope)")
	_ = cmd.MarkFlagRequired("catalog")
	return cmd
}

func pricingRefVerifyCmd() *cobra.Command {
	var packPath string
	cmd := &cobra.Command{
		Use:   "verify",
		Short: "Verify a reference pack envelope offline (schema + both digests)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			body, err := os.ReadFile(packPath) //nolint:gosec // G304: path is the operator's --pack snapshot, not a secret or a remote path
			if err != nil {
				return err
			}
			pack, cat, err := pricing.LoadRefPack(body)
			if err != nil {
				return err
			}
			_, err = fmt.Fprintf(cmd.OutOrStdout(),
				"catalog: yabanin-catalog@%s %s sha256:%s\nmodels: %d\npack_sha256: %s\nschema_version: %d\n",
				cat.Version, cat.GeneratedAt, pack.CatalogDigest, len(cat.Models), pack.PackSHA256, pack.PackSchemaVersion)
			return err
		},
	}
	cmd.Flags().StringVar(&packPath, "pack", "", "reference pack JSON path")
	_ = cmd.MarkFlagRequired("pack")
	return cmd
}

func pricingRefDiffCmd() *cobra.Command {
	var oldPath, newPath string
	cmd := &cobra.Command{
		Use:   "diff",
		Short: "Render the canonical diff between two reference packs",
		RunE: func(cmd *cobra.Command, _ []string) error {
			oldBody, err := os.ReadFile(oldPath) //nolint:gosec // G304: operator-provided snapshot paths
			if err != nil {
				return err
			}
			newBody, err := os.ReadFile(newPath) //nolint:gosec // G304: operator-provided snapshot paths
			if err != nil {
				return err
			}
			// RefDiff compares catalog bodies; the CLI accepts whole pack
			// envelopes and diffs their embedded sealed catalogs.
			oldPack, _, err := pricing.LoadRefPack(oldBody)
			if err != nil {
				return fmt.Errorf("--old: %w", err)
			}
			newPack, _, err := pricing.LoadRefPack(newBody)
			if err != nil {
				return fmt.Errorf("--new: %w", err)
			}
			out, err := pricing.RefDiff(oldPack.Catalog, newPack.Catalog)
			if err != nil {
				return err
			}
			if _, err := fmt.Fprint(cmd.OutOrStdout(), out); err != nil {
				return err
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&oldPath, "old", "", "current reference pack JSON path")
	cmd.Flags().StringVar(&newPath, "new", "", "candidate reference pack JSON path")
	_ = cmd.MarkFlagRequired("old")
	_ = cmd.MarkFlagRequired("new")
	return cmd
}

func pricingRefChainCmd() *cobra.Command {
	var prevPath, nextPath string
	cmd := &cobra.Command{
		Use:   "chain",
		Short: "Verify a successor pack's supersedes pointer against its predecessor",
		RunE: func(cmd *cobra.Command, _ []string) error {
			prevBody, err := os.ReadFile(prevPath) //nolint:gosec // G304: operator-provided snapshot paths
			if err != nil {
				return err
			}
			nextBody, err := os.ReadFile(nextPath) //nolint:gosec // G304: operator-provided snapshot paths
			if err != nil {
				return err
			}
			if err := pricing.VerifyRefPackChain(prevBody, nextBody); err != nil {
				return err
			}
			_, err = fmt.Fprintln(cmd.OutOrStdout(), "chain: ok")
			return err
		},
	}
	cmd.Flags().StringVar(&prevPath, "prev", "", "predecessor reference pack JSON path")
	cmd.Flags().StringVar(&nextPath, "next", "", "successor reference pack JSON path")
	_ = cmd.MarkFlagRequired("prev")
	_ = cmd.MarkFlagRequired("next")
	return cmd
}
