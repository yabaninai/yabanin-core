package trcli

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/reireirei/yabanin/pkg/adminstore"
	"github.com/reireirei/yabanin/pkg/pricing"
)

func pricingSyncCmd() *cobra.Command {
	var catalogPath string
	var apply bool
	cmd := &cobra.Command{
		Use:   "sync",
		Short: "Match the model registry to a price catalog",
		Long: `Print a registry-to-catalog map and, with --apply, import it.

The gateway reads models_pricing through DBPricer, which caches prices for
5 minutes. After an apply, new prices are visible within that window.`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			baseURL, _ := cmd.Flags().GetString("admin-url")
			apiKey, _ := cmd.Flags().GetString("api-key")
			if apiKey == "" {
				return fmt.Errorf("--api-key required (send it as the X-Admin-Key service key)")
			}
			raw, err := os.ReadFile(catalogPath) //nolint:gosec // G304: path is the operator's --catalog file
			if err != nil {
				return err
			}
			var catalog pricing.PriceFile
			if err := json.Unmarshal(raw, &catalog); err != nil {
				return fmt.Errorf("parse catalog: %w", err)
			}
			client := NewAdminClient(baseURL, apiKey)
			models, err := client.ListRegistryModels(cmd.Context())
			if err != nil {
				return err
			}
			rows, ambiguous := buildPricingSync(models, catalog)
			printPricingSync(cmd.OutOrStdout(), rows, ambiguous)
			if !apply {
				if _, err := fmt.Fprintln(cmd.OutOrStdout(), "dry-run only; pass --apply to write prices"); err != nil {
					return err
				}
				return nil
			}
			var mappings []adminstore.CatalogPriceMap
			for _, row := range rows {
				if row.CatalogProvider == "" {
					continue
				}
				mappings = append(mappings, adminstore.CatalogPriceMap{
					RegistryProvider: row.RegistryProvider,
					RegistryModel:    row.RegistryModel,
					CatalogProvider:  row.CatalogProvider,
					CatalogModel:     row.CatalogModel,
				})
			}
			result, err := client.ImportPricing(cmd.Context(), catalog, mappings, true)
			if err != nil {
				return err
			}
			if _, err := fmt.Fprintf(cmd.OutOrStdout(), "applied created=%d unchanged=%d unmatched=%d errors=%d\n",
				result.Created, result.Unchanged, len(result.Unmatched), len(result.Errors)); err != nil {
				return err
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&catalogPath, "catalog", "", "PriceFile JSON path")
	cmd.Flags().BoolVar(&apply, "apply", false, "Write matched prices (default is a dry run)")
	_ = cmd.MarkFlagRequired("catalog")
	return cmd
}

type pricingSyncRow struct {
	RegistryProvider string
	RegistryModel    string
	CatalogProvider  string
	CatalogModel     string
	Note             string
}

type pricingSyncAmbiguity struct {
	RegistryProvider string
	RegistryModel    string
	Candidates       []string
}

func buildPricingSync(registry []RegistryModel, catalog pricing.PriceFile) ([]pricingSyncRow, []pricingSyncAmbiguity) {
	exact := make(map[string]pricing.PriceFileModel, len(catalog.Models))
	byName := make(map[string][]pricing.PriceFileModel)
	for _, m := range catalog.Models {
		exact[m.Provider+"\x00"+m.Model] = m
		byName[m.Model] = append(byName[m.Model], m)
	}
	var rows []pricingSyncRow
	var ambiguous []pricingSyncAmbiguity
	for _, reg := range registry {
		provider := strings.ToLower(reg.Provider)
		if _, local := localPricingProviders[provider]; local {
			rows = append(rows, pricingSyncRow{RegistryProvider: reg.Provider, RegistryModel: reg.ModelName, Note: "skipped local provider"})
			continue
		}
		if m, ok := exact[provider+"\x00"+reg.ModelName]; ok {
			rows = append(rows, pricingSyncRow{RegistryProvider: reg.Provider, RegistryModel: reg.ModelName, CatalogProvider: m.Provider, CatalogModel: m.Model, Note: "exact"})
			continue
		}
		if provider == "openai-compat" {
			hits := byName[reg.ModelName]
			switch len(hits) {
			case 0:
				rows = append(rows, pricingSyncRow{RegistryProvider: reg.Provider, RegistryModel: reg.ModelName, Note: "unmatched"})
			case 1:
				rows = append(rows, pricingSyncRow{RegistryProvider: reg.Provider, RegistryModel: reg.ModelName, CatalogProvider: hits[0].Provider, CatalogModel: hits[0].Model, Note: "model name"})
			default:
				names := make([]string, len(hits))
				for i, h := range hits {
					names[i] = h.Provider + "/" + h.Model
				}
				sort.Strings(names)
				ambiguous = append(ambiguous, pricingSyncAmbiguity{RegistryProvider: reg.Provider, RegistryModel: reg.ModelName, Candidates: names})
			}
			continue
		}
		rows = append(rows, pricingSyncRow{RegistryProvider: reg.Provider, RegistryModel: reg.ModelName, Note: "unmatched"})
	}
	return rows, ambiguous
}

var localPricingProviders = map[string]struct{}{
	"vllm": {}, "ollama": {}, "tgi": {}, "llamacpp": {},
}

func printPricingSync(w io.Writer, rows []pricingSyncRow, ambiguous []pricingSyncAmbiguity) {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "registry_provider\tregistry_model\tcatalog_provider\tcatalog_model\tnote")
	for _, row := range rows {
		_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", row.RegistryProvider, row.RegistryModel, row.CatalogProvider, row.CatalogModel, row.Note)
	}
	_ = tw.Flush()
	for _, item := range ambiguous {
		_, _ = fmt.Fprintf(w, "ambiguous %s/%s: %s\n", item.RegistryProvider, item.RegistryModel, strings.Join(item.Candidates, ", "))
	}
}

// RegistryModel is one row of GET /api/models.
type RegistryModel struct {
	ModelName string `json:"model_name"`
	Provider  string `json:"provider"`
}

// ListRegistryModels reads every page of the admin model registry.
func (c *AdminClient) ListRegistryModels(ctx context.Context) ([]RegistryModel, error) {
	var all []RegistryModel
	for page := 1; ; page++ {
		var out struct {
			Data       []RegistryModel `json:"data"`
			Pagination struct {
				Page       int `json:"page"`
				TotalPages int `json:"total_pages"`
			} `json:"pagination"`
		}
		q := url.Values{}
		q.Set("page", fmt.Sprint(page))
		q.Set("page_size", "200")
		if err := c.getJSON(ctx, "/api/models", q, &out); err != nil {
			return nil, err
		}
		all = append(all, out.Data...)
		if len(out.Data) == 0 || out.Pagination.TotalPages == 0 || out.Pagination.Page >= out.Pagination.TotalPages {
			break
		}
	}
	return all, nil
}

// ImportPricing posts the catalog map with mode=apply.
func (c *AdminClient) ImportPricing(ctx context.Context, catalog pricing.PriceFile, mappings []adminstore.CatalogPriceMap, onlyMapped bool) (adminstore.CatalogImportResult, error) {
	body, err := json.Marshal(map[string]any{
		"catalog":     catalog,
		"map":         mappings,
		"only_mapped": onlyMapped,
	})
	if err != nil {
		return adminstore.CatalogImportResult{}, err
	}
	var out adminstore.CatalogImportResult
	if err := c.postJSON(ctx, "/api/pricing/import?mode=apply", body, &out); err != nil {
		return adminstore.CatalogImportResult{}, err
	}
	return out, nil
}

func (c *AdminClient) postJSON(ctx context.Context, path string, body []byte, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("X-Admin-Key", c.apiKey)
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.httpc.Do(req)
	if err != nil {
		return fmt.Errorf("admin service unreachable at %s: %w", c.baseURL, err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("admin service returned status %d from %s", resp.StatusCode, path)
	}
	if out == nil {
		return nil
	}
	return json.Unmarshal(raw, out)
}
