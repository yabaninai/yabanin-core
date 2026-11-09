package trcli

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/reireirei/yabanin/pkg/agenteval/datasets"
	"github.com/spf13/cobra"
)

func datasetCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "dataset", Short: "Import and export local versioned evaluation datasets"}
	cmd.AddCommand(datasetImportCmd(), datasetExportCmd())
	return cmd
}

func datasetImportCmd() *cobra.Command { return datasetTransferCmd(true) }
func datasetExportCmd() *cobra.Command { return datasetTransferCmd(false) }

func datasetTransferCmd(importing bool) *cobra.Command {
	var format, input, output string
	var preview bool
	name := "export"
	if importing {
		name = "import"
	}
	cmd := &cobra.Command{Use: name, Short: name + " a local dataset as JSONL or CSV", Args: cobra.NoArgs}
	cmd.Flags().StringVar(&format, "format", "", "Interchange format: jsonl or csv")
	cmd.Flags().StringVar(&input, "input", "", "Local input file")
	cmd.Flags().StringVar(&output, "output", "", "New local output file (existing files are preserved)")
	if importing {
		cmd.Flags().BoolVar(&preview, "preview", false, "Validate and show row diagnostics without writing a revision")
	}
	cmd.RunE = func(cmd *cobra.Command, _ []string) error {
		if format != "jsonl" && format != "csv" {
			return errors.New("format must be jsonl or csv")
		}
		if input == "" || (!preview && output == "") {
			return errors.New("input and output paths are required (preview needs only input)")
		}
		file, err := os.Open(input) //nolint:gosec // G304: --input is an explicit operator-selected local path.
		if err != nil {
			return errors.New("cannot open dataset input")
		}
		var revision datasets.Revision
		if importing {
			if format == "jsonl" {
				revision, err = datasets.ReadTransferJSONL(file)
			} else {
				revision, err = datasets.ReadTransferCSV(file)
			}
		} else {
			revision, _, err = datasets.ReadRevision(file)
		}
		closeErr := file.Close()
		if err != nil {
			if preview {
				var rowErrors *datasets.ImportError
				if errors.As(err, &rowErrors) {
					if encodeErr := json.NewEncoder(cmd.OutOrStdout()).Encode(rowErrors.Rows); encodeErr != nil {
						return encodeErr
					}
				}
			}
			return err
		}
		if closeErr != nil {
			return errors.New("cannot close dataset input")
		}
		if preview {
			_, err := fmt.Fprintf(cmd.OutOrStdout(), "valid samples=%d errors=0\n", len(revision.Samples))
			return err
		}
		var buf bytes.Buffer
		if importing {
			err = json.NewEncoder(&buf).Encode(revision)
		} else if format == "jsonl" {
			err = datasets.WriteTransferJSONL(&buf, revision)
		} else {
			err = datasets.WriteTransferCSV(&buf, revision)
		}
		if err != nil {
			return err
		}
		// A canonical revision includes one final newline; validate that final artifact too.
		if importing {
			if _, _, err := datasets.ReadRevision(bytes.NewReader(buf.Bytes())); err != nil {
				return err
			}
		}
		return createDatasetOutput(output, buf.Bytes())
	}
	return cmd
}

// Stage in the destination directory and publish by a no-clobber hard link.
// Incomplete writes never become visible at the requested destination.
func createDatasetOutput(path string, data []byte) (resultErr error) {
	return createDatasetOutputWithCleanup(path, data, os.Remove)
}

func createDatasetOutputWithCleanup(path string, data []byte, removeTemp func(string) error) (resultErr error) {
	file, err := os.CreateTemp(filepath.Dir(path), ".dataset-*")
	if err != nil {
		return errors.New("cannot create dataset output")
	}
	name := file.Name()
	published := false
	defer func() {
		if err := removeTemp(name); err != nil && !errors.Is(err, os.ErrNotExist) && !published {
			cleanupErr := errors.New("cannot remove temporary dataset output")
			resultErr = errors.Join(resultErr, cleanupErr)
		}
	}()
	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		return errors.New("cannot write dataset output")
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return errors.New("cannot sync dataset output")
	}
	if err := file.Close(); err != nil {
		return errors.New("cannot close dataset output")
	}
	if err := os.Link(name, path); err != nil {
		return errors.New("cannot publish dataset output: destination must be new and on a filesystem supporting hard links")
	}
	published = true
	return nil
}
