// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"strings"
)

type ingestBatch struct {
	opts  IngestOptions
	stats IngestStats
	rows  []Record
}

// IngestReader reads a log once. The optional name supplies a format hint;
// unnamed streams need neither seeking nor a temporary copy of raw prompts.
func IngestReader(ctx context.Context, r io.Reader, name string, opts IngestOptions) ([]Record, IngestStats, error) {
	if opts.MaxRecords <= 0 {
		opts.MaxRecords = DefaultMaxRecords
	}
	b := ingestBatch{opts: opts, stats: IngestStats{Cap: opts.MaxRecords}}
	s := bufio.NewScanner(r)
	s.Buffer(make([]byte, 64*1024), 4*1024*1024)
	if err := b.read(ctx, s, inputFormat(name, opts.Format)); err != nil {
		return nil, IngestStats{}, err
	}
	b.stats.Parsed = len(b.rows)
	return b.rows, b.stats, nil
}

func inputFormat(name, format string) string {
	if format != "" && format != "auto" {
		return format
	}
	switch strings.ToLower(filepath.Ext(name)) {
	case ".csv":
		return "csv"
	case ".json", ".jsonl", ".ndjson":
		return "jsonl"
	default:
		return "auto"
	}
}

func (b *ingestBatch) read(ctx context.Context, s *bufio.Scanner, format string) error {
	switch format {
	case "csv", "tokenrouter-csv", "yabanin-csv":
		return b.readCSV(ctx, s, "")
	case "openai-jsonl":
		return b.readJSONL(ctx, s, parseOpenAIJSONLLine)
	case "jsonl":
		return b.readJSONL(ctx, s, parseAuditJSON)
	case "auto":
		return b.readSniffed(ctx, s, parseAuditJSON)
	case "tokenrouter", "yabanin":
		return b.readSniffed(ctx, s, parseTokenRouterLine)
	default:
		return fmt.Errorf("unsupported format %q", format)
	}
}

func (b *ingestBatch) readSniffed(ctx context.Context, s *bufio.Scanner, parse func(string) (Record, error)) error {
	for s.Scan() {
		if err := ctx.Err(); err != nil {
			return err
		}
		line := s.Text()
		text := strings.TrimSpace(line)
		if text == "" {
			continue
		}
		if !strings.HasPrefix(text, "{") {
			return b.readCSV(ctx, s, line+"\n")
		}
		b.add(parse(text))
		if b.stats.WasTruncated {
			return nil
		}
		return b.readJSONL(ctx, s, parse)
	}
	return s.Err()
}

func parseAuditJSON(line string) (Record, error) {
	r, err := parseOpenAIJSONLLine(line)
	if err == nil && !hasAuditData(r) {
		return parseTokenRouterLine(line)
	}
	return r, err
}

func hasAuditData(r Record) bool {
	return r.Model != "" || r.Prompt != "" || r.PromptTokens != 0 || r.CompletionTokens != 0
}

func (b *ingestBatch) add(r Record, err error) {
	if err == nil && !hasAuditData(r) {
		err = errors.New("line carried no model, prompt, or token counts")
	}
	if err != nil {
		b.stats.ParseErrorCount++
		if len(b.stats.ParseErrorExamples) < maxReportedParseErrors {
			b.stats.ParseErrorExamples = append(b.stats.ParseErrorExamples, err.Error())
		}
		return
	}
	r = b.opts.prepare(r)
	if !r.TokensEstimated && (r.PromptTokens > 0 || r.CompletionTokens > 0) {
		b.stats.RealTokenCount++
	}
	if !r.Timestamp.IsZero() {
		b.stats.TimestampedCount++
	}
	b.rows = append(b.rows, r)
	b.stats.WasTruncated = len(b.rows) == b.opts.MaxRecords
}

func (o IngestOptions) prepare(r Record) Record {
	if o.Provider != "" {
		r.Provider = o.Provider
	} else if r.Provider == "" {
		r.Provider = InferProvider(r.Model)
	}
	if o.NoPrompts {
		r.PromptHash = promptHashFor(r)
		// An unavailable key is a miss, not a common identity for unknown prompts.
		r.exactCacheKey, _ = exactKey(r)
		r.Prompt = ""
	}
	return r
}
