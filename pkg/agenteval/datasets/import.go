package datasets

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// RowError identifies a source line and field without exposing source data.
type RowError struct {
	Row    int    `json:"row"`
	Column string `json:"column,omitempty"`
	Code   string `json:"code"`
}

func (e RowError) Error() string { return fmt.Sprintf("row %d column %s: %s", e.Row, e.Column, e.Code) }

// ImportError reports all recoverable row diagnostics. No partial revision is returned.
type ImportError struct{ Rows []RowError }

func (e *ImportError) Error() string {
	return fmt.Sprintf("invalid dataset transfer: %d row errors", len(e.Rows))
}

type transferRow struct {
	SchemaVersion int             `json:"schema_version"`
	DatasetID     string          `json:"dataset_id"`
	ID            string          `json:"id"`
	Payload       json.RawMessage `json:"payload"`
}

func readTransfer(r io.Reader) ([]byte, error) {
	if r == nil {
		return nil, ErrInvalidRevision
	}
	b, err := io.ReadAll(io.LimitReader(r, maxRevisionBytes+1))
	if err != nil {
		return nil, ErrInvalidRevision
	}
	if len(b) > maxRevisionBytes {
		return nil, ErrRevisionTooBig
	}
	return b, nil
}

type transferBuilder struct {
	revision Revision
	seen     map[string]bool
	rows     []RowError
	count    int
}

func newTransferBuilder() *transferBuilder {
	return &transferBuilder{revision: Revision{SchemaVersion: SchemaVersion}, seen: make(map[string]bool)}
}
func (b *transferBuilder) add(row transferRow, line int) {
	b.count++
	code, column := "", ""
	switch {
	case b.count > maxSamples:
		code = "too_many_samples"
	case row.SchemaVersion != SchemaVersion:
		code, column = "unsupported_schema", "schema_version"
	case strings.TrimSpace(row.DatasetID) == "":
		code, column = "missing_dataset_id", "dataset_id"
	case b.revision.DatasetID != "" && b.revision.DatasetID != row.DatasetID:
		code, column = "inconsistent_dataset_id", "dataset_id"
	case strings.TrimSpace(row.ID) == "":
		code, column = "missing_sample_id", "id"
	case b.seen[row.ID]:
		code, column = "duplicate_sample_id", "id"
	case validateUniqueJSONKeys(row.Payload) != nil:
		code, column = "invalid_payload", "payload"
	}
	if code != "" {
		b.rows = append(b.rows, RowError{Row: line, Column: column, Code: code})
		return
	}
	b.revision.DatasetID = row.DatasetID
	b.seen[row.ID] = true
	b.revision.Samples = append(b.revision.Samples, Sample{ID: row.ID, Payload: row.Payload})
}
func (b *transferBuilder) finish() (Revision, error) {
	if len(b.rows) != 0 {
		return Revision{}, &ImportError{Rows: b.rows}
	}
	if len(b.revision.Samples) == 0 {
		return Revision{}, &ImportError{Rows: []RowError{{Row: 1, Code: "empty_input"}}}
	}
	data, err := json.Marshal(b.revision)
	if err != nil {
		return Revision{}, ErrInvalidRevision
	}
	if len(data) > maxRevisionBytes {
		return Revision{}, ErrRevisionTooBig
	}
	return b.revision, nil
}

// ReadTransferJSONL imports strict versioned sample rows, bounded to 8 MiB.
func ReadTransferJSONL(r io.Reader) (Revision, error) {
	data, err := readTransfer(r)
	if err != nil {
		return Revision{}, err
	}
	b := newTransferBuilder()
	lineNumber := 0
	for line := range bytes.SplitSeq(bytes.TrimSuffix(data, []byte{'\n'}), []byte{'\n'}) {
		lineNumber++
		if lineNumber > maxSamples {
			b.rows = append(b.rows, RowError{Row: lineNumber, Code: "too_many_samples"})
			break
		}
		var row transferRow
		dec := json.NewDecoder(bytes.NewReader(line))
		dec.DisallowUnknownFields()
		if validateUniqueJSONKeys(line) != nil || dec.Decode(&row) != nil {
			b.rows = append(b.rows, RowError{Row: lineNumber, Code: "malformed_row"})
			continue
		}
		b.add(row, lineNumber)
	}
	return b.finish()
}

var transferHeader = []string{"schema_version", "dataset_id", "sample_id", "payload_json"}

// ReadTransferCSV imports the exact four-column versioned CSV format.
func ReadTransferCSV(r io.Reader) (Revision, error) {
	data, err := readTransfer(r)
	if err != nil {
		return Revision{}, err
	}
	b := newTransferBuilder()
	reader := csv.NewReader(bytes.NewReader(preserveQuotedCRLF(data)))
	header, err := reader.Read()
	if err != nil || len(header) != len(transferHeader) {
		return Revision{}, &ImportError{Rows: []RowError{{Row: 1, Code: "invalid_header"}}}
	}
	for i := range transferHeader {
		if header[i] != transferHeader[i] {
			return Revision{}, &ImportError{Rows: []RowError{{Row: 1, Code: "invalid_header"}}}
		}
	}
	for recordNumber := 1; ; recordNumber++ {
		record, err := reader.Read()
		if err == io.EOF {
			break
		}
		line := 1
		if parse, ok := err.(*csv.ParseError); ok {
			line = parse.StartLine
		} else if len(record) > 0 {
			line, _ = reader.FieldPos(0)
		}
		if recordNumber > maxSamples {
			b.rows = append(b.rows, RowError{Row: line, Code: "too_many_samples"})
			break
		}
		if err != nil {
			b.rows = append(b.rows, RowError{Row: line, Code: "malformed_row"})
			// Syntax errors can consume the rest of a quoted record; no guessed recovery.
			if !errors.Is(err, csv.ErrFieldCount) {
				break
			}
			continue
		}
		if len(record) != len(transferHeader) {
			b.rows = append(b.rows, RowError{Row: line, Code: "malformed_row"})
			continue
		}
		version, _ := strconv.Atoi(record[0])
		b.add(transferRow{SchemaVersion: version, DatasetID: unescapeCSVCell(record[1]), ID: unescapeCSVCell(record[2]), Payload: json.RawMessage(record[3])}, line)
	}
	return b.finish()
}

func formulaCell(s string) bool {
	t := strings.TrimLeft(s, " \t\r\n\v\f")
	prefix := s[:len(s)-len(t)]
	return strings.ContainsAny(prefix, "\t\r") || (len(t) > 0 && strings.ContainsRune("=+-@", rune(t[0])))
}

// encoding/csv normalizes CRLF even within quoted values. Double just those
// carriage returns before parsing so the original value survives normalization.
func preserveQuotedCRLF(data []byte) []byte {
	var out bytes.Buffer
	quoted := false
	for i := 0; i < len(data); i++ {
		if data[i] == '"' {
			if quoted && i+1 < len(data) && data[i+1] == '"' {
				out.WriteByte('"')
				out.WriteByte('"')
				i++
				continue
			}
			quoted = !quoted
		}
		if quoted && data[i] == '\r' && i+1 < len(data) && data[i+1] == '\n' {
			out.WriteByte('\r')
		}
		out.WriteByte(data[i])
	}
	return out.Bytes()
}
func escapeCSVCell(s string) string {
	if strings.HasPrefix(s, "'") || formulaCell(s) {
		return "'" + s
	}
	return s
}
func unescapeCSVCell(s string) string {
	if strings.HasPrefix(s, "'") && (strings.HasPrefix(s[1:], "'") || formulaCell(s[1:])) {
		return s[1:]
	}
	return s
}
