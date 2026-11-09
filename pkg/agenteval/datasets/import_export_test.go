package datasets

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

func TestTransferRoundTrip(t *testing.T) {
	samples := []struct {
		id      string
		csvCell string
	}{
		{id: "ordinary", csvCell: "ordinary"},
		{id: "=SUM(1,2)", csvCell: "'=SUM(1,2)"},
		{id: "+cmd", csvCell: "'+cmd"},
		{id: "-1", csvCell: "'-1"},
		{id: "@formula", csvCell: "'@formula"},
		{id: "\tformula", csvCell: "'\tformula"},
		{id: "\rformula", csvCell: "'\rformula"},
		{id: "  =formula", csvCell: "'  =formula"},
		{id: "'literal", csvCell: "''literal"},
		{id: "''two", csvCell: "'''two"},
		{id: "comma,\"quote\"\nline", csvCell: "comma,\"quote\"\nline"},
		// encoding/csv normalizes CRLF inside a quoted field; the transfer
		// reader roundtrip below separately asserts restoration of the ID.
		{id: "embedded\r\nline", csvCell: "embedded\nline"},
		{id: " \tformula", csvCell: "' \tformula"},
	}
	revision := Revision{SchemaVersion: 1, DatasetID: "  =dataset"}
	for _, sample := range samples {
		revision.Samples = append(revision.Samples, Sample{ID: sample.id, Payload: json.RawMessage(`{"text":"=formula","number":10000000000000001}`)})
	}
	for _, format := range []string{"jsonl", "csv"} {
		t.Run(format, func(t *testing.T) {
			var first, second bytes.Buffer
			write := WriteTransferJSONL
			read := ReadTransferJSONL
			if format == "csv" {
				write, read = WriteTransferCSV, ReadTransferCSV
			}
			if err := write(&first, revision); err != nil {
				t.Fatal(err)
			}
			if err := write(&second, revision); err != nil {
				t.Fatal(err)
			}
			if first.String() != second.String() {
				t.Fatal("export not deterministic")
			}
			got, err := read(&first)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, revision) {
				t.Fatalf("roundtrip mismatch: %#v", got)
			}
			if format == "csv" {
				r := csv.NewReader(&second)
				if _, err := r.Read(); err != nil {
					t.Fatal(err)
				}
				for _, sample := range samples {
					record, err := r.Read()
					if err != nil {
						t.Fatal(err)
					}
					if record[1] != "'  =dataset" {
						t.Fatalf("dataset ID cell = %q, want %q", record[1], "'  =dataset")
					}
					if record[2] != sample.csvCell {
						t.Fatalf("sample ID %q CSV cell = %q, want %q", sample.id, record[2], sample.csvCell)
					}
				}
			}
		})
	}
}

func TestTransferRejectsRowsWithoutPayloadDisclosure(t *testing.T) {
	good := `{"schema_version":1,"dataset_id":"demo","id":"a","payload":{"text":"private-row-content"}}`
	cases := map[string]string{
		"malformed":     good + "\n{private-row-content\n",
		"duplicate":     good + "\n" + good + "\n",
		"metadata":      good + "\n" + strings.Replace(good, `"demo"`, `"other"`, 1),
		"unknown":       strings.Replace(good, `"schema_version":1`, `"org_id":"foreign","schema_version":1`, 1),
		"payload":       strings.Replace(good, `{"text":"private-row-content"}`, `[]`, 1),
		"duplicate_key": strings.Replace(good, `"id":"a"`, `"id":"a","id":"b"`, 1),
		"trailing":      good + ` {}`,
		"empty":         "",
	}
	for name, input := range cases {
		t.Run(name, func(t *testing.T) {
			revision, err := ReadTransferJSONL(strings.NewReader(input))
			if err == nil || len(revision.Samples) != 0 {
				t.Fatal("partial/invalid import succeeded")
			}
			var rows *ImportError
			if !errors.As(err, &rows) {
				t.Fatalf("missing row diagnostics: %v", err)
			}
			encoded, marshalErr := json.Marshal(rows)
			if marshalErr != nil {
				t.Fatal(marshalErr)
			}
			if strings.Contains(string(encoded)+err.Error(), "private-row-content") {
				t.Fatal("payload disclosed")
			}
			if name == "malformed" && rows.Rows[0].Row != 2 {
				t.Fatalf("wrong physical line: %v", rows)
			}
		})
	}
	for _, input := range []string{"schema_version,dataset_id,sample_id,payload_json,org_id\n", "schema_version,dataset_id,sample_id,payload_json\n1,demo,a,not-json\n", "schema_version,dataset_id,sample_id,payload_json\n1,demo,a\n"} {
		if _, err := ReadTransferCSV(strings.NewReader(input)); err == nil {
			t.Fatal("bad CSV accepted")
		}
	}
}

func TestTransferRejectsNestedDuplicatePayloadKeys(t *testing.T) {
	payload := `{"nested":{"value":"first","value":"second"}}`
	jsonl := `{"schema_version":1,"dataset_id":"demo","id":"sample","payload":` + payload + "}\n"
	var csvInput bytes.Buffer
	csvWriter := csv.NewWriter(&csvInput)
	if err := csvWriter.Write(transferHeader); err != nil {
		t.Fatal(err)
	}
	if err := csvWriter.Write([]string{"1", "demo", "sample", payload}); err != nil {
		t.Fatal(err)
	}
	csvWriter.Flush()
	if err := csvWriter.Error(); err != nil {
		t.Fatal(err)
	}

	for _, test := range []struct {
		name  string
		input string
		read  func(io.Reader) (Revision, error)
		want  []RowError
	}{{"jsonl", jsonl, ReadTransferJSONL, []RowError{{Row: 1, Code: "malformed_row"}}}, {"csv", csvInput.String(), ReadTransferCSV, []RowError{{Row: 2, Column: "payload", Code: "invalid_payload"}}}} {
		t.Run(test.name, func(t *testing.T) {
			var firstRows []RowError
			for attempt := 0; attempt < 2; attempt++ {
				revision, err := test.read(strings.NewReader(test.input))
				if len(revision.Samples) != 0 {
					t.Fatalf("duplicate nested key returned a partial revision: %#v", revision)
				}
				var importErr *ImportError
				if !errors.As(err, &importErr) || !reflect.DeepEqual(importErr.Rows, test.want) {
					t.Fatalf("got error %v with rows %#v, want %#v", err, importErr, test.want)
				}
				encoded, marshalErr := json.Marshal(importErr.Rows)
				if marshalErr != nil {
					t.Fatal(marshalErr)
				}
				diagnostic := err.Error() + string(encoded)
				if strings.Contains(diagnostic, "first") || strings.Contains(diagnostic, "second") {
					t.Fatal("duplicate-key diagnostic disclosed payload contents")
				}
				if attempt == 0 {
					firstRows = append([]RowError(nil), importErr.Rows...)
				} else if !reflect.DeepEqual(importErr.Rows, firstRows) {
					t.Fatalf("retry diagnostics changed: first=%#v retry=%#v", firstRows, importErr.Rows)
				}
			}
		})
	}
}

func TestTransferCSVDuplicateSampleIDIsAllOrNothing(t *testing.T) {
	input := "schema_version,dataset_id,sample_id,payload_json\n" +
		"1,demo,repeat,{}\n" +
		"1,demo,repeat,{}\n"
	revision, err := ReadTransferCSV(strings.NewReader(input))
	if len(revision.Samples) != 0 {
		t.Fatalf("duplicate ID returned a partial revision: %#v", revision)
	}
	var importErr *ImportError
	want := []RowError{{Row: 3, Column: "id", Code: "duplicate_sample_id"}}
	if !errors.As(err, &importErr) || !reflect.DeepEqual(importErr.Rows, want) {
		t.Fatalf("got error %v, want duplicate_sample_id on CSV row 3", err)
	}
}

func TestTransferAcceptsExactlyTenThousandSamplesInBothFormats(t *testing.T) {
	const sampleLimit = 10_000
	for _, test := range []struct {
		name string
		read func(io.Reader) (Revision, error)
	}{
		{name: "jsonl", read: ReadTransferJSONL},
		{name: "csv", read: ReadTransferCSV},
	} {
		t.Run(test.name, func(t *testing.T) {
			var input strings.Builder
			if test.name == "csv" {
				input.WriteString("schema_version,dataset_id,sample_id,payload_json\n")
			}
			for i := 0; i < sampleLimit; i++ {
				if test.name == "jsonl" {
					fmt.Fprintf(&input, `{"schema_version":1,"dataset_id":"demo","id":"sample-%d","payload":{}}`+"\n", i)
				} else {
					fmt.Fprintf(&input, "1,demo,sample-%d,{}\n", i)
				}
			}
			revision, err := test.read(strings.NewReader(input.String()))
			if err != nil {
				t.Fatalf("exact sample limit rejected: %v", err)
			}
			if len(revision.Samples) != sampleLimit {
				t.Fatalf("exact-limit import returned %d samples, want %d", len(revision.Samples), sampleLimit)
			}
			if revision.Samples[0].ID != "sample-0" || revision.Samples[sampleLimit-1].ID != fmt.Sprintf("sample-%d", sampleLimit-1) {
				t.Fatalf("exact-limit import changed sample order: first=%q last=%q", revision.Samples[0].ID, revision.Samples[sampleLimit-1].ID)
			}
		})
	}
}

type transferReadFailure struct{ err error }

func (r transferReadFailure) Read([]byte) (int, error) { return 0, r.err }

type transferWriteFailure struct{ err error }

func (w transferWriteFailure) Write([]byte) (int, error) { return 0, w.err }

func TestTransferReaderAndWriterFailures(t *testing.T) {
	readFailure := errors.New("injected read failure")
	for _, read := range []func(io.Reader) (Revision, error){ReadTransferJSONL, ReadTransferCSV} {
		revision, err := read(transferReadFailure{err: readFailure})
		if !errors.Is(err, ErrInvalidRevision) || len(revision.Samples) != 0 {
			t.Fatalf("reader failure = (%#v, %v), want empty revision and ErrInvalidRevision", revision, err)
		}
	}

	writeFailure := errors.New("injected write failure")
	revision := Revision{SchemaVersion: SchemaVersion, DatasetID: "demo", Samples: []Sample{{ID: "sample", Payload: json.RawMessage(`{}`)}}}
	for _, write := range []func(io.Writer, Revision) error{WriteTransferJSONL, WriteTransferCSV} {
		if err := write(transferWriteFailure{err: writeFailure}, revision); !errors.Is(err, writeFailure) {
			t.Fatalf("writer failure = %v, want injected write failure", err)
		}
	}
}

func TestTransferCSVRejectsStructurallyInvalidHeaderWithoutPanic(t *testing.T) {
	input := "schema_version,dataset_id\x00sample_id,payload_json\n1,dataset,payload\n"
	revision, err := ReadTransferCSV(strings.NewReader(input))
	if len(revision.Samples) != 0 {
		t.Fatalf("invalid header returned a partial revision: %#v", revision)
	}
	var importErr *ImportError
	if !errors.As(err, &importErr) || !reflect.DeepEqual(importErr.Rows, []RowError{{Row: 1, Code: "invalid_header"}}) {
		t.Fatalf("got error %v, want invalid_header ImportError", err)
	}
}

func TestTransferCSVReportsPhysicalLines(t *testing.T) {
	const contractSampleLimit = 10_000
	const overflowPhysicalLine = 10_004
	for _, malformed := range []struct {
		name string
		row  string
	}{{name: "short", row: "1,dataset,short\n"}, {name: "long", row: "1,dataset,long,{},extra\n"}} {
		t.Run("malformed "+malformed.name+" row after multiline record", func(t *testing.T) {
			input := "schema_version,dataset_id,sample_id,payload_json\n" +
				"1,dataset,first,\"{\n\"\"x\"\":1\n}\"\n" + malformed.row
			revision, err := ReadTransferCSV(strings.NewReader(input))
			if len(revision.Samples) != 0 {
				t.Fatalf("malformed import returned a partial revision: %#v", revision)
			}
			var importErr *ImportError
			if !errors.As(err, &importErr) || !reflect.DeepEqual(importErr.Rows, []RowError{{Row: 5, Code: "malformed_row"}}) {
				t.Fatalf("got error %v, want malformed_row at physical line 5", err)
			}
		})
	}

	t.Run("limit after multiline record", func(t *testing.T) {
		var input strings.Builder
		input.WriteString("schema_version,dataset_id,sample_id,payload_json\n")
		input.WriteString("1,dataset,id-0,\"{\n\"\"x\"\":1\n}\"\n")
		for i := 1; i < contractSampleLimit; i++ {
			fmt.Fprintf(&input, "1,dataset,id-%d,{}\n", i)
		}
		input.WriteString("1,dataset,over-limit,{}\n")
		revision, err := ReadTransferCSV(strings.NewReader(input.String()))
		if len(revision.Samples) != 0 {
			t.Fatalf("over-limit import returned a partial revision: %#v", revision)
		}
		var importErr *ImportError
		want := []RowError{{Row: overflowPhysicalLine, Code: "too_many_samples"}}
		if !errors.As(err, &importErr) || !reflect.DeepEqual(importErr.Rows, want) {
			t.Fatalf("got error %v, want too_many_samples at physical line %d", err, overflowPhysicalLine)
		}
	})

	t.Run("malformed over-limit record after multiline record", func(t *testing.T) {
		var input strings.Builder
		input.WriteString("schema_version,dataset_id,sample_id,payload_json\n")
		input.WriteString("1,dataset,id-0,\"{\n\"\"x\"\":1\n}\"\n")
		for i := 1; i < contractSampleLimit; i++ {
			fmt.Fprintf(&input, "1,dataset,id-%d,{}\n", i)
		}
		input.WriteString("1,dataset,over-limit,\"unterminated\n")
		revision, err := ReadTransferCSV(strings.NewReader(input.String()))
		if len(revision.Samples) != 0 {
			t.Fatalf("malformed over-limit import returned a partial revision: %#v", revision)
		}
		var importErr *ImportError
		want := []RowError{{Row: overflowPhysicalLine, Code: "too_many_samples"}}
		if !errors.As(err, &importErr) || !reflect.DeepEqual(importErr.Rows, want) {
			t.Fatalf("got error %v, want too_many_samples at physical line %d", err, overflowPhysicalLine)
		}
	})
}

func TestTransferBounds(t *testing.T) {
	const contractInputLimit = 8 << 20
	for _, test := range []struct {
		name   string
		read   func(io.Reader) (Revision, error)
		prefix string
		suffix string
	}{
		{
			name:   "jsonl",
			read:   ReadTransferJSONL,
			prefix: `{"schema_version":1,"dataset_id":"demo","id":"first","payload":{}}` + "\n" + `{"schema_version":1,"dataset_id":"demo","id":"oversized","payload":{"pad":"`,
			suffix: "\"}}\n",
		},
		{
			name: "csv",
			read: ReadTransferCSV,
			prefix: "schema_version,dataset_id,sample_id,payload_json\n" +
				"1,demo,first,{}\n" + `1,demo,oversized,"{""pad"":""`,
			suffix: `""}"` + "\n",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			fillerSize := contractInputLimit + 1 - len(test.prefix) - len(test.suffix)
			if fillerSize <= 0 {
				t.Fatal("oversized fixture prefix exceeds the contract byte limit")
			}
			input := test.prefix + strings.Repeat("x", fillerSize) + test.suffix
			if len(input) != contractInputLimit+1 {
				t.Fatalf("oversized fixture has %d bytes, want %d", len(input), contractInputLimit+1)
			}
			revision, err := test.read(strings.NewReader(input))
			if !errors.Is(err, ErrRevisionTooBig) {
				t.Fatalf("oversized valid-prefix input error = %v, want ErrRevisionTooBig", err)
			}
			if !reflect.DeepEqual(revision, Revision{}) {
				t.Fatalf("over-limit input returned a partial revision: %#v", revision)
			}
		})
	}

	const contractSampleLimit = 10_000
	for _, test := range []struct {
		name string
		read func(io.Reader) (Revision, error)
	}{
		{name: "jsonl", read: ReadTransferJSONL},
		{name: "csv", read: ReadTransferCSV},
	} {
		t.Run(test.name+" sample limit", func(t *testing.T) {
			var input strings.Builder
			if test.name == "csv" {
				input.WriteString("schema_version,dataset_id,sample_id,payload_json\n")
			}
			for i := 0; i < contractSampleLimit+1; i++ {
				if test.name == "jsonl" {
					fmt.Fprintf(&input, `{"schema_version":1,"dataset_id":"demo","id":"sample-%d","payload":{}}`+"\n", i)
				} else {
					fmt.Fprintf(&input, "1,demo,sample-%d,{}\n", i)
				}
			}
			revision, err := test.read(strings.NewReader(input.String()))
			if !reflect.DeepEqual(revision, Revision{}) {
				t.Fatalf("over-limit input returned a partial revision: %#v", revision)
			}
			var importErr *ImportError
			row := contractSampleLimit + 1
			if test.name == "csv" {
				row++ // CSV header is physical line 1.
			}
			want := []RowError{{Row: row, Code: "too_many_samples"}}
			if !errors.As(err, &importErr) || !reflect.DeepEqual(importErr.Rows, want) {
				t.Fatalf("got error %v, want too_many_samples at physical row %d", err, row)
			}
		})
	}
}

func TestTransferExpandedExportIsAtomic(t *testing.T) {
	revision := Revision{SchemaVersion: 1, DatasetID: strings.Repeat("x", 10000)}
	for i := 0; i < 1000; i++ {
		revision.Samples = append(revision.Samples, Sample{ID: strconv.Itoa(i), Payload: json.RawMessage(`{}`)})
	}
	for _, write := range []func(io.Writer, Revision) error{WriteTransferJSONL, WriteTransferCSV} {
		var out bytes.Buffer
		if err := write(&out, revision); !errors.Is(err, ErrRevisionTooBig) {
			t.Fatalf("expanded export: %v", err)
		}
		if out.Len() != 0 {
			t.Fatal("oversized export emitted partial data")
		}
	}
}
