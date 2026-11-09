package datasets

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"io"
	"strconv"
)

func validateTransferRevision(revision Revision) error {
	data, err := json.Marshal(revision)
	if err != nil {
		return ErrInvalidRevision
	}
	_, _, err = ReadRevision(bytes.NewReader(data))
	return err
}

func writeTransfer(w io.Writer, data []byte) error {
	if len(data) > maxRevisionBytes {
		return ErrRevisionTooBig
	}
	if w == nil {
		return ErrInvalidRevision
	}
	n, err := w.Write(data)
	if err == nil && n != len(data) {
		return io.ErrShortWrite
	}
	return err
}

// WriteTransferJSONL validates before emitting deterministic versioned sample rows.
func WriteTransferJSONL(w io.Writer, revision Revision) error {
	if err := validateTransferRevision(revision); err != nil {
		return err
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	for _, sample := range revision.Samples {
		if err := enc.Encode(transferRow{SchemaVersion: SchemaVersion, DatasetID: revision.DatasetID, ID: sample.ID, Payload: sample.Payload}); err != nil {
			return err
		}
		if buf.Len() > maxRevisionBytes {
			return ErrRevisionTooBig
		}
	}
	return writeTransfer(w, buf.Bytes())
}

// WriteTransferCSV emits reversible formula-protected identifiers and object payloads.
func WriteTransferCSV(w io.Writer, revision Revision) error {
	if err := validateTransferRevision(revision); err != nil {
		return err
	}
	var buf bytes.Buffer
	writer := csv.NewWriter(&buf)
	if err := writer.Write(transferHeader); err != nil {
		return err
	}
	for _, sample := range revision.Samples {
		var payload bytes.Buffer
		if err := json.Compact(&payload, sample.Payload); err != nil {
			return ErrInvalidRevision
		}
		if err := writer.Write([]string{strconv.Itoa(SchemaVersion), escapeCSVCell(revision.DatasetID), escapeCSVCell(sample.ID), payload.String()}); err != nil {
			return err
		}
		if buf.Len() > maxRevisionBytes {
			return ErrRevisionTooBig
		}
	}
	writer.Flush()
	if err := writer.Error(); err != nil {
		return err
	}
	return writeTransfer(w, buf.Bytes())
}
