package qualityeval

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestEvaluateStructuredVerdicts(t *testing.T) {
	input := `[
 {"id":"one","task_id":"extract","expected":{"a":1,"b":2},"baseline":{"status":"ok","output":{"a":1,"b":2}},"candidate":{"status":"ok","output":{"b":2,"a":1}}},
 {"id":"two","task_id":"extract","expected":{"a":1},"baseline":{"status":"ok","output":{"a":1}},"candidate":{"status":"missing"}},
 {"id":"three","task_id":"sort","expected":[1,2],"baseline":{"status":"error"},"candidate":{"status":"ok","output":[2,1]}}
 ]`
	report, err := Evaluate(strings.NewReader(input), 0.3)
	if err != nil {
		t.Fatal(err)
	}
	if report.Candidate != (Counts{Total: 3, Pass: 1, Fail: 1, Unknown: 1}) || report.Regressions != 1 || report.MeetsThreshold {
		t.Fatalf("unexpected assessment: %+v", report)
	}
	if len(report.Tasks) != 2 || report.Tasks[0].TaskID != "extract" {
		t.Fatalf("missing task aggregation: %+v", report.Tasks)
	}
	data, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "expected") || strings.Contains(string(data), "output") {
		t.Fatal("payload leaked")
	}
}
func TestRejectAmbiguousAndInvalidInput(t *testing.T) {
	valid := `[{"id":"one","task_id":"t","expected":{},"baseline":{"status":"missing"},"candidate":{"status":"ok","output":{}}}]`
	for _, input := range []string{"", `[]`, `null`, valid + `[]`, strings.Replace(valid, `"id":"one"`, `"id":"one","id":"two"`, 1), strings.Replace(valid, `"output":{}`, `"output":{"secret":1,"secret":2}`, 1), strings.Replace(valid, `"status":"ok"`, `"status":"bad"`, 1), strings.Replace(valid, `,"output":{}`, ``, 1), strings.Replace(valid, `"expected":{}`, `"expected":null`, 1), strings.Replace(valid, `"task_id":"t"`, `"task_id":"t","prompt":"secret"`, 1)} {
		if _, err := Evaluate(strings.NewReader(input), 1); err == nil {
			t.Fatal("invalid input accepted")
		}
	}
	report, err := Evaluate(strings.NewReader(valid), 1)
	if err != nil || !report.MeetsThreshold {
		t.Fatalf("valid input failed: %+v %v", report, err)
	}
	if _, err := Evaluate(strings.NewReader(valid), 1.1); err == nil {
		t.Fatal("invalid threshold accepted")
	}
}
func TestLargeNumbersAndTypesRemainDistinct(t *testing.T) {
	for _, output := range []string{`{"n":9007199254740992}`, `{"n":"9007199254740993"}`, `{"n":9007199254740993.0}`} {
		input := `[{"id":"one","task_id":"t","expected":{"n":9007199254740993},"baseline":{"status":"error"},"candidate":{"status":"ok","output":` + output + `}}]`
		report, err := Evaluate(strings.NewReader(input), 1)
		if err != nil {
			t.Fatal(err)
		}
		if report.Candidate.Fail != 1 {
			t.Fatal("distinct numeric value/type accepted")
		}
	}
}
