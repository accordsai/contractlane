package render

import (
	"strings"
	"testing"

	"contractlane/pkg/domain"
)

func TestRenderDeterministic(t *testing.T) {
	defs := []domain.VariableDefinition{
		{Key: "a", Required: true},
		{Key: "b", Required: false},
	}
	template := "A={{a}}\nB={{b}}\n"
	values := map[string]string{"a": "x", "b": "y"}

	r1, miss1, err := Render(template, values, defs, "text")
	if err != nil {
		t.Fatalf("render err: %v", err)
	}
	r2, miss2, err := Render(template, values, defs, "text")
	if err != nil {
		t.Fatalf("render err: %v", err)
	}
	if len(miss1) != 0 || len(miss2) != 0 {
		t.Fatalf("expected no missing keys")
	}
	if r1 != r2 {
		t.Fatalf("expected deterministic output")
	}
}

func TestVariableOrderDoesNotAffectHashes(t *testing.T) {
	a := map[string]string{"b": "2", "a": "1"}
	b := map[string]string{"a": "1", "b": "2"}
	ha, _, err := HashVariablesSnapshot(a)
	if err != nil {
		t.Fatalf("hash err: %v", err)
	}
	hb, _, err := HashVariablesSnapshot(b)
	if err != nil {
		t.Fatalf("hash err: %v", err)
	}
	if ha != hb {
		t.Fatalf("expected equal hashes for equivalent maps")
	}
}

func TestMissingRequiredVariables(t *testing.T) {
	defs := []domain.VariableDefinition{{Key: "required_key", Required: true}}
	_, missing, err := Render("{{required_key}}", map[string]string{}, defs, "text")
	if err != nil {
		t.Fatalf("render err: %v", err)
	}
	if len(missing) != 1 || missing[0] != "required_key" {
		t.Fatalf("unexpected missing keys: %#v", missing)
	}
}

func TestHTMLRenderEscapesVariables(t *testing.T) {
	defs := []domain.VariableDefinition{{Key: "k", Required: true}}
	out, missing, err := Render("{{k}}", map[string]string{"k": `<script>alert("x")</script>`}, defs, "html")
	if err != nil {
		t.Fatalf("render err: %v", err)
	}
	if len(missing) != 0 {
		t.Fatalf("unexpected missing keys: %#v", missing)
	}
	if strings.Contains(out, "<script>") {
		t.Fatalf("script tag should be escaped: %s", out)
	}
	if !strings.Contains(out, "&lt;script&gt;") {
		t.Fatalf("escaped script tag expected: %s", out)
	}
}

func TestNormalizeTextRules(t *testing.T) {
	in := "a  \r\nb\t\r\n\r\n"
	got := NormalizeText(in)
	want := "a\nb\n"
	if got != want {
		t.Fatalf("normalize mismatch got=%q want=%q", got, want)
	}
}
