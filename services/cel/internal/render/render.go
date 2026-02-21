package render

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html"
	"regexp"
	"sort"
	"strings"

	"github.com/accordsai/contractlane/pkg/domain"
)

const DeterminismVersion = "render-v1"

type TemplateSpec struct {
	TemplateID      string
	TemplateVersion string
	DisplayName     string
	Variables       []domain.VariableDefinition
}

var placeholderRE = regexp.MustCompile(`\{\{\s*([a-zA-Z0-9_]+)\s*\}\}`)

func BuildCanonicalTemplateText(spec TemplateSpec) string {
	name := strings.TrimSpace(spec.DisplayName)
	if name == "" {
		name = strings.TrimSpace(spec.TemplateID)
	}
	vars := append([]domain.VariableDefinition(nil), spec.Variables...)
	sort.Slice(vars, func(i, j int) bool { return string(vars[i].Key) < string(vars[j].Key) })

	var b strings.Builder
	if name != "" {
		b.WriteString(name)
		b.WriteString("\n")
	}
	if strings.TrimSpace(spec.TemplateVersion) != "" {
		b.WriteString("Version: ")
		b.WriteString(strings.TrimSpace(spec.TemplateVersion))
		b.WriteString("\n")
	}
	b.WriteString("\n")
	b.WriteString("Terms\n")
	for _, v := range vars {
		b.WriteString("- ")
		b.WriteString(string(v.Key))
		b.WriteString(": {{")
		b.WriteString(string(v.Key))
		b.WriteString("}}\n")
	}
	return NormalizeText(b.String())
}

func Render(templateText string, values map[string]string, definitions []domain.VariableDefinition, format string) (rendered string, missingRequired []string, err error) {
	required := map[string]bool{}
	for _, d := range definitions {
		if d.Required {
			required[string(d.Key)] = true
		}
	}
	missingSet := map[string]struct{}{}
	raw := placeholderRE.ReplaceAllStringFunc(templateText, func(m string) string {
		match := placeholderRE.FindStringSubmatch(m)
		if len(match) != 2 {
			return ""
		}
		key := match[1]
		if v, ok := values[key]; ok {
			return v
		}
		if required[key] {
			missingSet[key] = struct{}{}
		}
		return ""
	})

	missingRequired = make([]string, 0, len(missingSet))
	for k := range missingSet {
		missingRequired = append(missingRequired, k)
	}
	sort.Strings(missingRequired)
	if len(missingRequired) > 0 {
		return "", missingRequired, nil
	}

	text := NormalizeText(raw)
	switch format {
	case "text":
		return text, nil, nil
	case "html":
		return textToSafeHTML(text), nil, nil
	default:
		return "", nil, fmt.Errorf("unsupported format: %s", format)
	}
}

func NormalizeText(in string) string {
	s := strings.ReplaceAll(in, "\r\n", "\n")
	s = strings.ReplaceAll(s, "\r", "\n")
	lines := strings.Split(s, "\n")
	for i := range lines {
		lines[i] = strings.TrimRight(lines[i], " \t")
	}
	for len(lines) > 0 && lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}
	out := strings.Join(lines, "\n")
	return out + "\n"
}

func HashVariablesSnapshot(values map[string]string) (hash string, canonical []byte, err error) {
	canonical, err = canonicalJSON(values)
	if err != nil {
		return "", nil, err
	}
	return sha256Hex(canonical), canonical, nil
}

func HashRendered(rendered string) string {
	return sha256Hex([]byte(rendered))
}

func canonicalJSON(v any) ([]byte, error) {
	return json.Marshal(v)
}

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func textToSafeHTML(text string) string {
	trimmed := strings.TrimSuffix(text, "\n")
	if strings.TrimSpace(trimmed) == "" {
		return "<p></p>\n"
	}
	paragraphs := strings.Split(trimmed, "\n\n")
	out := make([]string, 0, len(paragraphs))
	for _, p := range paragraphs {
		escaped := html.EscapeString(p)
		escaped = strings.ReplaceAll(escaped, "\n", "<br>\n")
		out = append(out, "<p>"+escaped+"</p>")
	}
	return strings.Join(out, "\n") + "\n"
}
