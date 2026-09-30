package rules

import (
	"fmt"
	"strconv"
	"strings"
)

// This file implements a deliberately small YAML subset parser sufficient for
// Spec-Guardian rule files. It supports nested mappings, sequences, quoted and
// plain scalars, inline [a, b] lists and {a: b} maps, comments, and document
// markers. Block scalars and anchors are intentionally unsupported; the CLI
// reports a clear error if it encounters unsupported syntax.

type yamlLine struct {
	indent int
	text   string
	num    int
}

// parseYAML parses a YAML document subset into Go values:
// map[string]any, []any, string, bool, int64, float64 or nil.
func parseYAML(src string) (any, error) {
	lines, err := yamlTokenize(src)
	if err != nil {
		return nil, err
	}
	if len(lines) == 0 {
		return map[string]any{}, nil
	}
	v, next, err := yamlParseBlock(lines, 0, lines[0].indent)
	if err != nil {
		return nil, err
	}
	if next != len(lines) {
		return nil, fmt.Errorf("yaml: unexpected indentation at line %d", lines[next].num)
	}
	return v, nil
}

func yamlTokenize(src string) ([]yamlLine, error) {
	var out []yamlLine
	for idx, raw := range strings.Split(src, "\n") {
		raw = strings.TrimRight(raw, " \t\r")
		trimmed := strings.TrimSpace(raw)
		if trimmed == "" || trimmed == "---" || trimmed == "..." || strings.HasPrefix(trimmed, "#") {
			continue
		}
		indent := 0
		for indent < len(raw) && raw[indent] == ' ' {
			indent++
		}
		if indent < len(raw) && raw[indent] == '\t' {
			return nil, fmt.Errorf("yaml: tabs are not allowed for indentation (line %d)", idx+1)
		}
		content := strings.TrimRight(stripInlineComment(raw[indent:]), " ")
		if strings.TrimSpace(content) == "" {
			continue
		}
		out = append(out, yamlLine{indent: indent, text: content, num: idx + 1})
	}
	return out, nil
}

func stripInlineComment(s string) string {
	inS, inD := false, false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch c {
		case '\'':
			if !inD {
				inS = !inS
			}
		case '"':
			if !inS {
				inD = !inD
			}
		case '#':
			if !inS && !inD && i > 0 && (s[i-1] == ' ' || s[i-1] == '\t') {
				return s[:i]
			}
		}
	}
	return s
}

func yamlIsSeqItem(text string) bool {
	return text == "-" || strings.HasPrefix(text, "- ")
}

func yamlParseBlock(ls []yamlLine, i, indent int) (any, int, error) {
	if i >= len(ls) {
		return nil, i, nil
	}
	if ls[i].indent > indent {
		indent = ls[i].indent
	}
	if yamlIsSeqItem(ls[i].text) {
		return yamlParseSeq(ls, i, indent)
	}
	return yamlParseMap(ls, i, indent)
}

func yamlParseSeq(ls []yamlLine, i, indent int) (any, int, error) {
	var arr []any
	for i < len(ls) && ls[i].indent == indent && yamlIsSeqItem(ls[i].text) {
		rest := strings.TrimSpace(strings.TrimPrefix(ls[i].text, "-"))
		i++
		if rest == "" {
			if i < len(ls) && ls[i].indent > indent {
				v, ni, err := yamlParseBlock(ls, i, ls[i].indent)
				if err != nil {
					return nil, i, err
				}
				arr = append(arr, v)
				i = ni
			} else {
				arr = append(arr, nil)
			}
			continue
		}
		if k, v, ok := yamlSplitKeyValue(rest); ok {
			m := map[string]any{}
			if v != "" {
				m[k] = yamlParseScalar(v)
			} else if i < len(ls) && ls[i].indent > indent {
				val, ni, err := yamlParseBlock(ls, i, ls[i].indent)
				if err != nil {
					return nil, i, err
				}
				m[k] = val
				i = ni
			} else {
				m[k] = nil
			}
			// Remaining keys of this sequence item's mapping.
			for i < len(ls) && ls[i].indent > indent {
				sub, ni, err := yamlParseMap(ls, i, ls[i].indent)
				if err != nil {
					return nil, i, err
				}
				if sm, ok := sub.(map[string]any); ok {
					for kk, vv := range sm {
						m[kk] = vv
					}
				}
				i = ni
			}
			arr = append(arr, m)
			continue
		}
		arr = append(arr, yamlParseScalar(rest))
	}
	return arr, i, nil
}

func yamlParseMap(ls []yamlLine, i, indent int) (any, int, error) {
	m := map[string]any{}
	for i < len(ls) && ls[i].indent == indent {
		if yamlIsSeqItem(ls[i].text) {
			break
		}
		k, v, ok := yamlSplitKeyValue(ls[i].text)
		if !ok {
			return nil, i, fmt.Errorf("yaml: line %d: expected \"key: value\"", ls[i].num)
		}
		i++
		if v != "" {
			m[k] = yamlParseScalar(v)
			continue
		}
		if i < len(ls) && ls[i].indent > indent {
			val, ni, err := yamlParseBlock(ls, i, ls[i].indent)
			if err != nil {
				return nil, i, err
			}
			m[k] = val
			i = ni
		} else {
			m[k] = nil
		}
	}
	return m, i, nil
}

func yamlSplitKeyValue(s string) (string, string, bool) {
	inS, inD := false, false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch c {
		case '\'':
			if !inD {
				inS = !inS
			}
		case '"':
			if !inS {
				inD = !inD
			}
		case ':':
			if inS || inD {
				continue
			}
			if i+1 == len(s) || s[i+1] == ' ' || s[i+1] == '\t' {
				key := yamlUnquote(strings.TrimSpace(s[:i]))
				return key, strings.TrimSpace(s[i+1:]), true
			}
		}
	}
	return "", "", false
}

func yamlParseScalar(s string) any {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		if v, err := strconv.Unquote(s); err == nil {
			return v
		}
		return strings.Trim(s, `"`)
	}
	if len(s) >= 2 && s[0] == '\'' && s[len(s)-1] == '\'' {
		return strings.ReplaceAll(s[1:len(s)-1], "''", "'")
	}
	if strings.HasPrefix(s, "[") && strings.HasSuffix(s, "]") {
		return yamlParseInlineList(s[1 : len(s)-1])
	}
	if strings.HasPrefix(s, "{") && strings.HasSuffix(s, "}") {
		return yamlParseInlineMap(s[1 : len(s)-1])
	}
	switch strings.ToLower(s) {
	case "true", "yes", "on":
		return true
	case "false", "no", "off":
		return false
	case "null", "~":
		return nil
	}
	if n, err := strconv.ParseInt(s, 10, 64); err == nil {
		return n
	}
	if f, err := strconv.ParseFloat(s, 64); err == nil {
		return f
	}
	return s
}

func yamlParseInlineList(s string) []any {
	var out []any
	for _, part := range yamlSplitTopLevel(s, ',') {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		out = append(out, yamlParseScalar(part))
	}
	return out
}

func yamlParseInlineMap(s string) map[string]any {
	m := map[string]any{}
	for _, part := range yamlSplitTopLevel(s, ',') {
		k, v, ok := yamlSplitKeyValue(strings.TrimSpace(part))
		if !ok {
			m[strings.TrimSpace(part)] = nil
			continue
		}
		m[k] = yamlParseScalar(v)
	}
	return m
}

func yamlSplitTopLevel(s string, sep byte) []string {
	var parts []string
	depth := 0
	inS, inD := false, false
	start := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch c {
		case '\'':
			if !inD {
				inS = !inS
			}
		case '"':
			if !inS {
				inD = !inD
			}
		case '[', '{':
			if !inS && !inD {
				depth++
			}
		case ']', '}':
			if !inS && !inD {
				depth--
			}
		default:
			if c == sep && depth == 0 && !inS && !inD {
				parts = append(parts, s[start:i])
				start = i + 1
			}
		}
	}
	parts = append(parts, s[start:])
	return parts
}

func yamlUnquote(s string) string {
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		if v, err := strconv.Unquote(s); err == nil {
			return v
		}
	}
	if len(s) >= 2 && s[0] == '\'' && s[len(s)-1] == '\'' {
		return s[1 : len(s)-1]
	}
	return s
}
