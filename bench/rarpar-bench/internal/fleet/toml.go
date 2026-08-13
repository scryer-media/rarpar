package fleet

// Minimal TOML subset decoder.
//
// The bench harness is deliberately dependency-free: go.mod declares no
// requires and the tree carries no go.sum. Benchmark evidence has to be
// reproducible from a checkout years from now, so the fleet configuration
// reader ships its own parser instead of pulling a module dependency into a
// provenance-sensitive tool.
//
// Supported: comments, bare and quoted keys, [table], [table.sub],
// [[array-of-tables]], basic and literal strings, integers (with `_`
// separators), floats, booleans, and single-line arrays of scalars.
//
// Deliberately rejected with a clear message rather than silently mis-parsed:
// inline tables, multi-line strings, multi-line arrays, and date/time values.
// A benchmark fleet config that quietly means something other than what the
// operator wrote is worse than one that refuses to load.

import (
	"fmt"
	"strconv"
	"strings"
)

type tomlKind int

const (
	tomlString tomlKind = iota
	tomlInt
	tomlFloat
	tomlBool
	tomlArray
)

type tomlValue struct {
	kind  tomlKind
	str   string
	int   int64
	float float64
	bool  bool
	array []tomlValue
	line  int
}

func (value tomlValue) typeName() string {
	switch value.kind {
	case tomlString:
		return "string"
	case tomlInt:
		return "integer"
	case tomlFloat:
		return "float"
	case tomlBool:
		return "boolean"
	default:
		return "array"
	}
}

type tomlTable struct {
	path    string
	line    int
	values  map[string]tomlValue
	tables  map[string]*tomlTable
	arrays  map[string][]*tomlTable
	defined bool
}

func newTomlTable(path string, line int) *tomlTable {
	return &tomlTable{
		path:   path,
		line:   line,
		values: map[string]tomlValue{},
		tables: map[string]*tomlTable{},
		arrays: map[string][]*tomlTable{},
	}
}

// parseTOML decodes the supported subset. name is only used in error text.
func parseTOML(name, data string) (*tomlTable, error) {
	root := newTomlTable("", 0)
	root.defined = true
	current := root
	for number, raw := range strings.Split(data, "\n") {
		line := number + 1
		text := strings.TrimSpace(stripTOMLComment(raw))
		if text == "" {
			continue
		}
		switch {
		case strings.HasPrefix(text, "[["):
			if !strings.HasSuffix(text, "]]") {
				return nil, fmt.Errorf("%s:%d: unterminated array-of-tables header", name, line)
			}
			parts, err := splitTOMLKeyPath(strings.TrimSpace(text[2 : len(text)-2]))
			if err != nil {
				return nil, fmt.Errorf("%s:%d: %w", name, line, err)
			}
			table, err := appendTOMLArrayTable(root, parts, line)
			if err != nil {
				return nil, fmt.Errorf("%s:%d: %w", name, line, err)
			}
			current = table
		case strings.HasPrefix(text, "["):
			if !strings.HasSuffix(text, "]") {
				return nil, fmt.Errorf("%s:%d: unterminated table header", name, line)
			}
			parts, err := splitTOMLKeyPath(strings.TrimSpace(text[1 : len(text)-1]))
			if err != nil {
				return nil, fmt.Errorf("%s:%d: %w", name, line, err)
			}
			table, err := resolveTOMLTable(root, parts, line)
			if err != nil {
				return nil, fmt.Errorf("%s:%d: %w", name, line, err)
			}
			if table.defined {
				return nil, fmt.Errorf("%s:%d: table [%s] is defined twice", name, line, strings.Join(parts, "."))
			}
			table.defined = true
			current = table
		default:
			key, literal, found := strings.Cut(text, "=")
			if !found {
				return nil, fmt.Errorf("%s:%d: expected key = value", name, line)
			}
			name2, err := decodeTOMLKey(strings.TrimSpace(key))
			if err != nil {
				return nil, fmt.Errorf("%s:%d: %w", name, line, err)
			}
			value, err := parseTOMLValue(strings.TrimSpace(literal), line)
			if err != nil {
				return nil, fmt.Errorf("%s:%d: key %q: %w", name, line, name2, err)
			}
			if _, exists := current.values[name2]; exists {
				return nil, fmt.Errorf("%s:%d: key %q is set twice", name, line, name2)
			}
			current.values[name2] = value
		}
	}
	return root, nil
}

// stripTOMLComment removes a trailing comment while respecting quoting, so a
// '#' inside a path or a sha256 comment marker cannot truncate a value.
func stripTOMLComment(line string) string {
	var quote rune
	for index, symbol := range line {
		switch {
		case quote != 0:
			if symbol == quote {
				quote = 0
			}
		case symbol == '"' || symbol == '\'':
			quote = symbol
		case symbol == '#':
			return line[:index]
		}
	}
	return line
}

func splitTOMLKeyPath(text string) ([]string, error) {
	if text == "" {
		return nil, fmt.Errorf("empty table name")
	}
	var parts []string
	var current strings.Builder
	var quote rune
	for _, symbol := range text {
		switch {
		case quote != 0:
			if symbol == quote {
				quote = 0
			}
			current.WriteRune(symbol)
		case symbol == '"' || symbol == '\'':
			quote = symbol
			current.WriteRune(symbol)
		case symbol == '.':
			parts = append(parts, current.String())
			current.Reset()
		default:
			current.WriteRune(symbol)
		}
	}
	if quote != 0 {
		return nil, fmt.Errorf("unterminated quote in table name")
	}
	parts = append(parts, current.String())
	decoded := make([]string, len(parts))
	for index, part := range parts {
		value, err := decodeTOMLKey(strings.TrimSpace(part))
		if err != nil {
			return nil, err
		}
		decoded[index] = value
	}
	return decoded, nil
}

func decodeTOMLKey(text string) (string, error) {
	if text == "" {
		return "", fmt.Errorf("empty key")
	}
	if strings.HasPrefix(text, "\"") || strings.HasPrefix(text, "'") {
		value, err := parseTOMLValue(text, 0)
		if err != nil {
			return "", err
		}
		if value.kind != tomlString {
			return "", fmt.Errorf("quoted key must be a string")
		}
		return value.str, nil
	}
	for _, symbol := range text {
		isBare := symbol == '-' || symbol == '_' ||
			(symbol >= 'a' && symbol <= 'z') || (symbol >= 'A' && symbol <= 'Z') ||
			(symbol >= '0' && symbol <= '9')
		if !isBare {
			return "", fmt.Errorf("key %q contains an unsupported character %q", text, string(symbol))
		}
	}
	return text, nil
}

func resolveTOMLTable(root *tomlTable, parts []string, line int) (*tomlTable, error) {
	current := root
	for index, part := range parts {
		path := strings.Join(parts[:index+1], ".")
		if array, ok := current.arrays[part]; ok {
			// [machines.connection] after [[machines]] addresses the most
			// recent array element, which is how operators read it.
			current = array[len(array)-1]
			continue
		}
		if _, ok := current.values[part]; ok {
			return nil, fmt.Errorf("%q is already a value, not a table", path)
		}
		table, ok := current.tables[part]
		if !ok {
			table = newTomlTable(path, line)
			current.tables[part] = table
		}
		current = table
	}
	return current, nil
}

func appendTOMLArrayTable(root *tomlTable, parts []string, line int) (*tomlTable, error) {
	parent := root
	if len(parts) > 1 {
		resolved, err := resolveTOMLTable(root, parts[:len(parts)-1], line)
		if err != nil {
			return nil, err
		}
		parent = resolved
	}
	name := parts[len(parts)-1]
	if _, ok := parent.tables[name]; ok {
		return nil, fmt.Errorf("%q is already a table, not an array of tables", strings.Join(parts, "."))
	}
	path := fmt.Sprintf("%s[%d]", strings.Join(parts, "."), len(parent.arrays[name]))
	table := newTomlTable(path, line)
	table.defined = true
	parent.arrays[name] = append(parent.arrays[name], table)
	return table, nil
}

func parseTOMLValue(text string, line int) (tomlValue, error) {
	if text == "" {
		return tomlValue{}, fmt.Errorf("missing value")
	}
	switch {
	case strings.HasPrefix(text, "\"\"\"") || strings.HasPrefix(text, "'''"):
		return tomlValue{}, fmt.Errorf("multi-line strings are not supported")
	case strings.HasPrefix(text, "{"):
		return tomlValue{}, fmt.Errorf("inline tables are not supported; use a [table] header")
	case strings.HasPrefix(text, "\""):
		value, err := parseTOMLBasicString(text)
		if err != nil {
			return tomlValue{}, err
		}
		return tomlValue{kind: tomlString, str: value, line: line}, nil
	case strings.HasPrefix(text, "'"):
		if !strings.HasSuffix(text, "'") || len(text) < 2 {
			return tomlValue{}, fmt.Errorf("unterminated literal string")
		}
		return tomlValue{kind: tomlString, str: text[1 : len(text)-1], line: line}, nil
	case strings.HasPrefix(text, "["):
		return parseTOMLArray(text, line)
	case text == "true" || text == "false":
		return tomlValue{kind: tomlBool, bool: text == "true", line: line}, nil
	}
	number := strings.ReplaceAll(text, "_", "")
	if integer, err := strconv.ParseInt(number, 10, 64); err == nil {
		return tomlValue{kind: tomlInt, int: integer, float: float64(integer), line: line}, nil
	}
	if float, err := strconv.ParseFloat(number, 64); err == nil {
		return tomlValue{kind: tomlFloat, float: float, line: line}, nil
	}
	return tomlValue{}, fmt.Errorf("unsupported value %q (dates and inline tables are not supported)", text)
}

func parseTOMLBasicString(text string) (string, error) {
	if len(text) < 2 || !strings.HasSuffix(text, "\"") {
		return "", fmt.Errorf("unterminated string")
	}
	body := text[1 : len(text)-1]
	var out strings.Builder
	for index := 0; index < len(body); index++ {
		symbol := body[index]
		if symbol != '\\' {
			if symbol == '"' {
				return "", fmt.Errorf("unescaped quote inside string")
			}
			out.WriteByte(symbol)
			continue
		}
		index++
		if index >= len(body) {
			return "", fmt.Errorf("trailing escape in string")
		}
		switch body[index] {
		case 'n':
			out.WriteByte('\n')
		case 't':
			out.WriteByte('\t')
		case 'r':
			out.WriteByte('\r')
		case '"':
			out.WriteByte('"')
		case '\\':
			out.WriteByte('\\')
		default:
			return "", fmt.Errorf("unsupported escape \\%s", string(body[index]))
		}
	}
	return out.String(), nil
}

func parseTOMLArray(text string, line int) (tomlValue, error) {
	if !strings.HasSuffix(text, "]") {
		return tomlValue{}, fmt.Errorf("multi-line arrays are not supported; keep the array on one line")
	}
	body := strings.TrimSpace(text[1 : len(text)-1])
	value := tomlValue{kind: tomlArray, line: line}
	if body == "" {
		return value, nil
	}
	var items []string
	var current strings.Builder
	var quote rune
	depth := 0
	for _, symbol := range body {
		switch {
		case quote != 0:
			current.WriteRune(symbol)
			if symbol == quote {
				quote = 0
			}
		case symbol == '"' || symbol == '\'':
			quote = symbol
			current.WriteRune(symbol)
		case symbol == '[':
			depth++
			current.WriteRune(symbol)
		case symbol == ']':
			depth--
			current.WriteRune(symbol)
		case symbol == ',' && depth == 0:
			items = append(items, current.String())
			current.Reset()
		default:
			current.WriteRune(symbol)
		}
	}
	if quote != 0 {
		return tomlValue{}, fmt.Errorf("unterminated quote in array")
	}
	if trailing := strings.TrimSpace(current.String()); trailing != "" {
		items = append(items, trailing)
	}
	for _, item := range items {
		element, err := parseTOMLValue(strings.TrimSpace(item), line)
		if err != nil {
			return tomlValue{}, err
		}
		value.array = append(value.array, element)
	}
	return value, nil
}
