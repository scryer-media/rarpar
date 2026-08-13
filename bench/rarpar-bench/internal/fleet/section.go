package fleet

import (
	"fmt"
	"sort"
	"strings"
)

// section is a strict reader over one parsed TOML table. Every key an operator
// writes must be consumed by the decoder; a leftover key is reported instead of
// ignored, because a typo in a fleet config otherwise shows up as a machine
// that silently benchmarks the wrong thing.
type section struct {
	state   *decodeState
	table   *tomlTable
	path    string
	used    map[string]bool
	present bool
}

type decodeState struct {
	file   string
	errors []string
}

func (state *decodeState) fail(format string, args ...any) {
	state.errors = append(state.errors, fmt.Sprintf(format, args...))
}

func (state *decodeState) err() error {
	if len(state.errors) == 0 {
		return nil
	}
	if len(state.errors) == 1 {
		return fmt.Errorf("%s: %s", state.file, state.errors[0])
	}
	return fmt.Errorf("%s: %d configuration problems:\n  - %s",
		state.file, len(state.errors), strings.Join(state.errors, "\n  - "))
}

func newSection(state *decodeState, table *tomlTable, path string, present bool) *section {
	return &section{state: state, table: table, path: path, used: map[string]bool{}, present: present}
}

func (item *section) label(key string) string {
	if item.path == "" {
		return key
	}
	return item.path + "." + key
}

func (item *section) value(key string, kind tomlKind) (tomlValue, bool) {
	if !item.present {
		return tomlValue{}, false
	}
	item.used[key] = true
	value, ok := item.table.values[key]
	if !ok {
		return tomlValue{}, false
	}
	if value.kind != kind {
		// An integer where a float is wanted is the one widening TOML makes
		// natural to write (`max_hours = 2`), so accept it explicitly.
		if kind == tomlFloat && value.kind == tomlInt {
			return value, true
		}
		item.state.fail("%s must be a %s, got a %s (line %d)", item.label(key), kindName(kind), value.typeName(), value.line)
		return tomlValue{}, false
	}
	return value, true
}

func kindName(kind tomlKind) string {
	return tomlValue{kind: kind}.typeName()
}

func (item *section) str(key, fallback string) string {
	value, ok := item.value(key, tomlString)
	if !ok {
		return fallback
	}
	return value.str
}

func (item *section) requiredStr(key string) string {
	value, ok := item.value(key, tomlString)
	if !ok {
		item.state.fail("%s is required", item.label(key))
		return ""
	}
	if strings.TrimSpace(value.str) == "" {
		item.state.fail("%s must not be empty", item.label(key))
	}
	return value.str
}

func (item *section) integer(key string, fallback int) int {
	value, ok := item.value(key, tomlInt)
	if !ok {
		return fallback
	}
	return int(value.int)
}

func (item *section) float(key string, fallback float64) float64 {
	value, ok := item.value(key, tomlFloat)
	if !ok {
		return fallback
	}
	if value.kind == tomlInt {
		return float64(value.int)
	}
	return value.float
}

func (item *section) boolean(key string, fallback bool) bool {
	value, ok := item.value(key, tomlBool)
	if !ok {
		return fallback
	}
	return value.bool
}

func (item *section) strings(key string, fallback []string) []string {
	value, ok := item.value(key, tomlArray)
	if !ok {
		return fallback
	}
	out := make([]string, 0, len(value.array))
	for _, element := range value.array {
		if element.kind != tomlString {
			item.state.fail("%s must be an array of strings (line %d)", item.label(key), value.line)
			return fallback
		}
		out = append(out, element.str)
	}
	return out
}

func (item *section) has(key string) bool {
	if !item.present {
		return false
	}
	_, valueOK := item.table.values[key]
	_, tableOK := item.table.tables[key]
	_, arrayOK := item.table.arrays[key]
	return valueOK || tableOK || arrayOK
}

func (item *section) child(key string) *section {
	if !item.present {
		return newSection(item.state, newTomlTable("", 0), item.label(key), false)
	}
	item.used[key] = true
	table, ok := item.table.tables[key]
	if !ok {
		return newSection(item.state, newTomlTable("", 0), item.label(key), false)
	}
	return newSection(item.state, table, item.label(key), true)
}

func (item *section) requiredChild(key string) *section {
	child := item.child(key)
	if !child.present {
		item.state.fail("[%s] is required", child.path)
	}
	return child
}

func (item *section) childNames() []string {
	if !item.present {
		return nil
	}
	names := make([]string, 0, len(item.table.tables))
	for name := range item.table.tables {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func (item *section) list(key string) []*section {
	if !item.present {
		return nil
	}
	item.used[key] = true
	tables, ok := item.table.arrays[key]
	if !ok {
		return nil
	}
	out := make([]*section, 0, len(tables))
	for index, table := range tables {
		out = append(out, newSection(item.state, table, fmt.Sprintf("%s[%d]", item.label(key), index), true))
	}
	return out
}

// finish reports keys and sub-tables the decoder never asked for.
func (item *section) finish() {
	if !item.present {
		return
	}
	var unknown []string
	for key, value := range item.table.values {
		if !item.used[key] {
			unknown = append(unknown, fmt.Sprintf("%s (line %d)", item.label(key), value.line))
		}
	}
	for key, table := range item.table.tables {
		if !item.used[key] {
			unknown = append(unknown, fmt.Sprintf("[%s] (line %d)", item.label(key), table.line))
		}
	}
	for key, tables := range item.table.arrays {
		if !item.used[key] && len(tables) > 0 {
			unknown = append(unknown, fmt.Sprintf("[[%s]] (line %d)", item.label(key), tables[0].line))
		}
	}
	if len(unknown) == 0 {
		return
	}
	sort.Strings(unknown)
	item.state.fail("unknown configuration key(s): %s", strings.Join(unknown, ", "))
}
