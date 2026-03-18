package output

import (
	"encoding/json"
	"fmt"
	"io"
	"reflect"
	"strings"
	"text/tabwriter"
)

// Writer defines the interface for output formatting
type Writer interface {
	// Write outputs a single value
	Write(v interface{}) error
	// WriteList outputs a list of values
	WriteList(v interface{}) error
	// WriteError outputs an error
	WriteError(err error) error
}

// JSONWriter outputs JSON format
type JSONWriter struct {
	w       io.Writer
	compact bool
}

// NewJSONWriter creates a new JSON writer
func NewJSONWriter(w io.Writer) *JSONWriter {
	return &JSONWriter{w: w, compact: false}
}

// NewCompactJSONWriter creates a compact JSON writer
func NewCompactJSONWriter(w io.Writer) *JSONWriter {
	return &JSONWriter{w: w, compact: true}
}

func (j *JSONWriter) Write(v interface{}) error {
	enc := json.NewEncoder(j.w)
	if !j.compact {
		enc.SetIndent("", "  ")
	}
	return enc.Encode(v)
}

func (j *JSONWriter) WriteList(v interface{}) error {
	return j.Write(v)
}

func (j *JSONWriter) WriteError(err error) error {
	errObj := map[string]interface{}{
		"error":   true,
		"message": err.Error(),
	}
	return j.Write(errObj)
}

// NDJSONWriter outputs newline-delimited JSON (one object per line)
type NDJSONWriter struct {
	w io.Writer
}

// NewNDJSONWriter creates a new NDJSON writer
func NewNDJSONWriter(w io.Writer) *NDJSONWriter {
	return &NDJSONWriter{w: w}
}

func (n *NDJSONWriter) Write(v interface{}) error {
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(n.w, string(data))
	return err
}

func (n *NDJSONWriter) WriteList(v interface{}) error {
	// Use reflection to iterate over slice/array
	val := reflect.ValueOf(v)
	if val.Kind() == reflect.Ptr {
		val = val.Elem()
	}

	switch val.Kind() {
	case reflect.Slice, reflect.Array:
		for i := 0; i < val.Len(); i++ {
			if err := n.Write(val.Index(i).Interface()); err != nil {
				return err
			}
		}
		return nil
	default:
		return n.Write(v)
	}
}

func (n *NDJSONWriter) WriteError(err error) error {
	errObj := map[string]interface{}{
		"error":   true,
		"message": err.Error(),
	}
	return n.Write(errObj)
}

// TableWriter outputs human-readable tables
type TableWriter struct {
	w *tabwriter.Writer
}

// NewTableWriter creates a new table writer
func NewTableWriter(w io.Writer) *TableWriter {
	return &TableWriter{
		w: tabwriter.NewWriter(w, 0, 0, 2, ' ', 0),
	}
}

func (t *TableWriter) Write(v interface{}) error {
	// For single objects, just print key-value pairs
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}

	var m map[string]interface{}
	if err := json.Unmarshal(data, &m); err != nil {
		// Not a map, just print as-is
		fmt.Fprintln(t.w, string(data))
		return t.w.Flush()
	}

	for k, v := range m {
		fmt.Fprintf(t.w, "%s:\t%v\n", k, formatValue(v))
	}
	return t.w.Flush()
}

func (t *TableWriter) WriteList(v interface{}) error {
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}

	var items []map[string]interface{}
	if err := json.Unmarshal(data, &items); err != nil {
		// Not a list of maps, fall back to JSON
		fmt.Fprintln(t.w, string(data))
		return t.w.Flush()
	}

	if len(items) == 0 {
		fmt.Fprintln(t.w, "(no results)")
		return t.w.Flush()
	}

	// Collect all unique keys for headers
	keySet := make(map[string]bool)
	for _, item := range items {
		for k := range item {
			keySet[k] = true
		}
	}

	// Sort keys for consistent output
	var keys []string
	// Prioritize common fields
	priority := []string{"id", "name", "type", "status", "state", "severity", "created", "updated"}
	for _, k := range priority {
		if keySet[k] {
			keys = append(keys, k)
			delete(keySet, k)
		}
	}
	for k := range keySet {
		keys = append(keys, k)
	}

	// Limit columns for readability
	if len(keys) > 8 {
		keys = keys[:8]
	}

	// Print header
	var headers []string
	for _, k := range keys {
		headers = append(headers, strings.ToUpper(k))
	}
	fmt.Fprintln(t.w, strings.Join(headers, "\t"))

	// Print rows
	for _, item := range items {
		var row []string
		for _, k := range keys {
			row = append(row, formatValue(item[k]))
		}
		fmt.Fprintln(t.w, strings.Join(row, "\t"))
	}

	return t.w.Flush()
}

func (t *TableWriter) WriteError(err error) error {
	fmt.Fprintf(t.w, "Error: %s\n", err.Error())
	return t.w.Flush()
}

func formatValue(v interface{}) string {
	if v == nil {
		return "-"
	}

	switch val := v.(type) {
	case string:
		if len(val) > 50 {
			return val[:47] + "..."
		}
		return val
	case float64:
		if val == float64(int64(val)) {
			return fmt.Sprintf("%d", int64(val))
		}
		return fmt.Sprintf("%.2f", val)
	case bool:
		if val {
			return "true"
		}
		return "false"
	case []interface{}:
		return fmt.Sprintf("[%d items]", len(val))
	case map[string]interface{}:
		return "{...}"
	default:
		return fmt.Sprintf("%v", v)
	}
}
