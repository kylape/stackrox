package fieldmask

import (
	"encoding/json"
	"strings"
)

// Apply filters a JSON object to only include specified fields.
// Fields are specified as comma-separated paths like "id,name,scan.vulnerabilities".
// Supports:
//   - Simple fields: "id", "name"
//   - Nested fields: "scan.components", "policy.name"
//   - Array access: "items[].name" (applies to all array elements)
func Apply(data []byte, fields string) ([]byte, error) {
	if fields == "" {
		return data, nil
	}

	// Parse the JSON
	var obj interface{}
	if err := json.Unmarshal(data, &obj); err != nil {
		return data, err
	}

	// Parse field paths
	paths := parseFieldPaths(fields)

	// Apply the mask
	result := applyMask(obj, paths)

	// Re-encode
	return json.Marshal(result)
}

// parseFieldPaths parses comma-separated field paths
func parseFieldPaths(fields string) [][]string {
	var paths [][]string
	for _, field := range strings.Split(fields, ",") {
		field = strings.TrimSpace(field)
		if field == "" {
			continue
		}
		// Split by dots, handling [] notation
		path := splitPath(field)
		paths = append(paths, path)
	}
	return paths
}

// splitPath splits a field path like "scan.vulnerabilities[].cve" into segments
func splitPath(path string) []string {
	var segments []string
	current := ""

	for i := 0; i < len(path); i++ {
		c := path[i]
		if c == '.' {
			if current != "" {
				segments = append(segments, current)
				current = ""
			}
		} else if c == '[' {
			if current != "" {
				segments = append(segments, current)
				current = ""
			}
			// Handle [] for array iteration
			if i+1 < len(path) && path[i+1] == ']' {
				segments = append(segments, "[]")
				i++ // skip ]
			}
		} else if c == ']' {
			// Skip, handled above
		} else {
			current += string(c)
		}
	}

	if current != "" {
		segments = append(segments, current)
	}

	return segments
}

// applyMask applies field paths to an object
func applyMask(obj interface{}, paths [][]string) interface{} {
	if len(paths) == 0 {
		return obj
	}

	switch v := obj.(type) {
	case map[string]interface{}:
		return applyMaskToObject(v, paths)
	case []interface{}:
		return applyMaskToArray(v, paths)
	default:
		return obj
	}
}

// applyMaskToObject filters a JSON object
func applyMaskToObject(obj map[string]interface{}, paths [][]string) map[string]interface{} {
	result := make(map[string]interface{})

	// Group paths by first segment
	groups := make(map[string][][]string)
	for _, path := range paths {
		if len(path) == 0 {
			continue
		}
		key := path[0]
		rest := path[1:]
		groups[key] = append(groups[key], rest)
	}

	// Apply each group
	for key, subPaths := range groups {
		val, ok := obj[key]
		if !ok {
			continue
		}

		// Check if any path is terminal (empty rest)
		hasTerminal := false
		var nonTerminal [][]string
		for _, sp := range subPaths {
			if len(sp) == 0 {
				hasTerminal = true
			} else {
				nonTerminal = append(nonTerminal, sp)
			}
		}

		if hasTerminal && len(nonTerminal) == 0 {
			// Include the whole value
			result[key] = val
		} else if len(nonTerminal) > 0 {
			// Recurse into nested paths
			result[key] = applyMask(val, nonTerminal)
		} else {
			result[key] = val
		}
	}

	return result
}

// applyMaskToArray filters a JSON array
func applyMaskToArray(arr []interface{}, paths [][]string) []interface{} {
	// Check if paths start with [] (apply to all elements)
	var elementPaths [][]string
	var directPaths [][]string

	for _, path := range paths {
		if len(path) > 0 && path[0] == "[]" {
			elementPaths = append(elementPaths, path[1:])
		} else {
			directPaths = append(directPaths, path)
		}
	}

	// If we have element paths, apply them to each element
	if len(elementPaths) > 0 {
		result := make([]interface{}, len(arr))
		for i, elem := range arr {
			result[i] = applyMask(elem, elementPaths)
		}
		return result
	}

	// If we have direct paths but no [], apply to the array as-is
	if len(directPaths) > 0 {
		// Try to apply paths to each element
		result := make([]interface{}, len(arr))
		for i, elem := range arr {
			result[i] = applyMask(elem, directPaths)
		}
		return result
	}

	return arr
}
