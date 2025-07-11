package querybuilders

import (
	"fmt"

	"github.com/stackrox/rox/generated/storage"
	"github.com/stackrox/rox/pkg/booleanpolicy/query"
)

// DynamicFieldQueryBuilder handles the "Kubernetes Field" criteria type
// It processes dynamic field paths and operators for any Kubernetes resource
type DynamicFieldQueryBuilder struct{}

// ForDynamicField creates a new dynamic field query builder
func ForDynamicField() *DynamicFieldQueryBuilder {
	return &DynamicFieldQueryBuilder{}
}

// FieldQueriesForGroup converts a PolicyGroup with dynamic field values to field queries
func (qb *DynamicFieldQueryBuilder) FieldQueriesForGroup(group *storage.PolicyGroup) []*query.FieldQuery {
	var fieldQueries []*query.FieldQuery

	for _, value := range group.GetValues() {
		// Handle new dynamic field values
		if dynamicValue := value.GetDynamic(); dynamicValue != nil {
			fq := qb.createDynamicFieldQuery(dynamicValue, group)
			if fq != nil {
				fieldQueries = append(fieldQueries, fq)
			}
		} else if value.GetStringValue() != "" {
			// Handle legacy string-encoded dynamic values for backward compatibility
			// Format: "field=spec.type,operator=equals,value=LoadBalancer"
			fq := qb.parseLegacyDynamicValue(value.GetStringValue(), group)
			if fq != nil {
				fieldQueries = append(fieldQueries, fq)
			}
		}
	}

	return fieldQueries
}

// createDynamicFieldQuery creates a field query from a DynamicFieldValue
func (qb *DynamicFieldQueryBuilder) createDynamicFieldQuery(dynamicValue *storage.DynamicFieldValue,
	group *storage.PolicyGroup) *query.FieldQuery {
	// Create a synthetic field name that encodes the dynamic nature
	fieldName := fmt.Sprintf("dynamic.%s", dynamicValue.GetFieldPath())

	// Convert storage.BooleanOperator to query.Operator
	operator := query.Or
	if group.GetBooleanOperator() == storage.BooleanOperator_AND {
		operator = query.And
	}

	return &query.FieldQuery{
		Field:    fieldName,
		Values:   dynamicValue.GetValues(),
		Operator: operator,
		Negate:   group.GetNegate(),
	}
}

// parseLegacyDynamicValue parses string-encoded dynamic field values
// This provides backward compatibility and a simpler way to define dynamic fields
func (qb *DynamicFieldQueryBuilder) parseLegacyDynamicValue(value string, group *storage.PolicyGroup) *query.FieldQuery {
	// Parse string format: "field=spec.type,operator=equals,value=LoadBalancer"
	params := parseKeyValuePairs(value)

	fieldPath, hasField := params["field"]
	_, hasOperator := params["operator"]
	fieldValue, hasValue := params["value"]

	if !hasField || !hasOperator {
		return nil
	}

	values := []string{}
	if hasValue {
		values = append(values, fieldValue)
	}

	fieldName := fmt.Sprintf("dynamic.%s", fieldPath)

	// Convert storage.BooleanOperator to query.Operator
	queryOperator := query.Or
	if group.GetBooleanOperator() == storage.BooleanOperator_AND {
		queryOperator = query.And
	}

	return &query.FieldQuery{
		Field:    fieldName,
		Values:   values,
		Operator: queryOperator,
		Negate:   group.GetNegate(),
	}
}

// parseKeyValuePairs parses comma-separated key=value pairs
func parseKeyValuePairs(input string) map[string]string {
	result := make(map[string]string)
	
	// Simple parser for "key=value,key2=value2" format
	pairs := splitWithEscape(input, ',')
	for _, pair := range pairs {
		kv := splitWithEscape(pair, '=')
		if len(kv) == 2 {
			result[kv[0]] = kv[1]
		}
	}
	
	return result
}

// splitWithEscape splits a string by delimiter, respecting escaped delimiters
func splitWithEscape(s string, delimiter rune) []string {
	var parts []string
	var current []rune
	var escaped bool

	for _, r := range s {
		if escaped {
			current = append(current, r)
			escaped = false
		} else if r == '\\' {
			escaped = true
		} else if r == delimiter {
			parts = append(parts, string(current))
			current = nil
		} else {
			current = append(current, r)
		}
	}

	if len(current) > 0 {
		parts = append(parts, string(current))
	}

	return parts
}

// GetSupportedOperators returns the operators supported by dynamic fields
func (qb *DynamicFieldQueryBuilder) GetSupportedOperators() []string {
	return []string{
		"equals",
		"contains", 
		"exists",
		"regex_match",
		">",
		"<",
		">=",
		"<=",
	}
}