package evaluator

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/stackrox/rox/pkg/booleanpolicy/augmentedobjs"
	"github.com/stackrox/rox/pkg/logging"
)

var (
	log = logging.LoggerForModule()
)

// DynamicFieldEvaluator evaluates dynamic Kubernetes field criteria
type DynamicFieldEvaluator struct {
	fieldPath string
	operator  string
	values    []string
	negate    bool
}

// NewDynamicFieldEvaluator creates a new dynamic field evaluator
func NewDynamicFieldEvaluator(fieldPath, operator string, values []string, negate bool) *DynamicFieldEvaluator {
	return &DynamicFieldEvaluator{
		fieldPath: fieldPath,
		operator:  operator,
		values:    values,
		negate:    negate,
	}
}

// Evaluate evaluates the dynamic field against an augmented resource
func (dfe *DynamicFieldEvaluator) Evaluate(resource augmentedobjs.AugmentedResource) (*Result, bool) {
	value, found, err := resource.GetField(dfe.fieldPath)
	if err != nil {
		log.Warnf("Error accessing field %s: %v", dfe.fieldPath, err)
		return nil, false
	}

	matched := dfe.evaluateValue(value, found)
	if dfe.negate {
		matched = !matched
	}

	if matched {
		return &Result{
			Matches: []map[string][]string{
				{
					dfe.fieldPath: {fmt.Sprintf("%v", value)},
				},
			},
		}, true
	}

	return nil, false
}

// evaluateValue evaluates a field value against the specified operator and values
func (dfe *DynamicFieldEvaluator) evaluateValue(value interface{}, found bool) bool {
	switch dfe.operator {
	case "exists":
		return found
	case "equals":
		return found && dfe.stringMatches(fmt.Sprintf("%v", value))
	case "contains":
		return found && dfe.stringContains(fmt.Sprintf("%v", value))
	case "regex_match":
		return found && dfe.regexMatches(fmt.Sprintf("%v", value))
	case ">", "<", ">=", "<=":
		return found && dfe.numericCompare(value)
	default:
		log.Warnf("Unknown operator: %s", dfe.operator)
		return false
	}
}

// stringMatches checks if the value exactly matches any of the target values
func (dfe *DynamicFieldEvaluator) stringMatches(value string) bool {
	for _, targetValue := range dfe.values {
		if value == targetValue {
			return true
		}
	}
	return false
}

// stringContains checks if the value contains any of the target values
func (dfe *DynamicFieldEvaluator) stringContains(value string) bool {
	valueLower := strings.ToLower(value)
	for _, targetValue := range dfe.values {
		if strings.Contains(valueLower, strings.ToLower(targetValue)) {
			return true
		}
	}
	return false
}

// regexMatches checks if the value matches any of the target regex patterns
func (dfe *DynamicFieldEvaluator) regexMatches(value string) bool {
	for _, pattern := range dfe.values {
		if matched, err := regexp.MatchString(pattern, value); err == nil && matched {
			return true
		}
	}
	return false
}

// numericCompare performs numeric comparison operations
func (dfe *DynamicFieldEvaluator) numericCompare(value interface{}) bool {
	if len(dfe.values) == 0 {
		return false
	}

	// Convert value to float64 for comparison
	var numValue float64
	var err error

	switch v := value.(type) {
	case float64:
		numValue = v
	case float32:
		numValue = float64(v)
	case int:
		numValue = float64(v)
	case int64:
		numValue = float64(v)
	case int32:
		numValue = float64(v)
	case string:
		numValue, err = strconv.ParseFloat(v, 64)
		if err != nil {
			log.Debugf("Cannot parse '%s' as number for comparison", v)
			return false
		}
	default:
		// Try converting to string then parsing
		strValue := fmt.Sprintf("%v", value)
		numValue, err = strconv.ParseFloat(strValue, 64)
		if err != nil {
			log.Debugf("Cannot convert '%v' to number for comparison", value)
			return false
		}
	}

	// Convert target value to float64
	targetValue, err := strconv.ParseFloat(dfe.values[0], 64)
	if err != nil {
		log.Debugf("Cannot parse target value '%s' as number", dfe.values[0])
		return false
	}

	// Perform comparison
	switch dfe.operator {
	case ">":
		return numValue > targetValue
	case "<":
		return numValue < targetValue
	case ">=":
		return numValue >= targetValue
	case "<=":
		return numValue <= targetValue
	default:
		return false
	}
}

// GetFieldPath returns the field path being evaluated
func (dfe *DynamicFieldEvaluator) GetFieldPath() string {
	return dfe.fieldPath
}

// GetOperator returns the operator being used
func (dfe *DynamicFieldEvaluator) GetOperator() string {
	return dfe.operator
}

// GetValues returns the values being evaluated against
func (dfe *DynamicFieldEvaluator) GetValues() []string {
	return dfe.values
}

// IsNegated returns whether the evaluation is negated
func (dfe *DynamicFieldEvaluator) IsNegated() bool {
	return dfe.negate
}