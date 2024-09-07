//
// IBM Confidential
// PID 5725-X36
// Copyright IBM Corp. 2019, 2024
//

// Package types extends Go types
package types

import (
	"strings"
)

type StringSlice []string

// ContainsString checks if the str match with any of the slice values.
// The comparison is case-insensitive.
func (slice StringSlice) ContainsString(str string) bool {
	for _, value := range slice {
		if strings.EqualFold(strings.ToLower(str), value) {
			return true
		}
	}
	return false
}

// PrefixedString checks if the str prefixed with any of the slice values
func (slice StringSlice) PrefixedString(str string) bool {
	for _, value := range slice {
		if strings.HasPrefix(str, value) {
			return true
		}
	}
	return false
}

// ToStringSlice converts an interface to string slice.
// If the interface is of type string, it is returned as a slice of length 1.
func ToStringSlice(obj interface{}) []string {

	if sa, ok := obj.([]string); ok {
		return sa
	}

	var result []string

	if ia, ok := obj.([]interface{}); ok {
		for _, val := range ia {
			if s, ok := val.(string); ok {
				result = append(result, s)
			}
		}
		if len(result) == 0 {
			return nil
		}
	} else if s, ok := obj.(string); ok {
		result = make([]string, 1)
		result[0] = s
	}
	return result
}
