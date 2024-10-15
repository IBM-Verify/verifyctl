//
// IBM Confidential
// PID 5725-X36
// Copyright IBM Corp. 2019, 2024
//

// Package types extends Go types
package types

// String converts an interface to string
func String(obj interface{}) string {
	result := ""
	if x, ok := obj.(string); ok {
		result = x
	}
	return result
}
