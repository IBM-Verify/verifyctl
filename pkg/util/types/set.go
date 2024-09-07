//
// IBM Confidential
// PID 5725-X36
// Copyright IBM Corp. 2019, 2024
//

// Package types extends Go types
package types

type void struct{}

// Set is the set data structure
type Set map[string]void

// ToArray converts the set values to a slice
func (s Set) ToArray() []string {
	var values []string
	for value := range s {
		values = append(values, value)
	}
	return values
}

// Add adds the value to the set
func (s Set) Add(value string) {
	s[value] = void{}
}

// Delete deletes the value from the set
func (s Set) Delete(value string) {
	delete(s, value)
}

// Contains checks if the value exists in the set
func (s Set) Contains(value string) bool {
	_, exists := s[value]
	return exists
}

// FromArray converts string array to Set object
func FromArray(values []string) Set {
	s := Set{}
	for _, v := range values {
		s.Add(v)
	}
	return s
}
