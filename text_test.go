package main

import (
	"testing"
)

func TestCleanChirp(t *testing.T) {
	wordFilters := map[string]bool{
		"kerfuffle": true,
		"sharbert":  true,
		"fornax":    true,
	}
	tests := []struct {
		input, expected string
	}{
		{
			input:    "This is a kerfuffle opinion I need to share with the world",
			expected: "This is a **** opinion I need to share with the world",
		},
		{
			input:    "My name is Kyle! Hurray!!!!",
			expected: "My name is Kyle! Hurray!!!!",
		},
		{
			input:    " Fornax what the hell!",
			expected: " **** what the hell!",
		},
	}

	for _, test := range tests {
		result := CleanChirp(test.input, wordFilters)
		if result != test.expected {
			t.Errorf("CleanChirp(%s) = %s; want %s", test.input, result, test.expected)
		}
	}
}
