package api

import (
	"testing"

	"github.com/go-acme/lego/v4/acme"
)

func TestIdentifiersMatch(t *testing.T) {
	tests := []struct {
		name     string
		a        []acme.Identifier
		b        []acme.Identifier
		expected bool
	}{
		{
			name: "Identical slices in same order",
			a: []acme.Identifier{
				{Type: "dns", Value: "example.com"},
				{Type: "dns", Value: "example.org"},
			},
			b: []acme.Identifier{
				{Type: "dns", Value: "example.com"},
				{Type: "dns", Value: "example.org"},
			},
			expected: true,
		},
		{
			name: "Same elements in different order",
			a: []acme.Identifier{
				{Type: "dns", Value: "example.com"},
				{Type: "dns", Value: "example.org"},
			},
			b: []acme.Identifier{
				{Type: "dns", Value: "example.org"},
				{Type: "dns", Value: "example.com"},
			},
			expected: true,
		},
		{
			name: "Different elements",
			a: []acme.Identifier{
				{Type: "dns", Value: "example.com"},
				{Type: "dns", Value: "example.org"},
			},
			b: []acme.Identifier{
				{Type: "dns", Value: "example.net"},
				{Type: "dns", Value: "example.org"},
			},
			expected: false,
		},
		{
			name:     "Both empty",
			a:        []acme.Identifier{},
			b:        []acme.Identifier{},
			expected: true,
		},
		{
			name: "Different types, same value",
			a: []acme.Identifier{
				{Type: "dns", Value: "example.com"},
			},
			b: []acme.Identifier{
				{Type: "ip", Value: "example.com"},
			},
			expected: false,
		},
		{
			name: "Different lengths",
			a: []acme.Identifier{
				{Type: "dns", Value: "example.com"},
				{Type: "dns", Value: "example.org"},
			},
			b: []acme.Identifier{
				{Type: "dns", Value: "example.com"},
			},
			expected: false,
		},
		{
			name: "One slice with duplicates",
			a: []acme.Identifier{
				{Type: "dns", Value: "example.com"},
				{Type: "dns", Value: "example.com"},
			},
			b: []acme.Identifier{
				{Type: "dns", Value: "example.com"},
				{Type: "dns", Value: "example.org"},
			},
			expected: false,
		},
		{
			name: "Both slices with same duplicates",
			a: []acme.Identifier{
				{Type: "dns", Value: "example.com"},
				{Type: "dns", Value: "example.com"},
			},
			b: []acme.Identifier{
				{Type: "dns", Value: "example.com"},
				{Type: "dns", Value: "example.com"},
			},
			expected: true,
		},
		{
			name: "Inconsistent use of Wildcard",
			a: []acme.Identifier{
				{Type: "dns", Value: "*.example.com"},
			},
			b: []acme.Identifier{
				{Type: "dns", Value: "example.com"},
			},
			expected: false,
		},
		{
			name: "Wildcard missing in one slice",
			a: []acme.Identifier{
				{Type: "dns", Value: "*.example.org"},
				{Type: "dns", Value: "example.org"},
			},
			b: []acme.Identifier{
				{Type: "dns", Value: "example.org"},
				{Type: "dns", Value: "example.org"},
			},
			expected: false,
		},
		{
			name: "Wildcard mixed",
			a: []acme.Identifier{
				{Type: "dns", Value: "*.example.org"},
				{Type: "dns", Value: "example.org"},
			},
			b: []acme.Identifier{
				{Type: "dns", Value: "example.org"},
				{Type: "dns", Value: "*.example.org"},
			},
			expected: true,
		},
		{
			name: "Multiple With Wildcard mixed",
			a: []acme.Identifier{
				{Type: "dns", Value: "*.example.org"},
				{Type: "dns", Value: "example.org"},
				{Type: "dns", Value: "example.com"},
				{Type: "dns", Value: "example.net"},
				{Type: "dns", Value: "example.de"},
				{Type: "dns", Value: "example.bayern"},
			},
			b: []acme.Identifier{
				{Type: "dns", Value: "example.bayern"},
				{Type: "dns", Value: "example.org"},
				{Type: "dns", Value: "example.net"},
				{Type: "dns", Value: "example.de"},
				{Type: "dns", Value: "*.example.org"},
				{Type: "dns", Value: "example.com"},
			},
			expected: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := IdentifiersMatch(test.a, test.b)
			if result != test.expected {
				t.Errorf("Expected %v, got %v", test.expected, result)
			}
		})
	}
}
