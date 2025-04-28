package api

import "github.com/go-acme/lego/v4/acme"

// IdentifiersMatch checks if two slices of acme.Identifier contain the same elements,
// regardless of their order.
func IdentifiersMatch(a, b []acme.Identifier) bool {
	if len(a) != len(b) {
		return false
	}

	mapA := make(map[string]int)
	mapB := make(map[string]int)

	// Use Type+Value as the key for uniqueness
	for _, id := range a {
		key := id.Type + ":" + id.Value
		mapA[key]++
	}

	for _, id := range b {
		key := id.Type + ":" + id.Value
		mapB[key]++
	}

	if len(mapA) != len(mapB) {
		return false
	}

	for k, v := range mapA {
		if mapB[k] != v {
			return false
		}
	}

	return true
}
