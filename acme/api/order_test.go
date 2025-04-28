package api

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"io"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-acme/lego/v4/acme"
	"github.com/go-acme/lego/v4/platform/tester"
	"github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOrderService_NewWithOptions(t *testing.T) {
	mux, apiURL := tester.SetupFakeAPI(t)

	// small value keeps test fast
	privateKey, errK := rsa.GenerateKey(rand.Reader, 1024)
	require.NoError(t, errK, "Could not generate test key")

	mux.HandleFunc("/newOrder", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
			return
		}

		body, err := readSignedBody(r, privateKey)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		order := acme.Order{}
		err = json.Unmarshal(body, &order)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		err = tester.WriteJSONResponse(w, acme.Order{
			Status:         acme.StatusValid,
			Expires:        order.Expires,
			Identifiers:    order.Identifiers,
			Profile:        order.Profile,
			NotBefore:      order.NotBefore,
			NotAfter:       order.NotAfter,
			Error:          order.Error,
			Authorizations: order.Authorizations,
			Finalize:       order.Finalize,
			Certificate:    order.Certificate,
			Replaces:       order.Replaces,
		})
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	})

	core, err := New(http.DefaultClient, "lego-test", apiURL+"/dir", "", privateKey)
	require.NoError(t, err)

	testCases := []struct {
		desc     string
		opts     *OrderOptions
		expected acme.ExtendedOrder
	}{
		{
			desc: "simple",
			expected: acme.ExtendedOrder{
				Order: acme.Order{
					Status:      "valid",
					Identifiers: []acme.Identifier{{Type: "dns", Value: "example.com"}},
				},
			},
		},
		{
			desc: "with options",
			opts: &OrderOptions{
				NotBefore: time.Date(2023, 1, 1, 1, 0, 0, 0, time.UTC),
				NotAfter:  time.Date(2023, 1, 2, 1, 0, 0, 0, time.UTC),
			},
			expected: acme.ExtendedOrder{
				Order: acme.Order{
					Status:      "valid",
					Identifiers: []acme.Identifier{{Type: "dns", Value: "example.com"}},
					NotBefore:   "2023-01-01T01:00:00Z",
					NotAfter:    "2023-01-02T01:00:00Z",
				},
			},
		},
	}

	for _, test := range testCases {
		t.Run(test.desc, func(t *testing.T) {
			t.Parallel()

			order, err := core.Orders.NewWithOptions([]string{"example.com"}, test.opts)
			require.NoError(t, err)

			assert.Equal(t, test.expected, order)
		})
	}
}

func TestOrderService_NewWithOptions_IdentifierMatch(t *testing.T) {
	mux, apiURL := tester.SetupFakeAPI(t)

	// small value keeps test fast
	privateKey, errK := rsa.GenerateKey(rand.Reader, 1024)
	require.NoError(t, errK, "Could not generate test key")

	// Create an atomic flag to control response modification
	var returnMismatchedIdentifiers int32

	mux.HandleFunc("/newOrder", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
			return
		}

		body, err := readSignedBody(r, privateKey)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		orderReq := acme.Order{}
		err = json.Unmarshal(body, &orderReq)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		// Create response order with either matching or mismatched identifiers
		orderResp := acme.Order{
			Status: acme.StatusPending,
		}

		if atomic.LoadInt32(&returnMismatchedIdentifiers) == 1 {
			// Return mismatched identifiers
			orderResp.Identifiers = []acme.Identifier{
				{Type: "dns", Value: "example.com"},
				{Type: "dns", Value: "example.com"},
			}
		} else {
			// Return matching identifiers
			orderResp.Identifiers = orderReq.Identifiers
		}

		err = tester.WriteJSONResponse(w, orderResp)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	})

	core, err := New(http.DefaultClient, "lego-test", apiURL+"/dir", "", privateKey)
	require.NoError(t, err)

	// Test case 1: Identifiers match (normal case)
	t.Run("matching identifiers", func(t *testing.T) {
		atomic.StoreInt32(&returnMismatchedIdentifiers, 0)

		domains := []string{"example.com", "*.example.com"}
		order, err := core.Orders.NewWithOptions(domains, nil)
		require.NoError(t, err)

		expected := []acme.Identifier{
			{Type: "dns", Value: "*.example.com"},
			{Type: "dns", Value: "example.com"},
		}
		assert.True(t, IdentifiersMatch(order.Identifiers, expected))
	})

	// Test case 2: Identifiers don't match (should return error)
	t.Run("mismatched identifiers", func(t *testing.T) {
		atomic.StoreInt32(&returnMismatchedIdentifiers, 1)

		domains := []string{"example.com", "*.example.com"}
		_, err := core.Orders.NewWithOptions(domains, nil)

		require.Error(t, err)
		assert.Contains(t, err.Error(), "Order Identifiers do not match")
		assert.Contains(t, err.Error(), "considered invalid as per RFC 8555")
	})
}

func readSignedBody(r *http.Request, privateKey *rsa.PrivateKey) ([]byte, error) {
	reqBody, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, err
	}

	sigAlgs := []jose.SignatureAlgorithm{jose.RS256}
	jws, err := jose.ParseSigned(string(reqBody), sigAlgs)
	if err != nil {
		return nil, err
	}

	body, err := jws.Verify(&jose.JSONWebKey{
		Key:       privateKey.Public(),
		Algorithm: "RSA",
	})
	if err != nil {
		return nil, err
	}

	return body, nil
}
