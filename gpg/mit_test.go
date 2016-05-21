package gpg

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func testServer() *httptest.Server {
	http.HandleFunc("/pks/lookup", func(w http.ResponseWriter, r *http.Request) {
		var file string
		if r.URL.Query().Get("op") == "get" {
			file = "fixtures/mit_test_key.html"
		} else {
			file = "fixtures/mit_test_keysearch.html"
		}
		http.ServeFile(w, r, file)
	})
	server := httptest.NewServer(http.DefaultServeMux)
	return server
}

func TestSearch(t *testing.T) {
	server := testServer()
	MITHost = server.URL
	client := new(http.Client)
	email := "jeff@bigboy.us"
	result, err := SearchEmailMIT(email, client)
	if err != nil {
		t.Fatalf("There should be results: %v", err)
	}
	var identityFound bool
	for _, i := range result.Identities {
		if i.UserId.Email == email {
			identityFound = true
		}
	}
	if !identityFound {
		t.Errorf("Email not found in identity (%v) for email (%v)", result, email)
	}
}
