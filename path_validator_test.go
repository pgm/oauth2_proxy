package main

import (
	"strings"
	"testing"

	"github.com/bmizerany/assert"
)

func init() {
	// log.SetFlags(log.Ldate | log.Ltime | log.Lshortfile)

}

func TestPathValidator(t *testing.T) {
	pv, err := parseUserPathWhitelistFromReader(strings.NewReader(`
	{"groups": [
		{"name": "sample1", "paths": ["/a"], "usernames": ["user@sample.com", "user2@sample.com"]},
		{"name": "sample2", "paths": ["/b"], "usernames": ["user@sample.com"]}
	]}
	`), "<testinput>")

	assert.Equal(t, nil, err)

	// confirm these two users need validation
	assert.T(t, pv.RequiresValidation("user@sample.com"))
	assert.T(t, pv.RequiresValidation("user2@sample.com"))

	// confirm user not in a group doesn't need validation
	assert.T(t, !pv.RequiresValidation("bad@sample.com"))

	// verify they have the expected path
	assert.T(t, pv.IsValid("user@sample.com", "/a/b/c"))
	assert.T(t, pv.IsValid("user2@sample.com", "/a/b/c"))
	assert.T(t, pv.IsValid("user@sample.com", "/a?x=true"))

	// and verify they don't have access to a random path
	assert.T(t, !pv.IsValid("user@sample.com", "/c/b/c"))
	assert.T(t, !pv.IsValid("user2@sample.com", "/c/b/c"))

	// check user which is not in any group
	assert.T(t, !pv.IsValid("bad@sample.com", "/a/b/c"))

	// check second path
	assert.T(t, pv.IsValid("user@sample.com", "/b/b/c"))
	assert.T(t, !pv.IsValid("user2@sample.com", "/b/b/c"))
	assert.T(t, pv.IsValid("user@sample.com", "/b?x=true"))

	// backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	// 	w.WriteHeader(200)
	// 	hostname, _, _ := net.SplitHostPort(r.Host)
	// 	w.Write([]byte(hostname))
	// }))
	// defer backend.Close()

	// backendURL, _ := url.Parse(backend.URL)
	// backendHostname, backendPort, _ := net.SplitHostPort(backendURL.Host)
	// backendHost := net.JoinHostPort(backendHostname, backendPort)
	// proxyURL, _ := url.Parse(backendURL.Scheme + "://" + backendHost + "/")

	// proxyHandler := NewReverseProxy(proxyURL)
	// setProxyUpstreamHostHeader(proxyHandler, proxyURL)
	// frontend := httptest.NewServer(proxyHandler)
	// defer frontend.Close()

	// getReq, _ := http.NewRequest("GET", frontend.URL, nil)
	// res, _ := http.DefaultClient.Do(getReq)
	// bodyBytes, _ := ioutil.ReadAll(res.Body)
	// if g, e := string(bodyBytes), backendHostname; g != e {
	// 	t.Errorf("got body %q; expected %q", g, e)
	// }
}
