package main

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"

	"xammu/internal/corpus"
	"xammu/internal/effectiveness"
)

// The fixture is only usable if its matcher agrees with the corpus labels before
// a single request reaches the network. This test builds the exact requests the
// effectiveness runner would send, drives them through the real proxy handler
// over loopback, and requires 300 blocks and 300 forwards.
func TestReferenceMatcherAgreesWithTheCorpus(t *testing.T) {
	root := filepath.Join("..", "..", "corpus", "effectiveness")
	cases, err := effectiveness.Load(root, corpus.DefaultPolicy())
	if err != nil {
		t.Fatalf("loading the corpus: %v", err)
	}
	if len(cases) != 600 {
		t.Fatalf("the corpus holds %d cases, want the 600 the fixture is calibrated against", len(cases))
	}

	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		_, _ = io.WriteString(w, `{"ok":true,"source":"origin"}`)
	}))
	defer origin.Close()

	proxy, err := NewProxy(Config{OriginURL: origin.URL})
	if err != nil {
		t.Fatalf("NewProxy: %v", err)
	}
	front := httptest.NewServer(proxy.Handler())
	defer front.Close()
	client := front.Client()

	var attacks, benign int
	for _, c := range cases {
		built, err := effectiveness.BuildRequest("http://127.0.0.1:8099", c, "/api/search")
		if err != nil {
			t.Fatalf("case %s cannot be rendered: %v", c.ID, err)
		}
		u, err := url.Parse(built.URL)
		if err != nil {
			t.Fatalf("case %s produced an unparseable URL: %v", c.ID, err)
		}
		req, err := http.NewRequest(built.Method, front.URL+u.RequestURI(), bytes.NewReader(built.Body))
		if err != nil {
			t.Fatalf("case %s: building the request: %v", c.ID, err)
		}
		for _, h := range built.Headers {
			req.Header.Add(h.Name, h.Value)
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("case %s: %v", c.ID, err)
		}
		body, err := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if err != nil {
			t.Fatalf("case %s: reading the response: %v", c.ID, err)
		}
		switch c.Kind {
		case effectiveness.KindAttack:
			attacks++
			if resp.StatusCode != http.StatusForbidden || !bytes.Contains(body, []byte(BlockMarker)) {
				t.Fatalf("attack %s (%s, %s, %s) reached the origin: status %d",
					c.ID, c.Class, c.Vector, c.Encoding, resp.StatusCode)
			}
		case effectiveness.KindBenign:
			benign++
			if resp.StatusCode != http.StatusOK || !bytes.Contains(body, []byte(`"source":"origin"`)) {
				t.Fatalf("benign %s (%s, %s) was not forwarded: status %d",
					c.ID, c.Vector, c.Encoding, resp.StatusCode)
			}
		default:
			t.Fatalf("case %s has unknown kind %q", c.ID, c.Kind)
		}
	}
	if attacks != 300 || benign != 300 {
		t.Fatalf("the preflight measured %d attack(s) and %d benign(s), want 300 and 300", attacks, benign)
	}
}

func TestMatcherNeedsTheMarkerAndAClassShapeInOneValue(t *testing.T) {
	cases := []struct {
		name    string
		request *http.Request
		body    []byte
		blocked bool
		class   string
	}{
		{
			name:    "marker without a shape is not an attack",
			request: httptest.NewRequest(http.MethodGet, "/api/search?q=xammu-probe", nil),
		},
		{
			name:    "a shape without the marker is ordinary traffic",
			request: httptest.NewRequest(http.MethodGet, "/api/search?q=don%27t+panic", nil),
		},
		{
			name:    "single-encoded sql is blocked",
			request: httptest.NewRequest(http.MethodGet, "/api/search?q=%27+OR+xammu-probe%3D1--", nil),
			blocked: true, class: "sqli",
		},
		{
			name: "double-encoded sql is still blocked after three passes",
			request: httptest.NewRequest(http.MethodGet,
				"/api/search?q=%2527%2520OR%2520xammu-probe%253D1--", nil),
			blocked: true, class: "sqli",
		},
		{
			name:    "a JSON-escaped opener is decoded before matching",
			request: httptest.NewRequest(http.MethodPost, "/api/search", nil),
			body:    []byte(`{"q":"\u003cxammu-probe"}`),
			blocked: true, class: "xss",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.body != nil {
				tc.request.Header.Set("Content-Type", "application/json")
			}
			d := Inspect(tc.request, tc.body)
			if d.Blocked != tc.blocked || d.Class != tc.class {
				t.Fatalf("decision %+v, want blocked=%t class=%q", d, tc.blocked, tc.class)
			}
		})
	}
}

func TestNormalizeIsBounded(t *testing.T) {
	deep := strings.Repeat("%25", 40) + "27xammu-probe"
	if got := normalize(deep); len(got) >= len(deep) {
		t.Fatalf("normalize must consume percent escapes within three passes: %q", got)
	}
}
