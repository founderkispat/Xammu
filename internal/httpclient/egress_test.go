package httpclient_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// Criterion 29 is an architectural property: XAMMU reaches the network through one
// authorized egress. internal/httpclient owns that egress; every other package hands
// it a request and never opens a connection of its own. A test cannot observe a
// connection that was never made, so this walks the shipped source instead and fails
// on the constructs that could make one.
//
// Test files are excluded: httptest servers in tests exist to answer requests, not to
// send them. lab/ is excluded for the same reason it exists at all: it is the target.
var connectionOpeners = map[string]string{
	"net.Dial":                   "opens a socket",
	"net.DialTimeout":            "opens a socket",
	"net.Dialer":                 "holds the dialer that opens sockets",
	"net.Listen":                 "listens instead of sending",
	"net.ListenConfig":           "listens instead of sending",
	"net.ListenPacket":           "listens instead of sending",
	"net.ListenTCP":              "listens instead of sending",
	"net.ListenUDP":              "listens instead of sending",
	"tls.Dial":                   "opens an encrypted socket",
	"tls.DialWithDialer":         "opens an encrypted socket",
	"http.Client":                "carries its own transport and connection pool",
	"http.DefaultClient":         "carries its own transport and connection pool",
	"http.DefaultTransport":      "carries its own connection pool",
	"http.Transport":             "carries its own connection pool",
	"http.Get":                   "sends without passing the egress",
	"http.Post":                  "sends without passing the egress",
	"http.PostForm":              "sends without passing the egress",
	"http.Head":                  "sends without passing the egress",
	"http.NewRequest":            "builds a request outside the egress",
	"http.NewRequestWithContext": "builds a request outside the egress",
	"http.ListenAndServe":        "serves traffic",
	"http.ListenAndServeTLS":     "serves traffic",
	"http.Serve":                 "serves traffic",
	"http.ServeTLS":              "serves traffic",
}

func shippedSources(t *testing.T) (files []string, root string) {
	t.Helper()
	abs, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatalf("module root: %v", err)
	}
	for _, dir := range []string{"cmd", "internal"} {
		err := filepath.WalkDir(filepath.Join(abs, dir), func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			name := d.Name()
			if d.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
				return nil
			}
			files = append(files, path)
			return nil
		})
		if err != nil {
			t.Fatalf("walk %s: %v", dir, err)
		}
	}
	sort.Strings(files)
	return files, abs
}

func TestOnlyTheEgressOpensConnections(t *testing.T) {
	files, root := shippedSources(t)
	if len(files) < 20 {
		t.Fatalf("the walk saw %d files, which is too few to call this a repo-wide check", len(files))
	}

	var outside []string
	foundInside := map[string]int{}
	for _, path := range files {
		rel, err := filepath.Rel(root, path)
		if err != nil {
			rel = path
		}
		rel = filepath.ToSlash(rel)
		isEgress := strings.HasPrefix(rel, "internal/httpclient/")

		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", rel, err)
		}
		ast.Inspect(f, func(n ast.Node) bool {
			sel, ok := n.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			base, ok := sel.X.(*ast.Ident)
			if !ok {
				return true
			}
			name := base.Name + "." + sel.Sel.Name
			if _, banned := connectionOpeners[name]; !banned {
				return true
			}
			if isEgress {
				foundInside[name]++
				return true
			}
			outside = append(outside, rel+":"+strconv.Itoa(fset.Position(sel.Pos()).Line)+": "+name)
			return true
		})
	}
	if len(outside) > 0 {
		t.Fatalf("the single authorized egress is internal/httpclient; these bypass it:\n%s",
			strings.Join(outside, "\n"))
	}
	// Without this the test would pass just as well if the scanner broke: prove it can
	// see the constructs it is looking for where they are allowed to live.
	for _, name := range []string{"http.Client", "net.Dialer"} {
		if foundInside[name] == 0 {
			t.Errorf("no %s found in internal/httpclient: the scanner is not seeing the egress", name)
		}
	}
}

// TestNoDotImportOfTheNetworkPackages closes the loophole the selector walk leaves: a
// dot-imported net or net/http would let Dial or Get be called without a selector.
func TestNoDotImportOfTheNetworkPackages(t *testing.T) {
	files, root := shippedSources(t)
	var hits []string
	for _, path := range files {
		rel, err := filepath.Rel(root, path)
		if err != nil {
			rel = path
		}
		rel = filepath.ToSlash(rel)
		if strings.HasPrefix(rel, "internal/httpclient/") {
			continue
		}
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", rel, err)
		}
		for _, imp := range f.Imports {
			if imp.Name == nil || imp.Name.Name != "." {
				continue
			}
			target, err := strconv.Unquote(imp.Path.Value)
			if err != nil {
				continue
			}
			switch target {
			case "net", "net/http", "net/http/httptrace", "crypto/tls":
				hits = append(hits, rel+":"+strconv.Itoa(fset.Position(imp.Pos()).Line)+": . "+target)
			}
		}
	}
	if len(hits) > 0 {
		t.Fatalf("a dot-import hides connection calls from review:\n%s", strings.Join(hits, "\n"))
	}
}
