package contracts_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"testing"

	"xammu/internal/contracts"
)

// The two criteria these tests enforce are about the source, not about a sample
// record: no numeric confidence scale may exist (JAVI-021), and no contract type may
// declare a severity or score key. A fixture-based check catches a field added to a
// type the fixtures cover; this walk catches one added to any type in the shipped
// tree, including the internal types the report and discovery layers build on.
//
// lab/ is deliberately out of scope: it is the fixture the tool measures, and its
// own diagnostic log is free to have a severity field. cmd/ and internal/ are the
// tool.

var scaleStems = []string{"confidence", "severity", "riskscore", "score"}

func shippedGoFiles(t *testing.T) (files []string, root string) {
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

func where(root, path string, pos token.Pos, fileset *token.FileSet) string {
	rel, err := filepath.Rel(root, path)
	if err != nil {
		rel = path
	}
	return filepath.ToSlash(rel) + ":" + strconv.Itoa(fileset.Position(pos).Line)
}

func TestNoForbiddenIdentifierInTheShippedTree(t *testing.T) {
	files, root := shippedGoFiles(t)
	if len(files) < 20 {
		t.Fatalf("the walk saw %d files, which is too few to call this a repo-wide check", len(files))
	}
	if len(contracts.ForbiddenSymbols) == 0 {
		t.Fatal("the denylist is empty: this test would pass over any tree")
	}

	forbidden := map[string]bool{}
	for _, s := range contracts.ForbiddenSymbols {
		forbidden[s] = true
	}
	var hits []string
	for _, path := range files {
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
		ast.Inspect(f, func(n ast.Node) bool {
			id, ok := n.(*ast.Ident)
			if !ok {
				return true
			}
			if forbidden[id.Name] {
				hits = append(hits, where(root, path, id.Pos(), fset)+": "+id.Name)
			}
			return true
		})
	}
	if len(hits) > 0 {
		t.Fatalf("v1.0.0 has no numeric confidence scale, yet these identifiers exist:\n%s",
			strings.Join(hits, "\n"))
	}
}

// TestNoNumericScaleIsDeclaredAnywhere widens the exact-match rule to declared
// names: a field called Confidence or a function returning a SeverityScore would
// reintroduce the scale under a synonym the exact list does not carry.
func TestNoNumericScaleIsDeclaredAnywhere(t *testing.T) {
	files, root := shippedGoFiles(t)
	var hits []string
	check := func(name string, fset *token.FileSet, path string, pos token.Pos) {
		lower := strings.ToLower(name)
		for _, stem := range scaleStems {
			if strings.Contains(lower, stem) {
				hits = append(hits, where(root, path, pos, fset)+": "+name)
				return
			}
		}
	}
	for _, path := range files {
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
		ast.Inspect(f, func(n ast.Node) bool {
			switch d := n.(type) {
			case *ast.FuncDecl:
				check(d.Name.Name, fset, path, d.Name.Pos())
			case *ast.TypeSpec:
				check(d.Name.Name, fset, path, d.Name.Pos())
			case *ast.ValueSpec:
				for _, name := range d.Names {
					check(name.Name, fset, path, name.Pos())
				}
			case *ast.Field:
				for _, name := range d.Names {
					check(name.Name, fset, path, name.Pos())
				}
			}
			return true
		})
	}
	if len(hits) > 0 {
		t.Fatalf("a declared name reintroduces a numeric scale:\n%s", strings.Join(hits, "\n"))
	}
}

// TestNoForbiddenJSONKeyInAStructTag is the serialized half of the same rule: a type
// may not emit a key the ingest denylist forbids, whichever package declares it.
func TestNoForbiddenJSONKeyInAStructTag(t *testing.T) {
	files, root := shippedGoFiles(t)
	forbidden := map[string]bool{}
	for _, key := range contracts.ForbiddenJSONKeyNames() {
		forbidden[key] = true
	}
	if len(forbidden) == 0 {
		t.Fatal("the JSON key denylist is empty")
	}

	var hits []string
	for _, path := range files {
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
		ast.Inspect(f, func(n ast.Node) bool {
			st, ok := n.(*ast.StructType)
			if !ok || st.Fields == nil {
				return true
			}
			for _, field := range st.Fields.List {
				if field.Tag == nil {
					continue
				}
				tag, err := strconv.Unquote(field.Tag.Value)
				if err != nil {
					continue
				}
				key, ok := reflect.StructTag(tag).Lookup("json")
				if !ok {
					continue
				}
				name := strings.Split(key, ",")[0]
				if forbidden[name] {
					hits = append(hits, where(root, path, field.Tag.Pos(), fset)+": json key "+name)
				}
			}
			return true
		})
	}
	if len(hits) > 0 {
		t.Fatalf("a stored contract would carry a forbidden key:\n%s", strings.Join(hits, "\n"))
	}
}
