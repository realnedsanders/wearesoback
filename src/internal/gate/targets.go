package gate

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/format"
	"go/parser"
	"go/token"
	"os"
	"path"
	"path/filepath"
	"strings"

	"go.yaml.in/yaml/v3"

	"github.com/realnedsanders/wearesoback/src/internal/git"
)

// Target is a concrete region of the repository that must be modeled.
type Target struct {
	Kind, Path, ID string
	File           string
	Line           int
	// Hash is the structural hash a model element records in Coverage.lastHash.
	Hash string
}

// Files lists tracked and untracked, non-ignored files that exist, repo-relative.
func Files(root string) ([]string, error) {
	out, err := git.Run(root, nil, "ls-files", "-z", "--cached", "--others", "--exclude-standard")
	if err != nil {
		return nil, err
	}
	var files []string
	for _, f := range strings.Split(out, "\x00") {
		if _, err := os.Stat(filepath.Join(root, f)); f != "" && err == nil {
			files = append(files, f)
		}
	}
	return files, nil
}

// Targets scans Go sources and zarf.yaml files.
func Targets(root string, files []string) ([]Target, error) {
	var ts []Target
	for _, f := range files {
		var found []Target
		var err error
		switch {
		case path.Base(f) == "zarf.yaml":
			found, err = zarfTargets(root, f)
		case strings.HasSuffix(f, ".go") && !strings.HasSuffix(f, "_test.go") && !skipGo(f):
			found, err = goTargets(root, f)
		}
		if err != nil {
			return nil, err
		}
		ts = append(ts, found...)
	}
	return ts, nil
}

func skipGo(f string) bool {
	for _, seg := range strings.Split(path.Dir(f), "/") {
		if seg == "vendor" || seg == "testdata" {
			return true
		}
	}
	return false
}

// goTargets returns exported functions and exported methods of exported types.
// The hash covers the signature, not the body.
func goTargets(root, f string) ([]Target, error) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, filepath.Join(root, f), nil, parser.SkipObjectResolution)
	if err != nil {
		return nil, err
	}
	var ts []Target
	for _, d := range file.Decls {
		fn, ok := d.(*ast.FuncDecl)
		if !ok || !fn.Name.IsExported() {
			continue
		}
		id := fn.Name.Name
		if fn.Recv != nil {
			recv := recvName(fn.Recv.List[0].Type)
			if !ast.IsExported(recv) {
				continue
			}
			id = recv + "." + id
		}
		sig := *fn
		sig.Body, sig.Doc = nil, nil
		var buf bytes.Buffer
		if err := format.Node(&buf, fset, &sig); err != nil {
			return nil, err
		}
		ts = append(ts, Target{Kind: "go.func", Path: path.Dir(f), ID: id, File: f, Line: fset.Position(fn.Pos()).Line, Hash: hash(buf.Bytes())})
	}
	return ts, nil
}

func recvName(e ast.Expr) string {
	switch t := e.(type) {
	case *ast.StarExpr:
		return recvName(t.X)
	case *ast.IndexExpr:
		return recvName(t.X)
	case *ast.IndexListExpr:
		return recvName(t.X)
	case *ast.Ident:
		return t.Name
	}
	return ""
}

// zarfTargets returns one target per component, keyed by name and flavor.
// The hash covers the whole component.
func zarfTargets(root, f string) ([]Target, error) {
	b, err := os.ReadFile(filepath.Join(root, f))
	if err != nil {
		return nil, err
	}
	var pkg struct {
		Components []yaml.Node `yaml:"components"`
	}
	if err := yaml.Unmarshal(b, &pkg); err != nil {
		return nil, fmt.Errorf("%s: %w", f, err)
	}
	var ts []Target
	seen := map[string]int{}
	for _, n := range pkg.Components {
		var c struct {
			Name string `yaml:"name"`
			Only struct {
				Flavor string `yaml:"flavor"`
			} `yaml:"only"`
		}
		var whole any
		if err := n.Decode(&c); err != nil {
			return nil, fmt.Errorf("%s:%d: %w", f, n.Line, err)
		}
		if err := n.Decode(&whole); err != nil {
			return nil, fmt.Errorf("%s:%d: %w", f, n.Line, err)
		}
		canon, err := json.Marshal(whole) // sorts keys, drops comments and layout
		if err != nil {
			return nil, fmt.Errorf("%s:%d: %w", f, n.Line, err)
		}
		id := c.Name
		if c.Only.Flavor != "" {
			id += "[" + c.Only.Flavor + "]"
		}
		if seen[id]++; seen[id] > 1 {
			id += fmt.Sprintf("#%d", seen[id])
		}
		ts = append(ts, Target{Kind: "zarf.component", Path: f, ID: id, File: f, Line: n.Line, Hash: hash(canon)})
	}
	return ts, nil
}

func hash(b []byte) string {
	return fmt.Sprintf("%x", sha256.Sum256(b))[:16]
}
