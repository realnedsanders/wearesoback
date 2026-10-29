package gate

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"go/ast"
	"go/format"
	"go/parser"
	"go/token"
	"io"
	"maps"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"go.yaml.in/yaml/v3"

	"github.com/realnedsanders/wearesoback/src/internal/git"
	"github.com/realnedsanders/wearesoback/src/internal/model"
)

// Target is a concrete region of the repository that must be modeled.
type Target struct {
	Kind, Path, ID string
	File           string
	Line           int
	// Hash is the structural hash a model element records in Coverage.lastHash.
	Hash string
	// Attrs are the kind's attributes as SysML literals; unknown ones are absent.
	Attrs map[string]string
	// Fraction is the share of the target the model generates.
	Fraction float64
}

// SysML writes the model element that anchors t.
func (t Target) SysML() string {
	k := model.Kinds[t.Kind]
	var b strings.Builder
	fmt.Fprintf(&b, "%s %s : WASB::%s {\n", k.Usage, model.Name(t.Path+"#"+t.ID), k.Def)
	fmt.Fprintf(&b, "    @WASB::Anchor { path = %s; kind = %s; id = %s; }\n", model.Literal(t.Path), model.Literal(t.Kind), model.Literal(t.ID))
	fmt.Fprintf(&b, "    @WASB::Coverage { lastHash = %s; }\n", model.Literal(t.Hash))
	for _, a := range k.Attrs {
		if v, ok := t.Attrs[a.Name]; ok {
			fmt.Fprintf(&b, "    :>> %s = %s;\n", a.Name, v)
		}
	}
	b.WriteString("}\n")
	return b.String()
}

// Scan is what the scanners found.
type Scan struct {
	Targets []Target
	// Examined are the files a scanner read; Skipped are files it could not, with why.
	Examined []string
	Skipped  map[string]string
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

// Targets scans Go sources, zarf.yaml, Helm charts, UDS Package CRs, UDS tasks and GitHub Actions workflows.
func Targets(root string, files []string) (*Scan, error) {
	s := &Scan{Skipped: map[string]string{}}
	var templates []string // template dir prefixes of every chart
	for _, f := range files {
		if path.Base(f) == "Chart.yaml" {
			templates = append(templates, strings.TrimPrefix(path.Dir(f)+"/", "./")+"templates/")
		}
	}
	for _, f := range files {
		if strings.HasPrefix(f, ".wasb/") {
			continue
		}
		yamlFile := strings.HasSuffix(f, ".yaml") || strings.HasSuffix(f, ".yml")
		chart := slices.IndexFunc(templates, func(t string) bool { return strings.HasPrefix(f, t) })
		var b []byte
		if yamlFile || chart >= 0 {
			var err error
			if b, err = os.ReadFile(filepath.Join(root, f)); err != nil {
				return nil, err
			}
		}
		var ts []Target
		var err error
		switch {
		case strings.HasSuffix(f, ".go") && !strings.HasSuffix(f, "_test.go") && !skipGo(f):
			ts, err = goTargets(root, f)
		case path.Base(f) == "zarf.yaml":
			ts, err = zarfTargets(f, b)
		case chart >= 0:
			dir := strings.TrimSuffix(templates[chart], "templates/")
			ts = []Target{{Kind: "helm.template", Path: strings.TrimSuffix(dir, "/"), ID: strings.TrimPrefix(f, templates[chart]), File: f, Line: 1, Hash: hash(b), Fraction: 1}}
			if bytes.Contains(b, []byte("uds.dev/")) {
				crs, cerr := udsTargets(f, untemplate(b))
				if cerr != nil {
					s.Skipped[f] = "UDS Package CR: " + cerr.Error()
				}
				ts = append(ts, crs...)
			}
		case yamlFile && strings.HasPrefix(f, ".github/workflows/"):
			ts, err = ghaTargets(f, b)
		case yamlFile && (path.Base(f) == "tasks.yaml" || slices.Contains(strings.Split(path.Dir(f), "/"), "tasks")):
			ts, err = taskTargets(f, b)
		case yamlFile && bytes.Contains(b, []byte("uds.dev/")):
			if ts, err = udsTargets(f, b); err != nil {
				s.Skipped[f], err = "UDS Package CR: "+err.Error(), nil
			}
		default:
			continue
		}
		if err != nil {
			return nil, err
		}
		s.Examined = append(s.Examined, f)
		s.Targets = append(s.Targets, ts...)
	}
	return s, nil
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
// The hash and the signature attribute cover the signature, not the body.
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
		start, end := fset.Position(fn.Pos()).Line, fset.Position(fn.End()).Line
		fraction := 1.0
		if fn.Body != nil {
			fraction = float64(fset.Position(fn.Body.Lbrace).Line-start+1) / float64(end-start+1)
		}
		ts = append(ts, Target{
			Kind: "go.func", Path: path.Dir(f), ID: id, File: f, Line: start, Hash: hash(buf.Bytes()),
			Attrs:    map[string]string{"signature": model.Literal(strings.Join(strings.Fields(buf.String()), " "))},
			Fraction: fraction,
		})
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
func zarfTargets(f string, b []byte) ([]Target, error) {
	var pkg struct {
		Components []yaml.Node `yaml:"components"`
	}
	if err := yaml.Unmarshal(b, &pkg); err != nil {
		return nil, fmt.Errorf("%s: %w", f, err)
	}
	ids := ids{}
	var ts []Target
	for i := range pkg.Components {
		n := &pkg.Components[i]
		var c struct {
			Name string `yaml:"name"`
			Only struct {
				Flavor string `yaml:"flavor"`
			} `yaml:"only"`
		}
		if err := n.Decode(&c); err != nil {
			return nil, fmt.Errorf("%s:%d: %w", f, n.Line, err)
		}
		id := c.Name
		if c.Only.Flavor != "" {
			id += "[" + c.Only.Flavor + "]"
		}
		t, err := entry("zarf.component", f, f, ids.next(id), n)
		if err != nil {
			return nil, err
		}
		ts = append(ts, t)
	}
	return ts, nil
}

// udsTargets returns the network allow and expose rules, SSO clients and
// monitors of every UDS Package CR in b.
func udsTargets(f string, b []byte) ([]Target, error) {
	docs, err := documents(b)
	if err != nil {
		return nil, err
	}
	seen := map[string]ids{"uds.allow": {}, "uds.expose": {}, "uds.sso": {}, "uds.monitor": {}}
	var ts []Target
	for _, doc := range docs {
		var head struct {
			APIVersion string `yaml:"apiVersion"`
			Kind       string `yaml:"kind"`
		}
		if err := doc.Decode(&head); err != nil || !strings.HasPrefix(head.APIVersion, "uds.dev/") || head.Kind != "Package" {
			continue
		}
		spec := get(doc, "spec")
		for _, list := range []struct {
			kind string
			node *yaml.Node
		}{
			{"uds.allow", get(get(spec, "network"), "allow")},
			{"uds.expose", get(get(spec, "network"), "expose")},
			{"uds.sso", get(spec, "sso")},
			{"uds.monitor", get(spec, "monitor")},
		} {
			if list.node == nil || list.node.Kind != yaml.SequenceNode {
				continue
			}
			for _, n := range list.node.Content {
				var v any
				if err := n.Decode(&v); err != nil {
					return nil, fmt.Errorf("%s:%d: %w", f, n.Line, err)
				}
				t, err := entry(list.kind, f, f, seen[list.kind].next(entryID(v)), n)
				if err != nil {
					return nil, err
				}
				ts = append(ts, t)
			}
		}
	}
	return ts, nil
}

// taskTargets returns one target per UDS runner task.
func taskTargets(f string, b []byte) ([]Target, error) {
	docs, err := documents(b)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", f, err)
	}
	ids := ids{}
	var ts []Target
	for _, doc := range docs {
		tasks := get(doc, "tasks")
		if tasks == nil || tasks.Kind != yaml.SequenceNode {
			continue
		}
		for _, n := range tasks.Content {
			name := get(n, "name")
			if name == nil {
				continue
			}
			t, err := entry("uds.task", f, f, ids.next(name.Value), n)
			if err != nil {
				return nil, err
			}
			ts = append(ts, t)
		}
	}
	return ts, nil
}

// ghaTargets returns one target per GitHub Actions job.
func ghaTargets(f string, b []byte) ([]Target, error) {
	docs, err := documents(b)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", f, err)
	}
	var ts []Target
	for _, doc := range docs {
		jobs := get(doc, "jobs")
		if jobs == nil || jobs.Kind != yaml.MappingNode {
			continue
		}
		for i := 0; i+1 < len(jobs.Content); i += 2 {
			t, err := entry("gha.job", f, f, jobs.Content[i].Value, jobs.Content[i+1])
			if err != nil {
				return nil, err
			}
			t.Line = jobs.Content[i].Line
			ts = append(ts, t)
		}
	}
	return ts, nil
}

// entry builds a target from a YAML node: the hash covers the whole node,
// without comments or layout, and the attributes come from its keys.
func entry(kind, p, f, id string, n *yaml.Node) (Target, error) {
	var v any
	if err := n.Decode(&v); err != nil {
		return Target{}, fmt.Errorf("%s:%d: %w", f, n.Line, err)
	}
	canon, err := yaml.Marshal(v) // sorts keys
	if err != nil {
		return Target{}, fmt.Errorf("%s:%d: %w", f, n.Line, err)
	}
	attrs := map[string]string{}
	for _, a := range model.Kinds[kind].Attrs {
		x := v
		for _, k := range strings.Split(a.Key, ".") {
			m, _ := x.(map[string]any)
			x = m[k]
		}
		switch x := x.(type) {
		case string:
			if a.Type == "String" && !strings.Contains(x, templated) {
				attrs[a.Name] = model.Literal(x)
			}
		case int:
			if a.Type == "Integer" {
				attrs[a.Name] = model.Literal(x)
			}
		case bool:
			if a.Type == "Boolean" {
				attrs[a.Name] = model.Literal(x)
			}
		}
	}
	return Target{Kind: kind, Path: p, ID: id, File: f, Line: n.Line, Hash: hash(canon), Attrs: attrs, Fraction: 1}, nil
}

// entryID names a list entry by its description, else by its scalar fields.
func entryID(v any) string {
	m, _ := v.(map[string]any)
	if d, ok := m["description"].(string); ok && d != "" {
		return d
	}
	var parts []string
	for _, k := range slices.Sorted(maps.Keys(m)) {
		if x := fmt.Sprint(m[k]); !strings.Contains(x, templated) {
			switch m[k].(type) {
			case string, int, bool, float64:
				parts = append(parts, k+"="+x)
			}
		}
	}
	return strings.Join(parts, " ")
}

// ids makes repeated ids unique in order of appearance.
type ids map[string]int

func (s ids) next(id string) string {
	if s[id]++; s[id] > 1 {
		return fmt.Sprintf("%s#%d", id, s[id])
	}
	return id
}

func documents(b []byte) ([]*yaml.Node, error) {
	dec := yaml.NewDecoder(bytes.NewReader(b))
	var docs []*yaml.Node
	for {
		var n yaml.Node
		err := dec.Decode(&n)
		if errors.Is(err, io.EOF) {
			return docs, nil
		}
		if err != nil {
			return nil, err
		}
		if len(n.Content) > 0 {
			docs = append(docs, n.Content[0])
		}
	}
}

// get returns the value of key in a mapping node, nil when absent.
func get(n *yaml.Node, key string) *yaml.Node {
	if n == nil || n.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(n.Content); i += 2 {
		if n.Content[i].Value == key {
			return n.Content[i+1]
		}
	}
	return nil
}

var (
	directiveLine = regexp.MustCompile(`(?m)^[ \t]*\{\{.*\}\}[ \t]*$`)
	directive     = regexp.MustCompile(`\{\{.*?\}\}`)
)

// templated stands in for a value a Helm directive computes.
const templated = "WASB_TEMPLATED"

// untemplate blanks Helm directives so the template reads as YAML; line numbers are kept.
func untemplate(b []byte) []byte {
	return directive.ReplaceAll(directiveLine.ReplaceAll(b, nil), []byte(templated))
}

func hash(b []byte) string {
	return fmt.Sprintf("%x", sha256.Sum256(b))[:16]
}
