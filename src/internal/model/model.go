// Package model loads the SysML model under .wasb/model through OpenSysML.
package model

import (
	"context"
	_ "embed"
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/Open-MBEE/OpenSysML/client/opensysml"
)

// Dir holds the model sources; UserDir holds the signature-protected part of it.
const (
	Dir     = ".wasb/model"
	UserDir = ".wasb/model/user"
)

//go:embed wasb.sysml
var library string

// Anchor points a model element at a concrete region of the repository.
type Anchor struct {
	Path, Kind, ID string
}

// Element is a model element that carries wasb metadata.
type Element struct {
	ID string
	// Files are the repo-relative model files declaring the element's top-level namespace.
	Files        []string
	Anchor       *Anchor
	LastHash     string
	Detached     bool
	UserDeclared bool
}

// Load parses the model files (repo-relative) together with the wasb library
// and returns every element carrying wasb metadata.
func Load(ctx context.Context, root string, files []string) ([]Element, error) {
	c, err := opensysml.New()
	if err != nil {
		return nil, err
	}
	defer func() { _ = c.Close() }()

	docs := []opensysml.Document{opensysml.Source("wasb.sysml", library)}
	for _, f := range files {
		docs = append(docs, opensysml.File(filepath.Join(root, f)))
	}
	m, err := c.ParseDocuments(ctx, docs)
	if err != nil {
		return nil, err
	}
	if diags := m.Errors(); len(diags) > 0 {
		errs := make([]error, len(diags))
		for i, d := range diags {
			errs[i] = errors.New(d.String())
		}
		return nil, fmt.Errorf("model does not parse: %w", errors.Join(errs...))
	}

	// Roots[0] is the library; the rest follow files in order.
	filesOf := map[string][]string{}
	for i, r := range m.Roots[1:] {
		for _, id := range r.ChildIDs {
			filesOf[id] = append(filesOf[id], files[i])
		}
	}

	all, err := c.Query(ctx, m, opensysml.Query{Select: []string{"@type"}})
	if err != nil {
		return nil, err
	}
	var elems []Element
	for _, q := range all {
		top, _, _ := strings.Cut(q.ID, "::")
		if top == "WASB" || strings.Contains(q.ID, "::@") {
			continue
		}
		e, err := read(ctx, c, m, q.ID)
		if err != nil {
			return nil, err
		}
		if e.Anchor != nil || e.LastHash != "" || e.Detached || e.UserDeclared {
			e.Files = filesOf[top]
			elems = append(elems, e)
		}
	}
	return elems, nil
}

// read evaluates the wasb metadata of one element.
func read(ctx context.Context, c opensysml.Client, m *opensysml.Model, id string) (Element, error) {
	e := Element{ID: id}
	meta := quote(id) + ".metadata"
	eval := func(expr string) ([]string, error) {
		v, err := c.Evaluate(ctx, m, expr)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", id, err)
		}
		seq, ok := v.(opensysml.Sequence)
		if !ok {
			seq = opensysml.Sequence{v}
		}
		var out []string
		for _, x := range seq {
			s, _ := x.(opensysml.String)
			out = append(out, string(s))
		}
		return out, nil
	}

	a := "(" + meta + " as WASB::Anchor)"
	anchor, err := eval("(" + a + ".path, " + a + ".kind, " + a + ".id)")
	if err != nil {
		return e, err
	}
	switch len(anchor) {
	case 0:
	case 3:
		e.Anchor = &Anchor{Path: anchor[0], Kind: anchor[1], ID: anchor[2]}
	default:
		return e, fmt.Errorf("%s: an element takes one Anchor with path, kind and id set", id)
	}

	hash, err := eval("(" + meta + " as WASB::Coverage).lastHash")
	if err != nil {
		return e, err
	}
	if len(hash) > 0 {
		e.LastHash = hash[0]
	}

	detached, err := eval(meta + " as WASB::Detached")
	if err != nil {
		return e, err
	}
	user, err := eval(meta + " as WASB::UserDeclared")
	if err != nil {
		return e, err
	}
	e.Detached, e.UserDeclared = len(detached) > 0, len(user) > 0
	return e, nil
}

var ident = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// quote writes a qualified name as an expression, quoting segments that are not identifiers.
func quote(id string) string {
	parts := strings.Split(id, "::")
	for i, p := range parts {
		if !ident.MatchString(p) {
			parts[i] = "'" + strings.ReplaceAll(p, "'", `\'`) + "'"
		}
	}
	return strings.Join(parts, "::")
}
