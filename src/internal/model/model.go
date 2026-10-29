// Package model loads the SysML model under .wasb/model through OpenSysML.
package model

import (
	"context"
	_ "embed"
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"github.com/Open-MBEE/OpenSysML/client/opensysml"
)

// Dir holds the model sources; UserDir holds the signature-protected part of it.
const (
	Dir     = ".wasb/model"
	UserDir = ".wasb/model/user"
)

//go:embed wasb.sysml
var embedded string

// Library is the wasb vocabulary every model is parsed with.
var Library = strings.Replace(embedded, "    /* kinds */\n", kindDefs(), 1)

// Anchor points a model element at a concrete region of the repository.
type Anchor struct {
	Path, Kind, ID string
}

// Element is a model element that carries wasb metadata.
type Element struct {
	ID string
	// Files are the repo-relative model files declaring the element's top-level namespace.
	Files    []string
	Anchor   *Anchor
	LastHash string
	// MinFraction is Coverage.generatedFraction, 0 when unset.
	MinFraction float64
	// Attrs are the anchor kind's attributes as SysML literals; unset ones are absent.
	Attrs          map[string]string
	Detached       bool
	UserDeclared   bool
	AgentSuggested bool
	KnownGaps      []string
}

// Requirement is a requirement definition or usage outside the wasb library.
type Requirement struct {
	ID string
	// Evidence is the EvidenceClassKind literal, its own or its definition's; empty when missing.
	Evidence     string
	Usage        bool // a requirement usage, not a definition
	UserDeclared bool
	Files        []string
	// Claimed is set when a satisfy assertion names the requirement.
	Claimed bool
}

// Verdict is one satisfy assertion's answer.
type Verdict struct {
	Requirement string `json:"requirement"`
	Assertion   string `json:"assertion"`
	Status      string `json:"status"` // holds, violated or undecided
	Condition   string `json:"condition,omitempty"`
	Error       string `json:"error,omitempty"`
}

// Model is a parsed model. Close releases it.
type Model struct {
	Elements     []Element
	Requirements []Requirement
	client       opensysml.Client
	parsed       *opensysml.Model
}

// Load parses the model files (repo-relative) with the wasb library.
// overrides replace or add files by path, for evaluating a proposal.
func Load(ctx context.Context, root string, files []string, overrides map[string]string) (*Model, error) {
	c, err := opensysml.New()
	if err != nil {
		return nil, err
	}
	m := &Model{client: c}
	if err := m.load(ctx, root, files, overrides); err != nil {
		m.Close()
		return nil, err
	}
	return m, nil
}

// Close releases the engine.
func (m *Model) Close() { _ = m.client.Close() }

func (m *Model) load(ctx context.Context, root string, files []string, overrides map[string]string) error {
	paths := slices.Clone(files)
	for p := range overrides {
		if !slices.Contains(paths, p) {
			paths = append(paths, p)
		}
	}
	slices.Sort(paths)
	paths = slices.Compact(paths)
	docs := []opensysml.Document{opensysml.Source("wasb.sysml", Library)}
	for _, p := range paths {
		if content, ok := overrides[p]; ok {
			docs = append(docs, opensysml.Source(p, content))
		} else {
			docs = append(docs, opensysml.File(filepath.Join(root, p)))
		}
	}
	parsed, err := m.client.ParseDocuments(ctx, docs)
	if err != nil {
		return err
	}
	if diags := parsed.Errors(); len(diags) > 0 {
		errs := make([]error, len(diags))
		for i, d := range diags {
			errs[i] = errors.New(d.String())
		}
		return fmt.Errorf("model does not parse: %w", errors.Join(errs...))
	}
	m.parsed = parsed

	// Roots[0] is the library; the rest follow paths in order.
	filesOf := map[string][]string{}
	for i, r := range parsed.Roots[1:] {
		for _, id := range r.ChildIDs {
			filesOf[id] = append(filesOf[id], paths[i])
		}
	}

	all, err := m.client.Query(ctx, parsed, opensysml.Query{Select: []string{"@type", "type", "satisfiedRequirement"}})
	if err != nil {
		return err
	}
	claimed := map[string]bool{}
	for _, q := range all {
		if q.Type == "SatisfyRequirementUsage" {
			claimed[q.Properties["satisfiedRequirement"]] = true
		}
	}
	for _, q := range all {
		top, _, _ := strings.Cut(q.ID, "::")
		if strings.Contains(q.ID, "::@") {
			continue
		}
		e, err := m.read(ctx, q.ID)
		if err != nil {
			return err
		}
		if top == "WASB" {
			if len(e.KnownGaps) > 0 {
				m.Elements = append(m.Elements, Element{ID: e.ID, KnownGaps: e.KnownGaps})
			}
			continue
		}
		e.Files = filesOf[top]
		if q.Type == "RequirementDefinition" || q.Type == "RequirementUsage" {
			evidence, err := m.evidence(ctx, q.ID)
			if err != nil {
				return err
			}
			if def := q.Properties["type"]; evidence == "" && def != "" {
				if evidence, err = m.evidence(ctx, def); err != nil {
					return err
				}
			}
			m.Requirements = append(m.Requirements, Requirement{ID: q.ID, Evidence: evidence, Usage: q.Type == "RequirementUsage", UserDeclared: e.UserDeclared, Files: e.Files, Claimed: claimed[q.ID]})
		}
		if e.Anchor != nil || e.LastHash != "" || e.Detached || e.UserDeclared || e.AgentSuggested || len(e.KnownGaps) > 0 {
			m.Elements = append(m.Elements, e)
		}
	}
	return nil
}

func (m *Model) eval(ctx context.Context, id, expr string) (opensysml.Sequence, error) {
	v, err := m.client.Evaluate(ctx, m.parsed, expr)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", id, err)
	}
	if seq, ok := v.(opensysml.Sequence); ok {
		return seq, nil
	}
	return opensysml.Sequence{v}, nil
}

func (m *Model) strs(ctx context.Context, id, expr string) ([]string, error) {
	seq, err := m.eval(ctx, id, expr)
	var out []string
	for _, x := range seq {
		s, _ := x.(opensysml.String)
		out = append(out, string(s))
	}
	return out, err
}

// read evaluates the wasb metadata of one element.
func (m *Model) read(ctx context.Context, id string) (Element, error) {
	e := Element{ID: id}
	meta := quote(id) + ".metadata"

	a := "(" + meta + " as WASB::Anchor)"
	anchor, err := m.strs(ctx, id, "("+a+".path, "+a+".kind, "+a+".id)")
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

	hash, err := m.strs(ctx, id, "("+meta+" as WASB::Coverage).lastHash")
	if err != nil {
		return e, err
	}
	for _, h := range hash {
		if e.LastHash == "" {
			e.LastHash = h
		}
	}
	fraction, err := m.eval(ctx, id, "("+meta+" as WASB::Coverage).generatedFraction")
	if err != nil {
		return e, err
	}
	for _, f := range fraction {
		switch f := f.(type) {
		case opensysml.Real:
			e.MinFraction = float64(f)
		case opensysml.Int:
			e.MinFraction = float64(f)
		}
	}
	if e.KnownGaps, err = m.strs(ctx, id, "("+meta+" as WASB::KnownGap).reason"); err != nil {
		return e, err
	}
	for flag, def := range map[*bool]string{&e.Detached: "Detached", &e.UserDeclared: "UserDeclared", &e.AgentSuggested: "AgentSuggested"} {
		seq, err := m.eval(ctx, id, meta+" as WASB::"+def)
		if err != nil {
			return e, err
		}
		*flag = len(seq) > 0
	}

	if e.Anchor != nil {
		e.Attrs = map[string]string{}
		for _, attr := range Kinds[e.Anchor.Kind].Attrs {
			// An element not typed by the kind's definition has no such feature: treat it as unset.
			if seq, err := m.eval(ctx, id, quote(id)+"::"+attr.Name); err == nil && len(seq) == 1 {
				if lit := literal(seq[0]); lit != "" {
					e.Attrs[attr.Name] = lit
				}
			}
		}
	}
	return e, nil
}

func (m *Model) evidence(ctx context.Context, id string) (string, error) {
	seq, err := m.eval(ctx, id, "("+quote(id)+".metadata as WASB::EvidenceClass).evidence")
	if err != nil || len(seq) == 0 {
		return "", err
	}
	lit, _ := seq[0].(opensysml.EnumLiteral)
	_, name, _ := strings.Cut(lit.Name, "::")
	return name, nil
}

// Verify evaluates every satisfy assertion.
func (m *Model) Verify(ctx context.Context) ([]Verdict, error) {
	s, err := m.client.VerifySatisfaction(ctx, m.parsed, "")
	if err != nil {
		return nil, err
	}
	var vs []Verdict
	for _, v := range s.Verdicts {
		vs = append(vs, Verdict{Requirement: v.RequirementID, Assertion: v.Element, Status: v.Status, Condition: v.Condition, Error: v.Error})
	}
	return vs, nil
}

// Evaluate evaluates a SysML expression against the model.
func (m *Model) Evaluate(ctx context.Context, expr string) (opensysml.Value, error) {
	return m.client.Evaluate(ctx, m.parsed, expr)
}

func literal(v opensysml.Value) string {
	switch v := v.(type) {
	case opensysml.String:
		return Literal(string(v))
	case opensysml.Int:
		return Literal(int64(v))
	case opensysml.Bool:
		return Literal(bool(v))
	}
	return ""
}

var ident = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// quote writes a qualified name as an expression, quoting segments that are not identifiers.
func quote(id string) string {
	parts := strings.Split(id, "::")
	for i, p := range parts {
		if !ident.MatchString(p) {
			parts[i] = Name(p)
		}
	}
	return strings.Join(parts, "::")
}
