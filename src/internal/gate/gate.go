// Package gate implements wasb's deterministic gates. Each is a pure function
// of the git tree and .wasb/ content.
package gate

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/realnedsanders/wearesoback/src/internal/git"
	"github.com/realnedsanders/wearesoback/src/internal/model"
	"github.com/realnedsanders/wearesoback/src/internal/trust"
)

// Diagnostic is one gate failure.
type Diagnostic struct {
	Gate    string `json:"gate"`
	Element string `json:"element,omitempty"`
	Path    string `json:"path,omitempty"`
	Line    int    `json:"line,omitempty"`
	Message string `json:"message"`
	Fix     string `json:"fix,omitempty"`
	// New marks a requirement failure the last commit did not have.
	New bool `json:"new,omitempty"`
}

func key(kind, path, id string) string { return kind + "\x00" + path + "\x00" + id }

// Index maps targets by anchor key.
func Index(targets []Target) map[string]Target {
	byKey := map[string]Target{}
	for _, t := range targets {
		byKey[key(t.Kind, t.Path, t.ID)] = t
	}
	return byKey
}

// Find returns the target an anchor points at.
func Find(byKey map[string]Target, a *model.Anchor) (Target, bool) {
	t, ok := byKey[key(a.Kind, a.Path, a.ID)]
	return t, ok
}

// Drift fails anchored elements whose target changed or disappeared while the
// element did not, and elements whose attributes disagree with their target.
func Drift(elems []model.Element, targets []Target) []Diagnostic {
	byKey := Index(targets)
	var ds []Diagnostic
	claimed := map[string]string{}
	for _, e := range elems {
		a := e.Anchor
		if a == nil {
			continue
		}
		k := key(a.Kind, a.Path, a.ID)
		t, found := byKey[k]
		d := Diagnostic{Gate: "drift", Element: e.ID, Path: a.Path}
		var differ []string
		for _, attr := range model.Kinds[a.Kind].Attrs {
			if e.Attrs[attr.Name] != t.Attrs[attr.Name] {
				differ = append(differ, fmt.Sprintf("%s is %s, the model says %s", attr.Name, orUnset(t.Attrs[attr.Name]), orUnset(e.Attrs[attr.Name])))
			}
		}
		switch {
		case model.Kinds[a.Kind].Def == "":
			d.Message = fmt.Sprintf("unsupported anchor kind %q", a.Kind)
		case claimed[k] != "":
			d.Message = fmt.Sprintf("%s %s is already anchored by %s", a.Kind, a.ID, claimed[k])
		case e.Detached:
		case !found:
			d.Message = fmt.Sprintf("%s %s no longer exists but the model still claims it", a.Kind, a.ID)
			d.Fix = fmt.Sprintf("restore it, delete %s from the model, or mark it @WASB::Detached", e.ID)
		case t.Hash != e.LastHash && (e.LastHash != "" || !model.Kinds[a.Kind].Complete):
			d.Path, d.Line = t.File, t.Line
			d.Message = fmt.Sprintf("%s %s changed but the model did not", a.Kind, a.ID)
			d.Fix = "replace " + e.ID + " with\n" + t.SysML()
		case len(differ) > 0:
			d.Path, d.Line = t.File, t.Line
			d.Message = fmt.Sprintf("the model disagrees with %s %s: %s", a.Kind, a.ID, strings.Join(differ, "; "))
			d.Fix = "replace " + e.ID + " with\n" + t.SysML()
		}
		claimed[k] = e.ID
		if d.Message != "" {
			ds = append(ds, d)
		}
	}
	return ds
}

func orUnset(lit string) string {
	if lit == "" {
		return "unset"
	}
	return lit
}

// Unmodeled fails targets that no model element anchors.
func Unmodeled(elems []model.Element, targets []Target) []Diagnostic {
	anchored := map[string]bool{}
	for _, e := range elems {
		if a := e.Anchor; a != nil {
			anchored[key(a.Kind, a.Path, a.ID)] = true
		}
	}
	var ds []Diagnostic
	for _, t := range targets {
		if !anchored[key(t.Kind, t.Path, t.ID)] {
			ds = append(ds, Diagnostic{Gate: "unmodeled", Path: t.File, Line: t.Line,
				Message: fmt.Sprintf("%s %s is not modeled", t.Kind, t.ID), Fix: t.SysML()})
		}
	}
	return ds
}

// Coverage fails anchored elements whose target's generated fraction dropped
// below the minimum the element sets in Coverage.generatedFraction.
func Coverage(elems []model.Element, targets []Target) []Diagnostic {
	byKey := Index(targets)
	var ds []Diagnostic
	for _, e := range elems {
		if e.Anchor == nil || e.MinFraction == 0 {
			continue
		}
		if t, ok := Find(byKey, e.Anchor); ok && t.Fraction < e.MinFraction {
			ds = append(ds, Diagnostic{Gate: "coverage", Element: e.ID, Path: t.File, Line: t.Line,
				Message: fmt.Sprintf("generated fraction %.2f is below the %.2f the model requires", t.Fraction, e.MinFraction),
				Fix:     "move hand-written code out of " + t.ID + ", or lower Coverage.generatedFraction with a signed commit"})
		}
	}
	return ds
}

// Awaiting is a requirement the model cannot discharge because its evidence is not structural.
type Awaiting struct {
	Requirement string `json:"requirement"`
	Evidence    string `json:"evidence"`
}

// Requirements fails requirements without an evidence class, structural
// satisfy assertions the model violates or cannot decide, and UserDeclared
// structural requirement usages nothing claims to satisfy. Requirements of
// other evidence classes are returned as awaiting evidence, never discharged.
func Requirements(reqs []model.Requirement, verdicts []model.Verdict) ([]Diagnostic, []Awaiting) {
	var ds []Diagnostic
	var awaiting []Awaiting
	evidence := map[string]string{}
	fail := func(r model.Requirement, msg, fix string) {
		path := ""
		if len(r.Files) > 0 {
			path = r.Files[0]
		}
		ds = append(ds, Diagnostic{Gate: "requirements", Element: r.ID, Path: path, Message: msg, Fix: fix})
	}
	for _, r := range reqs {
		evidence[r.ID] = r.Evidence
		switch {
		case r.Evidence == "":
			fail(r, "requirement has no EvidenceClass", "add @WASB::EvidenceClass { evidence = WASB::EvidenceClassKind::structural; } or another class")
		case r.Evidence != "structural":
			awaiting = append(awaiting, Awaiting{Requirement: r.ID, Evidence: r.Evidence})
		case r.Usage && r.UserDeclared && !r.Claimed:
			fail(r, "nothing claims to satisfy this requirement", "add a satisfy assertion naming it")
		}
	}
	for _, v := range verdicts {
		if evidence[v.Requirement] != "structural" {
			continue
		}
		r := model.Requirement{ID: v.Requirement}
		switch v.Status {
		case "holds":
		case "violated":
			fail(r, fmt.Sprintf("%s does not hold: %s", v.Assertion, v.Condition), "change the model or the code it anchors until it holds")
		default:
			fail(r, fmt.Sprintf("%s cannot be decided: %s", v.Assertion, v.Error), "give the subject the values the requirement reads")
		}
	}
	return ds, awaiting
}

// Signature fails changes to protected content that a trusted key did not sign.
// The trust chain must verify, must extend every committed chain (no
// rollback), and its version 1 must be signed by whoever signed the first
// commit touching .wasb/, so a key set started by anyone else is rejected.
func Signature(root string, elems []model.Element) []Diagnostic {
	var ds []Diagnostic
	fail := func(path, msg, fix string) {
		ds = append(ds, Diagnostic{Gate: "signature", Path: path, Message: msg, Fix: fix})
	}

	for _, e := range elems {
		if e.AgentSuggested {
			ds = append(ds, Diagnostic{Gate: "signature", Element: e.ID, Path: strings.Join(e.Files, ","),
				Message: "AgentSuggested content is in the model", Fix: "accept it (remove the mark, signed commit) or move it back to a proposal"})
		}
		for _, f := range e.Files {
			if e.UserDeclared && !strings.HasPrefix(f, model.UserDir+"/") {
				ds = append(ds, Diagnostic{Gate: "signature", Element: e.ID, Path: f,
					Message: "UserDeclared content outside " + model.UserDir + " is not protected", Fix: "move it under " + model.UserDir})
			}
		}
	}

	if dirty, err := git.Run(root, nil, "status", "--porcelain", "--", model.UserDir); err != nil {
		fail(model.UserDir, err.Error(), "")
	} else if dirty != "" {
		fail(model.UserDir, "uncommitted changes to protected content", "commit them with a trusted signing key")
	}

	chain, err := trust.Load(filepath.Join(root, trust.File))
	if err != nil {
		fail(trust.File, err.Error(), "")
		return ds
	}
	st, err := chain.Verify()
	if err != nil {
		fail(trust.File, err.Error(), "run wasb trust sign with a key the previous version trusts")
		return ds
	}
	if len(st.Keys) == 0 {
		fail(trust.File, "no trusted keys", "run wasb trust add, then wasb trust sign")
		return ds
	}

	history, err := git.Run(root, nil, "log", "--full-history", "--format=%H", "--", trust.File)
	if err != nil {
		fail(trust.File, err.Error(), "")
	}
	for _, h := range strings.Fields(history) {
		b, err := git.Run(root, nil, "show", h+":"+trust.File)
		if err != nil {
			continue // h deleted the file
		}
		if old, err := trust.Parse([]byte(b)); err != nil || !chain.Extends(old) {
			fail(trust.File, fmt.Sprintf("the current chain drops or rewrites versions committed in %.12s", h),
				"restore them; changes append new versions")
		}
	}

	genesis, err := trust.NewVerifier(st.Genesis)
	if err != nil {
		fail(trust.File, err.Error(), "")
		return ds
	}
	defer genesis.Close()
	current, err := trust.NewVerifier(st.Keys)
	if err != nil {
		fail(trust.File, err.Error(), "")
		return ds
	}
	defer current.Close()
	log := func(v *trust.Verifier, args ...string) ([][]string, error) {
		out, err := git.Run(root, v.Env, append(append(v.Args, "log", "--full-history", "--format=%H%x1f%G?%x1f%GF%x1f%GP%x1f%s"), args...)...)
		var rows [][]string
		for _, l := range strings.Split(out, "\n") {
			if l != "" {
				rows = append(rows, strings.Split(l, "\x1f"))
			}
		}
		return rows, err
	}

	first, err := log(genesis, "--reverse", "--", ".wasb")
	switch {
	case err != nil:
		fail(".wasb", err.Error(), "")
	case len(first) == 0:
		fail(".wasb", "the model has no commit, so it is not authoritative", "commit .wasb/ with your signing key")
	default:
		signer := first[0][3] // GPG primary key
		if signer == "" {
			signer = first[0][2] // SSH key
		}
		if first[0][1] != "G" || signer != st.Root {
			fail(".wasb", fmt.Sprintf("import commit %.12s is not signed by %s, the key that signed trust version 1", first[0][0], st.Root),
				"sign the import commit and trust version 1 with the same key")
		}
	}

	commits, err := log(current, "--", model.UserDir)
	if err != nil {
		fail(model.UserDir, err.Error(), "")
	}
	for _, c := range commits {
		if c[1] != "G" {
			fail(model.UserDir, fmt.Sprintf("commit %.12s %q changes protected content without a trusted signature", c[0], c[4]),
				"re-sign the commit with a key the trust chain trusts")
		}
	}
	return ds
}
