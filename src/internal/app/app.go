// Package app runs wasb's operations for the CLI and the MCP server.
package app

import (
	"context"
	"slices"
	"strings"

	"github.com/realnedsanders/wearesoback/src/internal/gate"
	"github.com/realnedsanders/wearesoback/src/internal/git"
	"github.com/realnedsanders/wearesoback/src/internal/model"
)

// Gates lists every gate in the order check runs them.
var Gates = []string{"drift", "unmodeled", "requirements", "signature", "coverage"}

// Report is one check run.
type Report struct {
	Pass bool `json:"pass"`
	// Mode is "enforcing", or "warning-only" until the first commit touching .wasb/ is signed.
	Mode        string            `json:"mode"`
	Diagnostics []gate.Diagnostic `json:"diagnostics"`
	Manifest    *Manifest         `json:"manifest"`
}

// Manifest lists what a check examined and what it did not.
type Manifest struct {
	Examined         []string          `json:"examined"`
	NotExamined      []string          `json:"notExamined"`
	Skipped          map[string]string `json:"skipped,omitempty"`
	KnownGaps        []Gap             `json:"knownGaps"`
	AwaitingEvidence []gate.Awaiting   `json:"awaitingEvidence"`
	Files            []FileCoverage    `json:"files"`
	Elements         []ElementCoverage `json:"elements"`
}

// Gap is a KnownGap the model declares.
type Gap struct {
	Element string `json:"element"`
	Reason  string `json:"reason"`
}

// FileCoverage counts a file's targets. Generated is the summed generated
// fraction of its modeled targets over all its targets.
type FileCoverage struct {
	File      string  `json:"file"`
	Targets   int     `json:"targets"`
	Modeled   int     `json:"modeled"`
	Generated float64 `json:"generated"`
}

// ElementCoverage is an anchored element's generated fraction and the minimum it sets.
type ElementCoverage struct {
	Element  string  `json:"element"`
	Fraction float64 `json:"fraction"`
	Minimum  float64 `json:"minimum,omitempty"`
}

// Check runs the named gates over the repository at root.
func Check(ctx context.Context, root string, gates ...string) (*Report, error) {
	files, err := gate.Files(root)
	if err != nil {
		return nil, err
	}
	r := &Report{Mode: "enforcing", Diagnostics: []gate.Diagnostic{}}
	if signed, err := imported(root); err != nil {
		return nil, err
	} else if !signed {
		r.Mode = "warning-only"
	}
	defer func() { r.Pass = len(r.Diagnostics) == 0 || r.Mode == "warning-only" }()

	scan, err := gate.Targets(root, files)
	if err != nil {
		r.Diagnostics = append(r.Diagnostics, gate.Diagnostic{Gate: "scan", Message: err.Error()})
		return r, nil
	}
	m, err := model.Load(ctx, root, modelFiles(files), nil)
	if err != nil {
		r.Diagnostics = append(r.Diagnostics, gate.Diagnostic{Gate: "model", Message: err.Error()})
		r.Manifest = manifest(files, scan, nil, nil)
		return r, nil
	}
	defer m.Close()

	var awaiting []gate.Awaiting
	for _, g := range gates {
		var ds []gate.Diagnostic
		switch g {
		case "drift":
			ds = gate.Drift(m.Elements, scan.Targets)
		case "unmodeled":
			ds = gate.Unmodeled(m.Elements, scan.Targets)
		case "coverage":
			ds = gate.Coverage(m.Elements, scan.Targets)
		case "signature":
			ds = gate.Signature(root, m.Elements)
		case "requirements":
			verdicts, err := m.Verify(ctx)
			if err != nil {
				ds = []gate.Diagnostic{{Gate: "requirements", Message: err.Error()}}
				break
			}
			ds, awaiting = gate.Requirements(m.Requirements, verdicts)
			before := headFailures(ctx, root)
			for i := range ds {
				ds[i].New = !before[ds[i].Element+"\x00"+ds[i].Message]
			}
		}
		r.Diagnostics = append(r.Diagnostics, ds...)
	}
	r.Manifest = manifest(files, scan, m, awaiting)
	return r, nil
}

// Managed reports whether dir is in a git repository where some commit has
// touched .wasb/. Deleting .wasb/ afterwards does not unmanage it.
func Managed(dir string) bool {
	root, err := git.Run(dir, nil, "rev-parse", "--show-toplevel")
	if err != nil {
		return false
	}
	out, err := git.Run(root, nil, "log", "-1", "--format=%H", "--", ".wasb")
	return err == nil && out != ""
}

// imported reports whether the first commit touching .wasb/ carries a
// signature. Until it does the model is not authoritative. Whether the
// signature is trusted is the signature gate's question.
func imported(root string) (bool, error) {
	if _, err := git.Run(root, nil, "rev-parse", "--verify", "-q", "HEAD"); err != nil {
		return false, nil // no commits yet
	}
	out, err := git.Run(root, nil, "log", "--reverse", "--full-history", "--format=%H", "--", ".wasb")
	if err != nil {
		return false, err
	}
	commits := strings.Fields(out)
	if len(commits) == 0 {
		return false, nil
	}
	obj, err := git.Run(root, nil, "cat-file", "commit", commits[0])
	if err != nil {
		return false, err
	}
	headers, _, _ := strings.Cut(obj, "\n\n")
	return strings.Contains(headers, "\ngpgsig"), nil
}

// headFailures are the requirement failures of the last commit's model.
func headFailures(ctx context.Context, root string) map[string]bool {
	out, err := git.Run(root, nil, "ls-tree", "-r", "-z", "--name-only", "HEAD", "--", model.Dir)
	if err != nil {
		return nil
	}
	files := map[string]string{}
	for _, f := range strings.Split(out, "\x00") {
		if strings.HasSuffix(f, ".sysml") {
			if files[f], err = git.Run(root, nil, "show", "HEAD:"+f); err != nil {
				return nil
			}
		}
	}
	m, err := model.Load(ctx, root, nil, files)
	if err != nil {
		return nil
	}
	defer m.Close()
	verdicts, err := m.Verify(ctx)
	if err != nil {
		return nil
	}
	ds, _ := gate.Requirements(m.Requirements, verdicts)
	failed := map[string]bool{}
	for _, d := range ds {
		failed[d.Element+"\x00"+d.Message] = true
	}
	return failed
}

func modelFiles(files []string) []string {
	var out []string
	for _, f := range files {
		if strings.HasPrefix(f, model.Dir+"/") && strings.HasSuffix(f, ".sysml") {
			out = append(out, f)
		}
	}
	return out
}

// manifest builds the coverage manifest; m is nil when there is no model.
func manifest(files []string, scan *gate.Scan, m *model.Model, awaiting []gate.Awaiting) *Manifest {
	mf := &Manifest{Examined: scan.Examined, NotExamined: []string{}, Skipped: scan.Skipped,
		KnownGaps: []Gap{}, AwaitingEvidence: append([]gate.Awaiting{}, awaiting...), Files: []FileCoverage{}, Elements: []ElementCoverage{}}
	for _, f := range files {
		if !strings.HasPrefix(f, ".wasb/") && !slices.Contains(scan.Examined, f) {
			mf.NotExamined = append(mf.NotExamined, f)
		}
	}
	var elems []model.Element
	if m != nil {
		elems = m.Elements
	}
	anchored := map[string]bool{}
	byKey := gate.Index(scan.Targets)
	for _, e := range elems {
		for _, g := range e.KnownGaps {
			mf.KnownGaps = append(mf.KnownGaps, Gap{Element: e.ID, Reason: g})
		}
		if e.Anchor == nil || e.Detached {
			continue
		}
		if t, ok := gate.Find(byKey, e.Anchor); ok {
			anchored[t.Kind+"\x00"+t.Path+"\x00"+t.ID] = true
			mf.Elements = append(mf.Elements, ElementCoverage{Element: e.ID, Fraction: t.Fraction, Minimum: e.MinFraction})
		}
	}
	byFile := map[string]*FileCoverage{}
	for _, t := range scan.Targets {
		fc := byFile[t.File]
		if fc == nil {
			fc = &FileCoverage{File: t.File}
			byFile[t.File] = fc
		}
		fc.Targets++
		if anchored[t.Kind+"\x00"+t.Path+"\x00"+t.ID] {
			fc.Modeled++
			fc.Generated += t.Fraction
		}
	}
	for _, f := range scan.Examined {
		if fc := byFile[f]; fc != nil {
			fc.Generated /= float64(fc.Targets)
			mf.Files = append(mf.Files, *fc)
		}
	}
	return mf
}
