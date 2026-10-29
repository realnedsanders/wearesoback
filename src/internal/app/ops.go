package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"go/parser"
	"go/token"
	"io/fs"
	"maps"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/realnedsanders/wearesoback/src/internal/gate"
	"github.com/realnedsanders/wearesoback/src/internal/model"
	"github.com/realnedsanders/wearesoback/src/internal/trust"
)

const (
	importFile   = model.Dir + "/generated/import.sysml"
	userStarter  = model.UserDir + "/requirements.sysml"
	importReport = ".wasb/coverage/import.json"
	proposalDir  = ".wasb/proposals"
	stubFile     = "wasb_generated.go"
)

// ImportResult is what import wrote and found.
type ImportResult struct {
	Written  []string       `json:"written"`
	Targets  map[string]int `json:"targets"` // by kind
	Manifest *Manifest      `json:"manifest"`
}

// Import proposes a model of every target under .wasb/model/generated and
// writes the coverage report. The model is not authoritative until the
// commit adding it is signed.
func Import(ctx context.Context, root string, force bool) (*ImportResult, error) {
	files, err := gate.Files(root)
	if err != nil {
		return nil, err
	}
	if len(modelFiles(files)) > 0 && !force {
		return nil, errors.New("a model already exists; pass --force to rewrite " + importFile)
	}
	scan, err := gate.Targets(root, files)
	if err != nil {
		return nil, err
	}
	res := &ImportResult{Targets: map[string]int{}}
	var b strings.Builder
	b.WriteString("// Proposed by wasb import from the repository as it was.\npackage Generated {\n")
	for _, t := range scan.Targets {
		res.Targets[t.Kind]++
		b.WriteString("\n" + indent(t.SysML()))
	}
	b.WriteString("}\n")
	write := func(p, content string) error {
		res.Written = append(res.Written, p)
		return writeFile(filepath.Join(root, p), content)
	}
	if err := write(importFile, b.String()); err != nil {
		return nil, err
	}
	if _, err := os.Stat(filepath.Join(root, userStarter)); errors.Is(err, fs.ErrNotExist) {
		starter := "package UserRequirements {\n    private import WASB::*;\n\n    // Requirements here change only through a signed commit.\n}\n"
		if err := write(userStarter, starter); err != nil {
			return nil, err
		}
	}

	// The import must load, or every later check fails on it.
	m, err := model.Load(ctx, root, modelFiles(append(files, res.Written...)), nil)
	if err != nil {
		return nil, fmt.Errorf("the imported model does not load: %w", err)
	}
	defer m.Close()
	res.Manifest = manifest(files, scan, m, nil)
	report, err := json.MarshalIndent(res, "", "  ")
	if err != nil {
		return nil, err
	}
	if err := write(importReport, string(report)+"\n"); err != nil {
		return nil, err
	}
	return res, nil
}

// Generate writes Go stubs for go.func elements whose function does not
// exist yet, or only returns their diff when write is false.
func Generate(ctx context.Context, root string, write bool) (string, error) {
	stubs, err := loadAndStub(ctx, root, nil)
	if err != nil {
		return "", err
	}
	before := map[string]string{}
	for p := range stubs {
		b, err := os.ReadFile(filepath.Join(root, p))
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			return "", err
		}
		before[p] = string(b)
	}
	d, err := diff(before, stubs)
	if err != nil || !write {
		return d, err
	}
	for p, content := range stubs {
		if err := writeFile(filepath.Join(root, p), content); err != nil {
			return "", err
		}
	}
	return d, nil
}

// LoadModel loads the repository's model; overrides replace or add model files by path.
func LoadModel(ctx context.Context, root string, overrides map[string]string) (*model.Model, error) {
	files, err := gate.Files(root)
	if err != nil {
		return nil, err
	}
	return model.Load(ctx, root, modelFiles(files), overrides)
}

func loadAndStub(ctx context.Context, root string, overrides map[string]string) (map[string]string, error) {
	files, err := gate.Files(root)
	if err != nil {
		return nil, err
	}
	scan, err := gate.Targets(root, files)
	if err != nil {
		return nil, err
	}
	m, err := model.Load(ctx, root, modelFiles(files), overrides)
	if err != nil {
		return nil, err
	}
	defer m.Close()
	return stubs(root, m.Elements, scan.Targets)
}

// stubs returns, per package directory, the stub file with a stub appended
// for every modeled go.func that has a signature but no function.
func stubs(root string, elems []model.Element, targets []gate.Target) (map[string]string, error) {
	byKey := gate.Index(targets)
	missing := map[string][]string{} // dir → signatures
	for _, e := range elems {
		a := e.Anchor
		if a == nil || a.Kind != "go.func" || e.Detached || e.Attrs["signature"] == "" {
			continue
		}
		if _, ok := gate.Find(byKey, a); ok {
			continue
		}
		sig, err := strconv.Unquote(e.Attrs["signature"])
		if err != nil {
			return nil, fmt.Errorf("%s: signature: %w", e.ID, err)
		}
		missing[a.Path] = append(missing[a.Path], sig)
	}
	out := map[string]string{}
	for dir, sigs := range missing {
		p := path.Join(dir, stubFile)
		content, err := os.ReadFile(filepath.Join(root, p))
		if errors.Is(err, fs.ErrNotExist) {
			content = []byte(fmt.Sprintf("// Stubs generated by wasb generate from the model. Fill in the bodies.\n\npackage %s\n", pkgName(root, dir)))
		} else if err != nil {
			return nil, err
		}
		s := string(content)
		slices.Sort(sigs)
		for _, sig := range sigs {
			s += "\n" + sig + " {\n\tpanic(\"wasb: not implemented\")\n}\n"
		}
		out[p] = s
	}
	return out, nil
}

// pkgName is the package of dir's Go files, else the directory's name.
func pkgName(root, dir string) string {
	matches, _ := filepath.Glob(filepath.Join(root, dir, "*.go"))
	for _, f := range matches {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		if file, err := parser.ParseFile(token.NewFileSet(), f, nil, parser.PackageClauseOnly); err == nil {
			return file.Name.Name
		}
	}
	return path.Base(dir)
}

// Proposal is a suggested model change, recorded in .wasb/proposals until a
// signed commit accepts it or it is rejected.
type Proposal struct {
	Name   string `json:"name"`
	Status string `json:"status"` // pending or rejected
	Reason string `json:"reason,omitempty"`
	// Files are the proposed contents of model files, by repo-relative path.
	Files        map[string]string `json:"files"`
	Delta        string            `json:"delta"`
	Constraints  []Change          `json:"constraints"`
	Regeneration string            `json:"regeneration"`
	Impact       Impact            `json:"impact"`
}

// Change is a satisfy assertion whose status the proposal changes; an empty status means absent.
type Change struct {
	Requirement string `json:"requirement"`
	Assertion   string `json:"assertion"`
	Before      string `json:"before"`
	After       string `json:"after"`
}

// Impact is what the proposal breaks and fixes.
type Impact struct {
	NewlyFailing    []string `json:"newlyFailing"`
	NewlyPassing    []string `json:"newlyPassing"`
	ElementsAdded   []string `json:"elementsAdded"`
	ElementsRemoved []string `json:"elementsRemoved"`
}

var proposalName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)

// Propose records a proposal to change the given model files.
func Propose(ctx context.Context, root, name string, files map[string]string) (*Proposal, error) {
	if !proposalName.MatchString(name) {
		return nil, fmt.Errorf("proposal name %q: use letters, digits, '.', '_' and '-'", name)
	}
	for p := range files {
		if !strings.HasPrefix(p, model.Dir+"/") || !strings.HasSuffix(p, ".sysml") || strings.Contains(p, "..") {
			return nil, fmt.Errorf("%s is not a model file under %s", p, model.Dir)
		}
	}
	out := filepath.Join(root, proposalDir, name+".json")
	if _, err := os.Stat(out); err == nil {
		return nil, fmt.Errorf("proposal %s already exists", name)
	}

	before, err := evaluate(ctx, root, nil)
	if err != nil {
		return nil, err
	}
	after, err := evaluate(ctx, root, files)
	if err != nil {
		return nil, fmt.Errorf("the proposed model: %w", err)
	}
	current := map[string]string{}
	for p := range files {
		b, err := os.ReadFile(filepath.Join(root, p))
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			return nil, err
		}
		current[p] = string(b)
	}
	p := &Proposal{Name: name, Status: "pending", Files: files, Constraints: []Change{}}
	if p.Delta, err = diff(current, files); err != nil {
		return nil, err
	}
	beforeStubs := map[string]string{}
	for f := range after.stubs {
		beforeStubs[f] = before.stubs[f]
		if beforeStubs[f] == "" {
			b, _ := os.ReadFile(filepath.Join(root, f))
			beforeStubs[f] = string(b)
		}
	}
	if p.Regeneration, err = diff(beforeStubs, after.stubs); err != nil {
		return nil, err
	}
	for _, k := range slices.Sorted(maps.Keys(union(before.verdicts, after.verdicts))) {
		if b, a := before.verdicts[k], after.verdicts[k]; b.Status != a.Status {
			v := a
			if v.Assertion == "" {
				v = b
			}
			p.Constraints = append(p.Constraints, Change{Requirement: v.Requirement, Assertion: v.Assertion, Before: b.Status, After: a.Status})
		}
	}
	p.Impact = Impact{NewlyFailing: minus(after.failures, before.failures), NewlyPassing: minus(before.failures, after.failures),
		ElementsAdded: minus(after.elements, before.elements), ElementsRemoved: minus(before.elements, after.elements)}
	return p, writeJSON(out, p)
}

type evaluation struct {
	verdicts map[string]model.Verdict // by assertion
	failures map[string]bool          // requirement gate messages
	elements map[string]bool
	stubs    map[string]string
}

func evaluate(ctx context.Context, root string, overrides map[string]string) (*evaluation, error) {
	files, err := gate.Files(root)
	if err != nil {
		return nil, err
	}
	scan, err := gate.Targets(root, files)
	if err != nil {
		return nil, err
	}
	m, err := model.Load(ctx, root, modelFiles(files), overrides)
	if err != nil {
		return nil, err
	}
	defer m.Close()
	vs, err := m.Verify(ctx)
	if err != nil {
		return nil, err
	}
	ev := &evaluation{verdicts: map[string]model.Verdict{}, failures: map[string]bool{}, elements: map[string]bool{}}
	for _, v := range vs {
		ev.verdicts[v.Assertion] = v
	}
	ds, _ := gate.Requirements(m.Requirements, vs)
	for _, d := range ds {
		ev.failures[d.Element+": "+d.Message] = true
	}
	for _, e := range m.Elements {
		if e.Anchor != nil {
			ev.elements[e.ID] = true
		}
	}
	ev.stubs, err = stubs(root, m.Elements, scan.Targets)
	return ev, err
}

// ListProposals returns every recorded proposal.
func ListProposals(root string) ([]Proposal, error) {
	matches, err := filepath.Glob(filepath.Join(root, proposalDir, "*.json"))
	if err != nil {
		return nil, err
	}
	ps := []Proposal{}
	for _, f := range matches {
		var p Proposal
		b, err := os.ReadFile(f)
		if err != nil {
			return nil, err
		}
		if err := json.Unmarshal(b, &p); err != nil {
			return nil, fmt.Errorf("%s: %w", f, err)
		}
		ps = append(ps, p)
	}
	return ps, nil
}

// Reject records that a proposal was rejected and why.
func Reject(root, name, reason string) error {
	if !proposalName.MatchString(name) {
		return fmt.Errorf("no proposal %q", name)
	}
	f := filepath.Join(root, proposalDir, name+".json")
	b, err := os.ReadFile(f)
	if err != nil {
		return err
	}
	var p Proposal
	if err := json.Unmarshal(b, &p); err != nil {
		return err
	}
	p.Status, p.Reason = "rejected", reason
	return writeJSON(f, p)
}

// Status summarizes the repository's standing.
type Status struct {
	Mode         string         `json:"mode"`
	Pass         bool           `json:"pass"`
	Diagnostics  map[string]int `json:"diagnostics"` // by gate
	TrustKeys    int            `json:"trustKeys"`
	TrustPending bool           `json:"trustPending"`
	Targets      int            `json:"targets"`
	Elements     int            `json:"elements"`
	Proposals    map[string]int `json:"proposals"` // by status
}

// GetStatus runs every gate and summarizes.
func GetStatus(ctx context.Context, root string) (*Status, error) {
	r, err := Check(ctx, root, Gates...)
	if err != nil {
		return nil, err
	}
	s := &Status{Mode: r.Mode, Pass: r.Pass, Diagnostics: map[string]int{}, Proposals: map[string]int{}}
	for _, d := range r.Diagnostics {
		s.Diagnostics[d.Gate]++
	}
	if r.Manifest != nil {
		for _, f := range r.Manifest.Files {
			s.Targets += f.Targets
		}
		s.Elements = len(r.Manifest.Elements)
	}
	chain, err := trust.Load(filepath.Join(root, trust.File))
	if err != nil {
		return nil, err
	}
	keys, pending, err := chain.Keys()
	if err != nil {
		return nil, err
	}
	s.TrustKeys, s.TrustPending = len(keys), pending
	ps, err := ListProposals(root)
	if err != nil {
		return nil, err
	}
	for _, p := range ps {
		s.Proposals[p.Status]++
	}
	return s, nil
}

// diff is a unified diff from before to after, by path; an empty side is an absent file.
func diff(before, after map[string]string) (string, error) {
	dir, err := os.MkdirTemp("", "wasb-diff-")
	if err != nil {
		return "", err
	}
	defer func() { _ = os.RemoveAll(dir) }()
	var out strings.Builder
	for _, p := range slices.Sorted(maps.Keys(union(before, after))) {
		a, b := filepath.Join(dir, "a", p), filepath.Join(dir, "b", p)
		if err := writeFile(a, before[p]); err != nil {
			return "", err
		}
		if err := writeFile(b, after[p]); err != nil {
			return "", err
		}
		cmd := exec.Command("git", "diff", "--no-index", "--no-color", "--", filepath.Join("a", p), filepath.Join("b", p))
		cmd.Dir = dir
		d, err := cmd.Output()
		var exit *exec.ExitError
		if err != nil && (!errors.As(err, &exit) || exit.ExitCode() != 1) {
			return "", fmt.Errorf("git diff: %w", err)
		}
		out.Write(d)
	}
	return out.String(), nil
}

func union[V any](a, b map[string]V) map[string]V {
	u := maps.Clone(a)
	if u == nil {
		u = map[string]V{}
	}
	maps.Copy(u, b)
	return u
}

func minus(a, b map[string]bool) []string {
	out := []string{}
	for _, k := range slices.Sorted(maps.Keys(a)) {
		if !b[k] {
			out = append(out, k)
		}
	}
	return out
}

func indent(s string) string {
	lines := strings.SplitAfter(s, "\n")
	for i, l := range lines {
		if l != "" && l != "\n" {
			lines[i] = "    " + l
		}
	}
	return strings.Join(lines, "")
}

func writeFile(p, content string) error {
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return err
	}
	return os.WriteFile(p, []byte(content), 0o644)
}

func writeJSON(p string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return writeFile(p, string(b)+"\n")
}
