// Package e2e drives the built wasb binary against scratch git repositories.
package e2e

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"go.yaml.in/yaml/v3"
)

var bin string

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "wasb-e2e-")
	if err != nil {
		panic(err)
	}
	bin = filepath.Join(dir, "wasb")
	gnupg := filepath.Join(dir, "gnupg")
	// Keep the developer's git config (signing defaults, hooks) and keyring out of the tests.
	for k, v := range map[string]string{"GIT_CONFIG_GLOBAL": os.DevNull, "GIT_CONFIG_NOSYSTEM": "1", "GNUPGHOME": gnupg} {
		_ = os.Setenv(k, v)
	}
	if err := os.Mkdir(gnupg, 0o700); err != nil {
		panic(err)
	}
	if out, err := exec.Command("go", "build", "-o", bin, "../cmd/wasb").CombinedOutput(); err != nil {
		fmt.Fprintln(os.Stderr, string(out))
		os.Exit(1)
	}
	code := m.Run()
	_ = exec.Command("gpgconf", "--kill", "all").Run()
	_ = os.RemoveAll(dir)
	os.Exit(code)
}

const (
	appGo = `package app

type Server struct{}

func New() *Server { return &Server{} }

func (s *Server) Run(addr string) error { return nil }

func helper() {}

type inner struct{}

func (inner) Do() {}
`
	appTestGo = `package app

import "testing"

func TestNew(t *testing.T) {}
`
	zarfYAML = `kind: ZarfPackageConfig
metadata:
  name: demo
components:
  - name: demo
    required: true
    only:
      flavor: upstream
    images:
      - ghcr.io/example/demo:v1
  - name: demo
    required: true
    only:
      flavor: unicorn
    images:
      - ghcr.io/example/demo:v1
`
	userReqs = `package UserRequirements {
    private import WASB::*;
    requirement def KeepServer {
        @UserDeclared;
        @EvidenceClass { evidence = EvidenceClassKind::structural; }
    }
}
`
	chartYAML  = "apiVersion: v2\nname: demo\nversion: 0.1.0\n"
	udsPackage = `apiVersion: uds.dev/v1alpha1
kind: Package
metadata:
  name: demo
  namespace: {{ .Release.Namespace }}
spec:
  network:
    expose:
      - service: demo
        host: demo
        gateway: tenant
        port: 8080
    allow:
      - direction: Egress
        remoteNamespace: keycloak
        port: 8080
        description: "Keycloak egress"
      {{- if .Values.debug }}
      - direction: Egress
        remoteGenerated: Anywhere
        description: "Debug egress"
      {{- end }}
`
	tasksYAML = "tasks:\n  - name: build\n    description: Build it\n    actions:\n      - cmd: echo build\n"
	workflow  = "on: push\njobs:\n  test:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n"
	// storyReqs is the user's: the Keycloak egress rule must stay pointed at keycloak.
	storyReqs = `package UserRequirements {
    private import WASB::*;
    requirement def KeepServer {
        @UserDeclared;
        @EvidenceClass { evidence = EvidenceClassKind::structural; }
    }
    requirement def KeycloakEgress {
        @UserDeclared;
        @EvidenceClass { evidence = EvidenceClassKind::structural; }
        subject rule : UDSAllow;
        require constraint { rule.remoteNamespace == "keycloak" }
    }
    requirement keycloakEgress : KeycloakEgress { @UserDeclared; }
    satisfy keycloakEgress by Generated::'chart/templates/uds-package.yaml#Keycloak egress';
}
`
	missingFunc = `    action 'app#Missing' : WASB::GoFunc {
        @WASB::Anchor { path = "app"; kind = "go.func"; id = "Missing"; }
        :>> signature = "func Missing() error";
    }
`
	generated = ".wasb/model/generated/import.sysml"
	user      = ".wasb/model/user/requirements.sysml"
)

type result struct {
	Pass        bool   `json:"pass"`
	Mode        string `json:"mode"`
	Diagnostics []struct {
		Gate, Element, Path, Message, Fix string
		Line                              int
		New                               bool
	} `json:"diagnostics"`
	Manifest struct {
		KnownGaps        []struct{ Element, Reason string }       `json:"knownGaps"`
		AwaitingEvidence []struct{ Requirement, Evidence string } `json:"awaitingEvidence"`
		Files            []struct {
			File             string
			Targets, Modeled int
		} `json:"files"`
	} `json:"manifest"`
}

type env struct {
	t              *testing.T
	dir, repo, cfg string
}

func newEnv(t *testing.T) *env {
	d := t.TempDir()
	e := &env{t: t, dir: d, repo: filepath.Join(d, "repo"), cfg: filepath.Join(d, "cfg")}
	e.run("git", "init", "-q", "-b", "main", e.repo)
	e.git("config", "user.email", "dev@example.com")
	e.git("config", "user.name", "dev")
	return e
}

func (e *env) run(name string, args ...string) string {
	e.t.Helper()
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		e.t.Fatalf("%s %s: %v\n%s", name, strings.Join(args, " "), err, out)
	}
	return strings.TrimSpace(string(out))
}

func (e *env) git(args ...string) string {
	e.t.Helper()
	return e.run("git", append([]string{"-C", e.repo}, args...)...)
}

func (e *env) write(path, content string) {
	e.t.Helper()
	p := filepath.Join(e.repo, path)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		e.t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		e.t.Fatal(err)
	}
}

func (e *env) read(path string) string {
	e.t.Helper()
	b, err := os.ReadFile(filepath.Join(e.repo, path))
	if err != nil {
		e.t.Fatal(err)
	}
	return string(b)
}

// replace edits a file and fails when old is absent, so a stale fixture cannot pass silently.
func (e *env) replace(path, old, repl string) {
	e.t.Helper()
	s := e.read(path)
	if !strings.Contains(s, old) {
		e.t.Fatalf("%s does not contain %q", path, old)
	}
	e.write(path, strings.Replace(s, old, repl, 1))
}

// wasb runs a command with --json and checks the exit code agrees with the verdict.
func (e *env) wasb(args ...string) result {
	e.t.Helper()
	cmd := exec.Command(bin, append([]string{"--json", "--repo", e.repo, "--config-dir", e.cfg}, args...)...)
	out, err := cmd.Output()
	var r result
	if jerr := json.Unmarshal(out, &r); jerr != nil {
		e.t.Fatalf("wasb %v: %v: %s", args, jerr, out)
	}
	if r.Pass != (err == nil) {
		e.t.Fatalf("wasb %v: pass=%t but exit err=%v", args, r.Pass, err)
	}
	return r
}

// cli runs a non-check command and fails on error.
func (e *env) cli(args ...string) {
	e.t.Helper()
	e.run(bin, append([]string{"--repo", e.repo, "--config-dir", e.cfg}, args...)...)
}

// cliFails runs a non-check command and fails unless it errors with msg.
func (e *env) cliFails(msg string, args ...string) {
	e.t.Helper()
	out, err := exec.Command(bin, append([]string{"--repo", e.repo, "--config-dir", e.cfg}, args...)...).CombinedOutput()
	if err == nil || !strings.Contains(string(out), msg) {
		e.t.Fatalf("wasb %v: want error containing %q, got %v: %s", args, msg, err, out)
	}
}

func (e *env) sshKey(name string) string {
	e.t.Helper()
	p := filepath.Join(e.dir, name)
	e.run("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", name, "-f", p)
	return p
}

// commit commits everything, SSH-signed by key or unsigned when key is empty.
func (e *env) commit(key, msg string) {
	e.t.Helper()
	e.git("add", "-A")
	if key == "" {
		e.git("commit", "-q", "--no-gpg-sign", "-m", msg)
		return
	}
	e.git("-c", "gpg.format=ssh", "-c", "user.signingkey="+key+".pub", "commit", "-q", "-S", "-m", msg)
}

// chainDoc is .wasb/trust.yaml as an attacker editing it by hand sees it.
type chainDoc struct {
	Versions []map[string]any `yaml:"versions"`
}

func (e *env) chain() chainDoc {
	e.t.Helper()
	var c chainDoc
	if err := yaml.Unmarshal([]byte(e.read(".wasb/trust.yaml")), &c); err != nil {
		e.t.Fatal(err)
	}
	return c
}

func (e *env) setChain(c chainDoc) {
	e.t.Helper()
	b, err := yaml.Marshal(c)
	if err != nil {
		e.t.Fatal(err)
	}
	e.write(".wasb/trust.yaml", string(b))
}

func pass(t *testing.T, r result) {
	t.Helper()
	if !r.Pass {
		t.Fatalf("want pass, got %+v", r.Diagnostics)
	}
}

// fails finds a diagnostic and, when the model is authoritative, checks that it blocks.
func fails(t *testing.T, r result, gate, msg string) {
	t.Helper()
	if r.Mode == "enforcing" && r.Pass {
		t.Fatalf("want %s to block, got pass", gate)
	}
	for _, d := range r.Diagnostics {
		if d.Gate == gate && strings.Contains(d.Message, msg) {
			return
		}
	}
	t.Fatalf("want %s diagnostic containing %q, got %+v", gate, msg, r.Diagnostics)
}

// fixture writes the Go and zarf fixture and, with chart, a Helm chart with a
// UDS Package CR, a tasks file and a workflow.
func (e *env) fixture(chart bool) {
	e.write("app/app.go", appGo)
	e.write("app/app_test.go", appTestGo)
	e.write("zarf.yaml", zarfYAML)
	if chart {
		e.write("chart/Chart.yaml", chartYAML)
		e.write("chart/templates/uds-package.yaml", udsPackage)
		e.write("chart/templates/_helpers.tpl", "{{- define \"demo.name\" -}}demo{{- end }}\n")
		e.write("tasks.yaml", tasksYAML)
		e.write(".github/workflows/ci.yaml", workflow)
	}
}

// repo writes the fixture, imports it and writes the user's requirements.
func repo(t *testing.T, chart bool, reqs string) *env {
	e := newEnv(t)
	e.fixture(chart)
	e.cli("import")
	e.write(user, reqs)
	return e
}

func modeled(t *testing.T) *env { return repo(t, false, userReqs) }

// sign trusts a new root key, signs the chain with it and commits everything signed.
func sign(t *testing.T, e *env) string {
	root := e.sshKey("root")
	e.cli("trust", "add", root+".pub")
	e.cli("trust", "sign", "--format", "ssh", "--key", root)
	e.commit(root, "import")
	r := e.wasb("check")
	pass(t, r)
	if r.Mode != "enforcing" {
		t.Fatalf("want enforcing after a signed import, got %s", r.Mode)
	}
	return root
}

// fixDrift applies every drift fix the way an agent would: replace the named element.
func (e *env) fixDrift() {
	e.t.Helper()
	for _, d := range e.wasb("check", "drift").Diagnostics {
		_, element, ok := strings.Cut(d.Fix, "\n")
		if !ok {
			e.t.Fatalf("no element in fix %q", d.Fix)
		}
		s := e.read(generated)
		head := "    " + element[:strings.Index(element, " : ")] + " : "
		start := strings.Index(s, head)
		end := start + strings.Index(s[start:], "\n    }\n") + len("\n    }\n")
		e.write(generated, s[:start]+indent(element)+s[end:])
	}
}

func indent(s string) string {
	return "    " + strings.TrimSuffix(strings.ReplaceAll(s, "\n", "\n    "), "    ")
}

func TestUnmodeled(t *testing.T) {
	e := newEnv(t)
	e.write("app/app.go", appGo)
	e.write("app/app_test.go", appTestGo)
	e.write("zarf.yaml", zarfYAML)
	r := e.wasb("check", "unmodeled")
	var got []string
	for _, d := range r.Diagnostics {
		got = append(got, d.Message)
	}
	want := []string{
		"go.func New is not modeled",
		"go.func Server.Run is not modeled",
		"zarf.component demo[upstream] is not modeled",
		"zarf.component demo[unicorn] is not modeled",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("got\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}

	e = modeled(t)
	pass(t, e.wasb("check", "unmodeled"))
	pass(t, e.wasb("check", "drift"))
}

func TestDrift(t *testing.T) {
	t.Run("body change is free", func(t *testing.T) {
		e := modeled(t)
		e.replace("app/app.go", "error { return nil }", "error { _ = addr; return nil }")
		pass(t, e.wasb("check", "drift"))
	})

	t.Run("signature change needs the model", func(t *testing.T) {
		e := modeled(t)
		e.replace("app/app.go", "Run(addr string)", "Run(addr string, port int)")
		fails(t, e.wasb("check", "drift"), "drift", "go.func Server.Run changed but the model did not")
		e.fixDrift()
		pass(t, e.wasb("check", "drift"))
		if !strings.Contains(e.read(generated), `signature = "func (s *Server) Run(addr string, port int) error"`) {
			t.Fatal("the fix did not record the new signature")
		}
	})

	t.Run("zarf component change needs the model", func(t *testing.T) {
		e := modeled(t)
		e.replace("zarf.yaml", "demo:v1", "demo:v2")
		fails(t, e.wasb("check", "drift"), "drift", "zarf.component demo[upstream] changed")
	})

	t.Run("removal needs Detached", func(t *testing.T) {
		e := modeled(t)
		e.replace("app/app.go", "func New() *Server { return &Server{} }", "")
		fails(t, e.wasb("check", "drift"), "drift", "go.func New no longer exists")
		e.replace(generated, `@WASB::Anchor { path = "app"; kind = "go.func"; id = "New"; }`,
			`@WASB::Detached; @WASB::Anchor { path = "app"; kind = "go.func"; id = "New"; }`)
		pass(t, e.wasb("check", "drift"))
	})

	t.Run("broken model fails", func(t *testing.T) {
		e := modeled(t)
		e.write(".wasb/model/generated/broken.sysml", "package Broken {")
		fails(t, e.wasb("check", "drift"), "model", "does not parse")
	})
}

// signed returns a modeled repo whose import commit and trust file are signed by root.
func signed(t *testing.T) (e *env, root string) {
	e = modeled(t)
	return e, sign(t, e)
}

func TestSignature(t *testing.T) {
	t.Run("no trust file", func(t *testing.T) {
		e := modeled(t)
		e.commit("", "import")
		fails(t, e.wasb("check", "signature"), "signature", "no trusted keys")
	})

	t.Run("unsigned import", func(t *testing.T) {
		e := modeled(t)
		root := e.sshKey("root")
		e.cli("trust", "add", root+".pub")
		e.cli("trust", "sign", "--format", "ssh", "--key", root)
		e.commit("", "import")
		fails(t, e.wasb("check", "signature"), "signature", "import commit")
	})

	t.Run("unsigned change to user", func(t *testing.T) {
		e, _ := signed(t)
		e.replace(user, "KeepServer", "KeepServerMaybe")
		e.commit("", "relax")
		fails(t, e.wasb("check", "signature"), "signature", "without a trusted signature")
	})

	t.Run("untrusted key signs user change", func(t *testing.T) {
		e, _ := signed(t)
		evil := e.sshKey("evil")
		e.replace(user, "KeepServer", "KeepServerMaybe")
		e.commit(evil, "relax")
		fails(t, e.wasb("check", "signature"), "signature", "without a trusted signature")
	})

	t.Run("trusted key signs user change", func(t *testing.T) {
		e, root := signed(t)
		e.replace(user, "KeepServer", "KeepServerAlways")
		e.commit(root, "tighten")
		pass(t, e.wasb("check", "signature"))
	})

	t.Run("uncommitted user change", func(t *testing.T) {
		e, _ := signed(t)
		e.replace(user, "KeepServer", "KeepServerMaybe")
		fails(t, e.wasb("check", "signature"), "signature", "uncommitted")
	})

	t.Run("agent adds its own key to the trust chain", func(t *testing.T) {
		e, _ := signed(t)
		evil := e.sshKey("evil")
		e.cli("trust", "add", evil+".pub")
		e.cliFails("not trusted by version 1", "trust", "sign", "--format", "ssh", "--key", evil)
		e.replace(user, "KeepServer", "KeepServerMaybe")
		e.commit(evil, "relax")
		fails(t, e.wasb("check", "signature"), "signature", "version 2 is not signed")

		// Bypass the CLI: sign the pending version's payload with evil directly.
		chain := e.chain()
		v := chain.Versions[1]
		payload, _ := json.Marshal(map[string]any{"nonce": "", "previous": v["previous"], "keys": v["keys"]})
		e.write("payload", string(payload))
		e.run("ssh-keygen", "-Y", "sign", "-n", "wasb-trust", "-f", evil, filepath.Join(e.repo, "payload"))
		v["signer"] = strings.Fields(e.run("ssh-keygen", "-lf", evil+".pub"))[1]
		v["signature"] = e.read("payload.sig")
		e.setChain(chain)
		fails(t, e.wasb("check", "signature"), "signature", "which version 1 does not trust")
	})

	t.Run("agent starts a new trust chain", func(t *testing.T) {
		e, root := signed(t)
		evil := e.sshKey("evil")
		if err := os.Remove(filepath.Join(e.repo, ".wasb/trust.yaml")); err != nil {
			t.Fatal(err)
		}
		e.cli("trust", "add", evil+".pub")
		e.cli("trust", "add", root+".pub")
		e.cli("trust", "sign", "--format", "ssh", "--key", evil)
		fails(t, e.wasb("check", "signature"), "signature", "import commit")
	})

	t.Run("agent splices in a version from another repo", func(t *testing.T) {
		e, root := signed(t)
		other := modeled(t)
		evil := other.sshKey("evil")
		other.cli("trust", "add", root+".pub")
		other.cli("trust", "sign", "--format", "ssh", "--key", root)
		other.cli("trust", "add", evil+".pub")
		other.cli("trust", "sign", "--format", "ssh", "--key", root)
		ours := e.chain()
		ours.Versions = append(ours.Versions, other.chain().Versions[1])
		e.setChain(ours)
		fails(t, e.wasb("check", "signature"), "signature", "version 2 does not follow version 1")
	})

	t.Run("teammate replaces a lost root key", func(t *testing.T) {
		e, root := signed(t)
		mate, newRoot := e.sshKey("mate"), e.sshKey("root2")
		e.cli("trust", "add", mate+".pub")
		e.cli("trust", "sign", "--format", "ssh", "--key", root)
		e.commit(root, "trust mate")
		// root's private key is gone from here on.
		e.cli("trust", "add", newRoot+".pub")
		e.cli("trust", "sign", "--format", "ssh", "--key", mate)
		e.replace(user, "KeepServer", "KeepServerAlways")
		e.commit(newRoot, "tighten")
		pass(t, e.wasb("check", "signature"))
	})

	t.Run("agent rolls the trust chain back", func(t *testing.T) {
		e, root := signed(t)
		mate := e.sshKey("mate")
		e.cli("trust", "add", mate+".pub")
		e.cli("trust", "sign", "--format", "ssh", "--key", root)
		e.commit(root, "trust mate")
		e.git("checkout", "HEAD~1", "--", ".wasb/trust.yaml")
		e.commit("", "untrust mate")
		fails(t, e.wasb("check", "signature"), "signature", "drops or rewrites versions")
	})

	t.Run("verifier planted in repo config", func(t *testing.T) {
		e, _ := signed(t)
		evil := e.sshKey("evil")
		e.replace(user, "KeepServer", "KeepServerMaybe")
		e.commit(evil, "relax")
		fake := filepath.Join(e.dir, "fake-ssh-keygen")
		if err := os.WriteFile(fake, []byte("#!/bin/sh\necho 'Good \"git\" signature for wasb with ED25519 key SHA256:x'\n"), 0o755); err != nil {
			t.Fatal(err)
		}
		e.git("config", "gpg.ssh.program", fake)
		fails(t, e.wasb("check", "signature"), "signature", "without a trusted signature")
	})

	t.Run("UserDeclared outside user", func(t *testing.T) {
		e, root := signed(t)
		e.replace(generated, "package Generated {", "package Generated {\n    requirement def Sneaky { @WASB::UserDeclared; }")
		e.commit(root, "sneak")
		fails(t, e.wasb("check", "signature"), "signature", "UserDeclared content outside")
	})
}

func TestSignatureGPG(t *testing.T) {
	e := modeled(t)
	e.run("gpg", "--batch", "--passphrase", "", "--quick-gen-key", "root <root@example.com>", "ed25519", "sign", "never")
	fpr := ""
	for _, l := range strings.Split(e.run("gpg", "--with-colons", "--list-keys", "root@example.com"), "\n") {
		if f := strings.Split(l, ":"); f[0] == "fpr" && fpr == "" {
			fpr = f[9]
		}
	}
	e.cli("trust", "add", fpr)
	e.cli("trust", "sign", "--format", "openpgp", "--key", fpr)
	e.git("add", "-A")
	e.git("-c", "gpg.format=openpgp", "-c", "user.signingkey="+fpr, "commit", "-q", "-S", "-m", "import")
	pass(t, e.wasb("check"))

	e.replace(user, "KeepServer", "KeepServerMaybe")
	e.commit("", "relax")
	fails(t, e.wasb("check", "signature"), "signature", "without a trusted signature")
}

func TestReferencePackage(t *testing.T) {
	src := os.Getenv("WASB_REFERENCE_PACKAGE")
	if src == "" {
		src = "../../../../uds-packages/reference-package"
	}
	if _, err := os.Stat(filepath.Join(src, "zarf.yaml")); err != nil {
		t.Skip("reference package not found; set WASB_REFERENCE_PACKAGE")
	}
	e := &env{t: t, dir: t.TempDir()}
	e.repo, e.cfg = filepath.Join(e.dir, "repo"), filepath.Join(e.dir, "cfg")
	e.run("git", "clone", "-q", src, e.repo)

	r := e.wasb("check", "unmodeled")
	fails(t, r, "unmodeled", "zarf.component reference-package[upstream] is not modeled")
	fails(t, r, "unmodeled", "uds.allow Keycloak OIDC backend (operator only generates for Authservice clients) is not modeled")
	fails(t, r, "unmodeled", "gha.job validate is not modeled")
	e.cli("import")
	pass(t, e.wasb("check", "unmodeled"))
	pass(t, e.wasb("check", "drift"))
	pass(t, e.wasb("check", "requirements"))

	e.replace("zarf.yaml", "reference-package:v0.3.0", "reference-package:v0.4.0")
	fails(t, e.wasb("check", "drift"), "drift", "zarf.component reference-package[upstream] changed")
}

func TestScanners(t *testing.T) {
	e := newEnv(t)
	e.fixture(true)
	r := e.wasb("check", "unmodeled")
	for _, want := range []string{
		"helm.template uds-package.yaml is not modeled",
		"helm.template _helpers.tpl is not modeled",
		"uds.allow Keycloak egress is not modeled",
		"uds.allow Debug egress is not modeled",
		"uds.expose gateway=tenant host=demo port=8080 service=demo is not modeled",
		"uds.task build is not modeled",
		"gha.job test is not modeled",
	} {
		fails(t, r, "unmodeled", want)
	}
	e.cli("import")
	pass(t, e.wasb("check", "unmodeled"))
	pass(t, e.wasb("check", "drift"))
	if !strings.Contains(e.read(generated), `:>> portNumber = 8080;`) || !strings.Contains(e.read(generated), `:>> runsOn = "ubuntu-latest";`) {
		t.Fatal("import did not record the targets' attributes")
	}

	t.Run("template edit is drift", func(t *testing.T) {
		e.replace("chart/templates/uds-package.yaml", "port: 8080\n        description: \"Keycloak egress\"", "port: 9090\n        description: \"Keycloak egress\"")
		r := e.wasb("check", "drift")
		fails(t, r, "drift", "helm.template uds-package.yaml changed")
		fails(t, r, "drift", "uds.allow Keycloak egress changed")
		e.fixDrift()
		pass(t, e.wasb("check", "drift"))
	})

	t.Run("model attribute edit is drift", func(t *testing.T) {
		e.replace(generated, `:>> remoteNamespace = "keycloak";`, `:>> remoteNamespace = "elsewhere";`)
		fails(t, e.wasb("check", "drift"), "drift", `remoteNamespace is "keycloak", the model says "elsewhere"`)
	})
}

func TestRequirements(t *testing.T) {
	setup := func(t *testing.T) (*env, string) {
		e := repo(t, true, storyReqs)
		return e, sign(t, e)
	}

	t.Run("loosened rule fails and is new", func(t *testing.T) {
		e, root := setup(t)
		e.replace("chart/templates/uds-package.yaml", "remoteNamespace: keycloak", "remoteNamespace: elsewhere")
		fails(t, e.wasb("check", "drift"), "drift", "uds.allow Keycloak egress changed")
		e.fixDrift()
		pass(t, e.wasb("check", "drift"))
		r := e.wasb("check", "requirements")
		fails(t, r, "requirements", `does not hold: rule.remoteNamespace == "keycloak"`)
		if !r.Diagnostics[0].New {
			t.Fatal("want the failure marked new against HEAD")
		}
		e.commit(root, "loosen")
		if r := e.wasb("check", "requirements"); r.Pass || r.Diagnostics[0].New {
			t.Fatalf("want an old failure after committing it, got %+v", r.Diagnostics)
		}
	})

	t.Run("deleting the rule and its element breaks the model", func(t *testing.T) {
		e, _ := setup(t)
		e.replace("chart/templates/uds-package.yaml", "      - direction: Egress\n        remoteNamespace: keycloak\n        port: 8080\n        description: \"Keycloak egress\"\n", "")
		s := e.read(generated)
		start := strings.Index(s, "    part 'chart/templates/uds-package.yaml#Keycloak egress'")
		end := start + strings.Index(s[start:], "\n    }\n") + len("\n    }\n")
		e.write(generated, s[:start]+s[end:])
		fails(t, e.wasb("check"), "model", "does not parse")
	})

	t.Run("dropping the satisfy claim", func(t *testing.T) {
		e, _ := setup(t)
		e.replace(user, "    satisfy keycloakEgress by Generated::'chart/templates/uds-package.yaml#Keycloak egress';\n", "")
		e.commit("", "drop claim")
		r := e.wasb("check")
		fails(t, r, "requirements", "nothing claims to satisfy this requirement")
		fails(t, r, "signature", "without a trusted signature")
	})

	t.Run("requirement without evidence class", func(t *testing.T) {
		e, _ := setup(t)
		e.replace(generated, "package Generated {", "package Generated {\n    requirement def Vague;")
		fails(t, e.wasb("check", "requirements"), "requirements", "requirement has no EvidenceClass")
	})

	t.Run("runtime evidence is never discharged by the model", func(t *testing.T) {
		e, _ := setup(t)
		e.replace(generated, "package Generated {", `package Generated {
    requirement def Uptime {
        @WASB::EvidenceClass { evidence = WASB::EvidenceClassKind::runtimeObservation; }
        subject rule : WASB::UDSAllow;
        require constraint { rule.remoteNamespace == "nowhere" }
    }
    requirement uptime : Uptime;
    satisfy uptime by Generated::'chart/templates/uds-package.yaml#Keycloak egress';`)
		r := e.wasb("check", "requirements")
		pass(t, r)
		var awaiting []string
		for _, a := range r.Manifest.AwaitingEvidence {
			awaiting = append(awaiting, a.Requirement+"="+a.Evidence)
		}
		if !slices.Contains(awaiting, "Generated::uptime=runtimeObservation") {
			t.Fatalf("want uptime awaiting runtime evidence, got %v", awaiting)
		}
	})
}

func TestImportFlow(t *testing.T) {
	e := newEnv(t)
	e.fixture(true)
	e.cli("import")
	e.cliFails("a model already exists", "import")
	e.cli("import", "--force")
	e.write(user, userReqs)

	e.replace("app/app.go", "Run(addr string)", "Run(addr string, port int)")
	r := e.wasb("check")
	if r.Mode != "warning-only" || !r.Pass {
		t.Fatalf("want warnings only before the import is signed, got mode=%s pass=%t", r.Mode, r.Pass)
	}
	fails(t, r, "drift", "go.func Server.Run changed")

	e.replace("app/app.go", "Run(addr string, port int)", "Run(addr string)")
	sign(t, e)
	e.replace("app/app.go", "Run(addr string)", "Run(addr string, port int)")
	fails(t, e.wasb("check"), "drift", "go.func Server.Run changed")

	t.Run("unsigned import commit stays warning-only", func(t *testing.T) {
		e := modeled(t)
		e.commit("", "import")
		e.replace("app/app.go", "Run(addr string)", "Run(addr string, port int)")
		if r := e.wasb("check"); r.Mode != "warning-only" || !r.Pass {
			t.Fatalf("want warnings only while the import commit is unsigned, got mode=%s pass=%t", r.Mode, r.Pass)
		}
	})
}

func TestPropose(t *testing.T) {
	e := repo(t, true, storyReqs)
	sign(t, e)
	proposed := filepath.Join(e.dir, "stricter.sysml")
	if err := os.WriteFile(proposed, []byte(strings.Replace(storyReqs, `== "keycloak"`, `== "elsewhere"`, 1)), 0o644); err != nil {
		t.Fatal(err)
	}
	var p struct {
		Status, Delta, Regeneration string
		Constraints                 []struct{ Requirement, Before, After string }
		Impact                      struct{ NewlyFailing []string }
	}
	if err := json.Unmarshal([]byte(e.run(bin, "--json", "--repo", e.repo, "propose", "stricter", user+"="+proposed)), &p); err != nil {
		t.Fatal(err)
	}
	if p.Status != "pending" || !strings.Contains(p.Delta, `+        require constraint { rule.remoteNamespace == "elsewhere" }`) {
		t.Fatalf("want a pending proposal with its delta, got %+v", p)
	}
	if len(p.Constraints) != 1 || p.Constraints[0].Before != "holds" || p.Constraints[0].After != "violated" || len(p.Impact.NewlyFailing) != 1 {
		t.Fatalf("want keycloakEgress to go from holds to violated, got %+v", p)
	}
	if e.read(user) != storyReqs {
		t.Fatal("propose changed the model")
	}
	pass(t, e.wasb("check"))

	e.cli("propose", "reject", "stricter", "--reason", "too strict")
	if out := e.run(bin, "--repo", e.repo, "propose", "list"); !strings.Contains(out, "stricter rejected too strict") {
		t.Fatalf("want the rejection recorded, got %q", out)
	}

	withFunc := filepath.Join(e.dir, "with-func.sysml")
	if err := os.WriteFile(withFunc, []byte(strings.Replace(e.read(generated), "package Generated {\n", "package Generated {\n"+missingFunc, 1)), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal([]byte(e.run(bin, "--json", "--repo", e.repo, "propose", "add-func", generated+"="+withFunc)), &p); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(p.Regeneration, "+func Missing() error {") {
		t.Fatalf("want the stub in the regeneration diff, got %q", p.Regeneration)
	}

	t.Run("AgentSuggested content in the model", func(t *testing.T) {
		e.replace(generated, "package Generated {", "package Generated {\n    part idea { @WASB::AgentSuggested; }")
		fails(t, e.wasb("check", "signature"), "signature", "AgentSuggested content is in the model")
	})
}

func TestGenerate(t *testing.T) {
	e := modeled(t)
	e.replace(generated, "package Generated {\n", "package Generated {\n"+missingFunc)
	fails(t, e.wasb("check", "drift"), "drift", "go.func Missing no longer exists")
	if out := e.run(bin, "--repo", e.repo, "generate"); !strings.Contains(out, "+func Missing() error {") {
		t.Fatalf("want the stub in the diff, got %q", out)
	}
	e.cli("generate", "--write")
	if s := e.read("app/wasb_generated.go"); !strings.Contains(s, "package app\n") || !strings.Contains(s, "func Missing() error {\n\tpanic(\"wasb: not implemented\")\n}") {
		t.Fatalf("unexpected stub file:\n%s", s)
	}
	pass(t, e.wasb("check", "drift"))
	pass(t, e.wasb("check", "unmodeled"))
}

func TestCoverage(t *testing.T) {
	e := modeled(t)
	e.replace("app/app.go", "error { return nil }", "error {\n\tif addr == \"\" {\n\t\treturn nil\n\t}\n\treturn nil\n}")
	pass(t, e.wasb("check", "drift"))
	r := e.wasb("coverage")
	pass(t, r)
	if len(r.Manifest.Files) == 0 || r.Manifest.Files[0].File != "app/app.go" || r.Manifest.Files[0].Modeled != 2 {
		t.Fatalf("want app/app.go fully modeled, got %+v", r.Manifest.Files)
	}
	if len(r.Manifest.KnownGaps) < 6 || r.Manifest.KnownGaps[0].Element != "WASB::Checker" {
		t.Fatalf("want wasb's own known gaps, got %+v", r.Manifest.KnownGaps)
	}
	e.replace(generated, `@WASB::Anchor { path = "app"; kind = "go.func"; id = "Server.Run"; }`,
		`@WASB::Anchor { path = "app"; kind = "go.func"; id = "Server.Run"; }
        @WASB::Coverage { generatedFraction = 0.5; }`)
	fails(t, e.wasb("coverage"), "coverage", "generated fraction 0.17 is below the 0.50 the model requires")
}

func TestMCP(t *testing.T) {
	e := modeled(t)
	ctx := context.Background()
	session, err := mcp.NewClient(&mcp.Implementation{Name: "e2e"}, nil).
		Connect(ctx, &mcp.CommandTransport{Command: exec.Command(bin, "--repo", e.repo, "mcp")}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = session.Close() }()

	tools, err := session.ListTools(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, tool := range tools.Tools {
		names = append(names, tool.Name)
	}
	for _, want := range []string{"check", "status", "coverage", "import", "generate", "propose", "proposals", "model_evaluate", "model_elements", "model_edit"} {
		if !slices.Contains(names, want) {
			t.Fatalf("missing tool %s in %v", want, names)
		}
	}
	call := func(name string, args map[string]any) *mcp.CallToolResult {
		t.Helper()
		res, err := session.CallTool(ctx, &mcp.CallToolParams{Name: name, Arguments: args})
		if err != nil {
			t.Fatal(err)
		}
		return res
	}
	if res := call("check", map[string]any{"gate": "drift"}); res.IsError || !res.StructuredContent.(map[string]any)["pass"].(bool) {
		t.Fatalf("want drift to pass over MCP, got %+v", res)
	}
	if res := call("model_evaluate", map[string]any{"expression": "Generated::'app#New'::signature"}); res.IsError || !strings.Contains(res.StructuredContent.(map[string]any)["value"].(string), "func New() *Server") {
		t.Fatalf("want New's signature, got %+v", res)
	}
	if res := call("model_edit", map[string]any{"path": user, "content": "package X {}"}); !res.IsError {
		t.Fatal("model_edit wrote user requirements")
	}
	if res := call("model_edit", map[string]any{"path": generated, "content": "package Broken {"}); !res.IsError {
		t.Fatal("model_edit accepted a model that does not parse")
	}
}

// fauxModel answers every prompt with "done" three times, then runs out, and logs each settle.
const fauxModel = `import { fauxProvider, fauxAssistantMessage } from "@earendil-works/pi-ai";
import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import { appendFileSync } from "node:fs";
export default function (pi: ExtensionAPI) {
	const faux = fauxProvider();
	faux.setResponses(Array.from({ length: 3 }, () => fauxAssistantMessage("done")));
	pi.registerProvider(faux.provider);
	pi.on("agent_settled", () => appendFileSync(process.env.FAUX_LOG!, "modelCalls=" + faux.state.callCount + "\n"));
}
`

func TestPiHarness(t *testing.T) {
	pi := os.Getenv("WASB_PI")
	if pi == "" {
		t.Skip("set WASB_PI to a pi >= 1.4 binary")
	}
	gateExt, err := filepath.Abs("../../harness/pi/wasb-gate.ts")
	if err != nil {
		t.Fatal(err)
	}
	run := func(e *env) (settles, out string) {
		faux, log := filepath.Join(e.dir, "faux.ts"), filepath.Join(e.dir, "faux.log")
		if err := os.WriteFile(faux, []byte(fauxModel), 0o644); err != nil {
			t.Fatal(err)
		}
		_ = os.Remove(log)
		cmd := exec.Command(pi, "-p", "--mode", "json", "--no-session", "-ne", "-e", faux, "-e", gateExt, "--provider", "faux", "--model", "faux-1", "finish")
		cmd.Dir = e.repo
		cmd.Env = append(os.Environ(), "WASB_BIN="+bin, "FAUX_LOG="+log, "PI_CODING_AGENT_DIR="+filepath.Join(e.dir, "pi"))
		b, _ := cmd.Output()
		l, _ := os.ReadFile(log)
		return strings.TrimSpace(string(l)), string(b)
	}

	e, _ := signed(t)
	if settles, out := run(e); settles != "modelCalls=1" || strings.Contains(out, `"customType":"wasb-gate"`) {
		t.Fatalf("want a passing repo to settle after one call, got %q", settles)
	}
	e.replace("app/app.go", "Run(addr string)", "Run(addr string, port int)")
	settles, out := run(e)
	if n := strings.Count(out, `"customType":"wasb-gate"`); n != 3 || !strings.Contains(out, "go.func Server.Run changed") {
		t.Fatalf("want every answer gated with the drift diagnostic, got %d gate messages, settles %q", n, settles)
	}
}
