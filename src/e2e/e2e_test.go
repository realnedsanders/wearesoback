// Package e2e drives the built wasb binary against scratch git repositories.
package e2e

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

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
    requirement def KeepServer { @WASB::UserDeclared; }
}
`
	generated = ".wasb/model/generated/model.sysml"
	user      = ".wasb/model/user/requirements.sysml"
)

type result struct {
	Pass        bool `json:"pass"`
	Diagnostics []struct {
		Gate, Element, Path, Message, Fix string
		Line                              int
	} `json:"diagnostics"`
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

func fails(t *testing.T, r result, gate, msg string) {
	t.Helper()
	for _, d := range r.Diagnostics {
		if d.Gate == gate && strings.Contains(d.Message, msg) {
			return
		}
	}
	t.Fatalf("want %s diagnostic containing %q, got %+v", gate, msg, r.Diagnostics)
}

// modeled writes the fixture and a model built from the unmodeled gate's own fixes.
func modeled(t *testing.T) *env {
	e := newEnv(t)
	e.write("app/app.go", appGo)
	e.write("app/app_test.go", appTestGo)
	e.write("zarf.yaml", zarfYAML)
	e.write(user, userReqs)
	r := e.wasb("check", "unmodeled")
	var fixes []string
	for _, d := range r.Diagnostics {
		fixes = append(fixes, "    "+d.Fix)
	}
	e.write(generated, "package Generated {\n"+strings.Join(fixes, "\n")+"\n}\n")
	return e
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
		r := e.wasb("check", "drift")
		fails(t, r, "drift", "go.func Server.Run changed but the model did not")
		var stale string
		for _, el := range strings.Split(e.read(generated), "\n") {
			if strings.Contains(el, `id = "Server.Run"`) {
				stale = el[strings.Index(el, "lastHash = ")+len("lastHash = ") : strings.LastIndex(el, `";`)+1]
			}
		}
		fix := r.Diagnostics[0].Fix
		e.replace(generated, stale, fix[strings.Index(fix, "lastHash = ")+len("lastHash = "):])
		pass(t, e.wasb("check", "drift"))
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
	root = e.sshKey("root")
	e.cli("trust", "add", root+".pub")
	e.cli("trust", "sign", "--format", "ssh", "--key", root)
	e.commit(root, "import")
	pass(t, e.wasb("check"))
	return e, root
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
	fails(t, r, "unmodeled", "zarf.component reference-package[unicorn] is not modeled")
	var fixes []string
	for _, d := range r.Diagnostics {
		fixes = append(fixes, "    "+d.Fix)
	}
	e.write(generated, "package Generated {\n"+strings.Join(fixes, "\n")+"\n}\n")
	pass(t, e.wasb("check", "unmodeled"))
	pass(t, e.wasb("check", "drift"))

	e.replace("zarf.yaml", "reference-package:v0.3.0", "reference-package:v0.4.0")
	fails(t, e.wasb("check", "drift"), "drift", "zarf.component reference-package[upstream] changed")
}
