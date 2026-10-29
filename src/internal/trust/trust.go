// Package trust manages .wasb/trust.yaml, an append-only chain of trusted
// key sets. Version 1 is signed by a key it lists. Every later version names
// the digest of the version before it and is signed by a key that version
// lists, so any one trusted key can change the set but no other key can.
package trust

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"

	"go.yaml.in/yaml/v3"
)

// File is the trust chain, repo-relative.
const File = ".wasb/trust.yaml"

const namespace = "wasb-trust"

// Key is one trusted public key.
type Key struct {
	Type        string `json:"type"` // "ssh" or "gpg"
	Fingerprint string `json:"fingerprint"`
	data        string
}

// Version is one key set in the chain.
type Version struct {
	// Nonce makes version 1 unique, so versions signed for another repo's chain never link into this one.
	Nonce     string   `yaml:"nonce,omitempty"`
	Previous  string   `yaml:"previous,omitempty"`
	Keys      []string `yaml:"keys"`
	Signer    string   `yaml:"signer,omitempty"`
	Signature string   `yaml:"signature,omitempty"`
}

// payload is what a version's signature covers.
func (v Version) payload() []byte {
	b, _ := json.Marshal(struct {
		Nonce    string   `json:"nonce"`
		Previous string   `json:"previous"`
		Keys     []string `json:"keys"`
	}{v.Nonce, v.Previous, v.Keys})
	return b
}

func (v Version) digest() string {
	sum := sha256.Sum256(v.payload())
	return hex.EncodeToString(sum[:])
}

// Chain is the trust file.
type Chain struct {
	Versions []Version `yaml:"versions"`
	path     string
}

// Load reads the chain at path. A missing file is an empty chain.
func Load(path string) (*Chain, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return &Chain{path: path}, nil
	}
	if err != nil {
		return nil, err
	}
	c, err := Parse(b)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	c.path = path
	return c, nil
}

// Parse reads a chain without checking it.
func Parse(b []byte) (*Chain, error) {
	var c Chain
	return &c, yaml.Unmarshal(b, &c)
}

func (c *Chain) save() error {
	b, err := yaml.Marshal(c)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(c.path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(c.path, b, 0o644)
}

// State is what a verified chain vouches for.
type State struct {
	Root    string // fingerprint of the key that signed version 1
	Genesis []Key  // keys of version 1
	Keys    []Key  // keys of the last version
}

// Verify checks every link of the chain.
func (c *Chain) Verify() (State, error) {
	var st State
	for i, v := range c.Versions {
		keys, err := parseAll(v.Keys)
		if err != nil {
			return st, fmt.Errorf("version %d: %w", i+1, err)
		}
		if v.Signature == "" {
			return st, fmt.Errorf("version %d is not signed", i+1)
		}
		signers, prev := keys, ""
		if i > 0 {
			signers, prev = st.Keys, c.Versions[i-1].digest()
		}
		if v.Previous != prev {
			return st, fmt.Errorf("version %d does not follow version %d", i+1, i)
		}
		j := slices.IndexFunc(signers, func(k Key) bool { return k.Fingerprint == v.Signer })
		if j < 0 {
			return st, fmt.Errorf("version %d is signed by %s, which version %d does not trust", i+1, v.Signer, max(i, 1))
		}
		if err := verify(signers[j], v.payload(), []byte(v.Signature)); err != nil {
			return st, fmt.Errorf("version %d: %w", i+1, err)
		}
		if i == 0 {
			st.Root, st.Genesis = v.Signer, keys
		}
		st.Keys = keys
	}
	return st, nil
}

// signed is the chain without an unsigned last version.
func (c *Chain) signed() []Version {
	n := len(c.Versions)
	if n > 0 && c.Versions[n-1].Signature == "" {
		n--
	}
	return c.Versions[:n]
}

// Extends reports whether c's signed versions start with old's, so nothing
// old vouched for was dropped or rewritten.
func (c *Chain) Extends(old *Chain) bool {
	o, n := old.signed(), c.signed()
	if len(o) > len(n) {
		return false
	}
	for i := range o {
		if o[i].digest() != n[i].digest() {
			return false
		}
	}
	return true
}

// Keys returns the latest version's keys and whether that version awaits a signature.
func (c *Chain) Keys() ([]Key, bool, error) {
	n := len(c.Versions)
	if n == 0 {
		return nil, false, nil
	}
	keys, err := parseAll(c.Versions[n-1].Keys)
	return keys, c.Versions[n-1].Signature == "", err
}

// pending returns the unsigned last version, starting one from the last signed version if needed.
func (c *Chain) pending() *Version {
	n := len(c.Versions)
	if n == 0 || c.Versions[n-1].Signature != "" {
		next := Version{Nonce: rand.Text()}
		if n > 0 {
			last := c.Versions[n-1]
			next = Version{Previous: last.digest(), Keys: slices.Clone(last.Keys)}
		}
		c.Versions = append(c.Versions, next)
	}
	return &c.Versions[len(c.Versions)-1]
}

// Add trusts a key given as an SSH public key file, an armored GPG key file,
// an SSH public key line, or a GPG key id in the local keyring. The change
// lands in an unsigned version until Sign.
func (c *Chain) Add(arg string) (Key, error) {
	k, err := resolve(arg)
	if err != nil {
		return Key{}, err
	}
	p := c.pending()
	keys, err := parseAll(p.Keys)
	if err != nil {
		return Key{}, err
	}
	if slices.ContainsFunc(keys, func(o Key) bool { return o.Fingerprint == k.Fingerprint }) {
		return Key{}, fmt.Errorf("%s is already trusted", k.Fingerprint)
	}
	p.Keys = append(p.Keys, k.data)
	return k, c.save()
}

// Remove stops trusting the key with fingerprint. Commits it signed stop
// verifying, so remove only a compromised key; keep a lost one.
func (c *Chain) Remove(fingerprint string) error {
	p := c.pending()
	keys, err := parseAll(p.Keys)
	if err != nil {
		return err
	}
	i := slices.IndexFunc(keys, func(k Key) bool { return k.Fingerprint == fingerprint })
	if i < 0 {
		return fmt.Errorf("%s is not trusted", fingerprint)
	}
	p.Keys = slices.Delete(p.Keys, i, i+1)
	return c.save()
}

// Sign signs the unsigned last version with key in format ("ssh" or
// "openpgp", as git's gpg.format) and returns the signer's fingerprint.
// Version 1 takes a key it lists; later versions take a key the version
// before lists.
func (c *Chain) Sign(format, key string) (string, error) {
	n := len(c.Versions)
	if n == 0 || c.Versions[n-1].Signature != "" {
		return "", errors.New("nothing to sign: add or remove a key first")
	}
	v := &c.Versions[n-1]
	signers := v.Keys
	if n > 1 {
		signers = c.Versions[n-2].Keys
	}
	keys, err := parseAll(signers)
	if err != nil {
		return "", err
	}
	sig, err := sign(format, key, v.payload())
	if err != nil {
		return "", err
	}
	for _, k := range keys {
		if verify(k, v.payload(), sig) == nil {
			v.Signer, v.Signature = k.Fingerprint, string(sig)
			return k.Fingerprint, c.save()
		}
	}
	return "", fmt.Errorf("the signing key is not trusted by version %d", max(n-1, 1))
}

func sign(format, key string, data []byte) ([]byte, error) {
	dir, err := os.MkdirTemp("", "wasb-")
	if err != nil {
		return nil, err
	}
	defer func() { _ = os.RemoveAll(dir) }()
	file := filepath.Join(dir, "payload")
	if err := os.WriteFile(file, data, 0o600); err != nil {
		return nil, err
	}
	switch format {
	case "ssh":
		if lit, ok := strings.CutPrefix(key, "key::"); ok {
			key = filepath.Join(dir, "key.pub")
			if err := os.WriteFile(key, []byte(lit), 0o600); err != nil {
				return nil, err
			}
		}
		if _, err := run(nil, true, "ssh-keygen", "-Y", "sign", "-n", namespace, "-f", key, file); err != nil {
			return nil, err
		}
		return os.ReadFile(file + ".sig")
	case "openpgp", "":
		args := []string{"--armor", "--detach-sign", "--output", "-"}
		if key != "" {
			args = append(args, "--local-user", key)
		}
		return run(nil, true, "gpg", append(args, file)...)
	}
	return nil, fmt.Errorf("unsupported signing format %q", format)
}

// Verifier is git configuration that makes %G? answer G only for the given keys.
type Verifier struct {
	Args, Env []string
	dir       string
}

// Close removes the verifier's keyrings.
func (v *Verifier) Close() { _ = os.RemoveAll(v.dir) }

// NewVerifier builds an SSH allowed-signers file and a GPG keyring holding only keys.
func NewVerifier(keys []Key) (*Verifier, error) {
	dir, err := os.MkdirTemp("", "wasb-")
	if err != nil {
		return nil, err
	}
	v := &Verifier{dir: dir}
	home := filepath.Join(dir, "gnupg")
	if err := os.Mkdir(home, 0o700); err != nil {
		v.Close()
		return nil, err
	}
	var allowed, ownertrust strings.Builder
	for _, k := range keys {
		if k.Type == "ssh" {
			fmt.Fprintf(&allowed, "wasb %s\n", k.data)
			continue
		}
		if err := gpgImport(home, k.data); err != nil {
			v.Close()
			return nil, err
		}
		fmt.Fprintf(&ownertrust, "%s:6:\n", k.Fingerprint)
	}
	signers := filepath.Join(dir, "allowed_signers")
	if err := os.WriteFile(signers, []byte(allowed.String()), 0o600); err != nil {
		v.Close()
		return nil, err
	}
	if ownertrust.Len() > 0 {
		if err := runIn(home, []byte(ownertrust.String()), "--import-ownertrust"); err != nil {
			v.Close()
			return nil, err
		}
	}
	// Command-line config outranks repo config, so a planted gpg.program cannot vouch for itself.
	v.Args = []string{
		"-c", "gpg.ssh.allowedSignersFile=" + signers,
		"-c", "gpg.program=gpg", "-c", "gpg.openpgp.program=gpg", "-c", "gpg.ssh.program=ssh-keygen",
	}
	v.Env = []string{"GNUPGHOME=" + home}
	return v, nil
}

// resolve reads a key argument: a key file, an SSH public key line, or a GPG key id.
func resolve(arg string) (Key, error) {
	data := arg
	if b, err := os.ReadFile(arg); err == nil {
		data = string(b)
	} else if !strings.Contains(arg, " ") {
		b, err := run(nil, false, "gpg", "--armor", "--export", arg)
		if err != nil || len(b) == 0 {
			return Key{}, fmt.Errorf("%s is not a key file, an SSH key or a GPG key id in your keyring", arg)
		}
		data = string(b)
	}
	return parse(strings.TrimSpace(data))
}

func parseAll(data []string) ([]Key, error) {
	keys := make([]Key, len(data))
	for i, d := range data {
		k, err := parse(d)
		if err != nil {
			return nil, err
		}
		keys[i] = k
	}
	return keys, nil
}

func parse(data string) (Key, error) {
	if strings.HasPrefix(data, "-----BEGIN PGP PUBLIC KEY BLOCK-----") {
		fpr, err := gpgFingerprint(data)
		return Key{Type: "gpg", Fingerprint: fpr, data: data}, err
	}
	fields := strings.Fields(data)
	if len(fields) < 2 {
		return Key{}, fmt.Errorf("not an SSH or GPG public key: %.40q", data)
	}
	blob, err := base64.StdEncoding.DecodeString(fields[1])
	if err != nil {
		return Key{}, fmt.Errorf("not an SSH public key: %w", err)
	}
	sum := sha256.Sum256(blob)
	return Key{Type: "ssh", Fingerprint: "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:]), data: data}, nil
}

func verify(k Key, data, sig []byte) error {
	dir, err := os.MkdirTemp("", "wasb-")
	if err != nil {
		return err
	}
	defer func() { _ = os.RemoveAll(dir) }()
	dataFile, sigFile := filepath.Join(dir, "data"), filepath.Join(dir, "sig")
	if err := os.WriteFile(dataFile, data, 0o600); err != nil {
		return err
	}
	if err := os.WriteFile(sigFile, sig, 0o600); err != nil {
		return err
	}

	if k.Type == "ssh" {
		signers := filepath.Join(dir, "allowed_signers")
		if err := os.WriteFile(signers, []byte("wasb "+k.data+"\n"), 0o600); err != nil {
			return err
		}
		cmd := exec.Command("ssh-keygen", "-Y", "verify", "-f", signers, "-I", "wasb", "-n", namespace, "-s", sigFile)
		cmd.Stdin = bytes.NewReader(data)
		if out, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("bad signature: %s", strings.TrimSpace(string(out)))
		}
		return nil
	}

	home := filepath.Join(dir, "gnupg")
	if err := os.Mkdir(home, 0o700); err != nil {
		return err
	}
	if err := gpgImport(home, k.data); err != nil {
		return err
	}
	out, _ := run([]string{"GNUPGHOME=" + home}, false, "gpg", "--batch", "--status-fd", "1", "--verify", sigFile, dataFile)
	for _, l := range strings.Split(string(out), "\n") {
		f := strings.Fields(l)
		if len(f) > 2 && f[1] == "VALIDSIG" && f[len(f)-1] == k.Fingerprint {
			return nil
		}
	}
	return errors.New("bad signature")
}

func gpgFingerprint(armored string) (string, error) {
	cmd := exec.Command("gpg", "--batch", "--with-colons", "--import-options", "show-only", "--import")
	cmd.Stdin = strings.NewReader(armored)
	b, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("gpg: %w", err)
	}
	for _, l := range strings.Split(string(b), "\n") {
		if f := strings.Split(l, ":"); f[0] == "fpr" && len(f) > 9 {
			return f[9], nil // the first fpr record is the primary key's
		}
	}
	return "", errors.New("no GPG public key found")
}

func gpgImport(home, armored string) error {
	return runIn(home, []byte(armored), "--import")
}

func runIn(home string, stdin []byte, args ...string) error {
	cmd := exec.Command("gpg", append([]string{"--batch", "--quiet"}, args...)...)
	cmd.Env = append(os.Environ(), "GNUPGHOME="+home)
	cmd.Stdin = bytes.NewReader(stdin)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("gpg %s: %w: %s", args[0], err, strings.TrimSpace(string(out)))
	}
	return nil
}

// run runs name; interactive passes stderr through so pinentry and
// security-key touch prompts reach the user.
func run(env []string, interactive bool, name string, args ...string) ([]byte, error) {
	cmd := exec.Command(name, args...)
	cmd.Env = append(os.Environ(), env...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if interactive {
		cmd.Stderr = os.Stderr
	}
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("%s: %w: %s", name, err, strings.TrimSpace(stderr.String()))
	}
	return out, nil
}
