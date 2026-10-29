// Command wasb keeps a repository honest to the SysML v2 model in .wasb/.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/realnedsanders/wearesoback/src/internal/gate"
	"github.com/realnedsanders/wearesoback/src/internal/git"
	"github.com/realnedsanders/wearesoback/src/internal/model"
	"github.com/realnedsanders/wearesoback/src/internal/trust"
)

// errFailed is returned after the diagnostics are printed.
var errFailed = errors.New("gates failed")

func main() {
	err := rootCmd().ExecuteContext(context.Background())
	if err != nil && !errors.Is(err, errFailed) {
		fmt.Fprintln(os.Stderr, "wasb:", err)
	}
	if err != nil {
		os.Exit(1)
	}
}

func rootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:           "wasb",
		Short:         "Structural backpressure for a SysML v2 model kept in .wasb/",
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	configDir, _ := os.UserConfigDir()
	f := root.PersistentFlags()
	f.String("repo", ".", "repository to work on")
	f.Bool("json", false, "machine-readable output")
	f.String("config-dir", filepath.Join(configDir, "wasb"), "directory holding config.yaml")
	_ = viper.BindPFlags(f)
	viper.SetEnvPrefix("WASB")
	viper.SetEnvKeyReplacer(strings.NewReplacer("-", "_"))
	viper.AutomaticEnv()
	root.PersistentPreRunE = func(*cobra.Command, []string) error {
		viper.SetConfigFile(filepath.Join(viper.GetString("config-dir"), "config.yaml"))
		if err := viper.ReadInConfig(); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
		return nil
	}
	root.AddCommand(checkCmd(), trustCmd())
	return root
}

var gates = []string{"drift", "unmodeled", "signature"}

func checkCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "check",
		Short: "Run every gate",
		Args:  cobra.NoArgs,
		RunE:  func(c *cobra.Command, _ []string) error { return check(c, gates...) },
	}
	for _, g := range gates {
		cmd.AddCommand(&cobra.Command{
			Use:   g,
			Short: "Run the " + g + " gate",
			Args:  cobra.NoArgs,
			RunE:  func(c *cobra.Command, _ []string) error { return check(c, g) },
		})
	}
	return cmd
}

func check(cmd *cobra.Command, run ...string) error {
	var ds []gate.Diagnostic
	fail := func(g string, err error) error {
		return report(cmd, append(ds, gate.Diagnostic{Gate: g, Message: err.Error()}))
	}
	root, err := repoRoot()
	if err != nil {
		return fail("wasb", err)
	}
	files, err := gate.Files(root)
	if err != nil {
		return fail("wasb", err)
	}
	var modelFiles []string
	for _, f := range files {
		if strings.HasPrefix(f, model.Dir+"/") && strings.HasSuffix(f, ".sysml") {
			modelFiles = append(modelFiles, f)
		}
	}
	elems, err := model.Load(cmd.Context(), root, modelFiles)
	if err != nil {
		return fail("model", err)
	}
	var targets []gate.Target
	if slices.Contains(run, "drift") || slices.Contains(run, "unmodeled") {
		if targets, err = gate.Targets(root, files); err != nil {
			return fail("scan", err)
		}
	}
	for _, g := range run {
		switch g {
		case "drift":
			ds = append(ds, gate.Drift(elems, targets)...)
		case "unmodeled":
			ds = append(ds, gate.Unmodeled(elems, targets)...)
		case "signature":
			ds = append(ds, gate.Signature(root, elems)...)
		}
	}
	return report(cmd, ds)
}

func report(cmd *cobra.Command, ds []gate.Diagnostic) error {
	out := cmd.OutOrStdout()
	if viper.GetBool("json") {
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		err := enc.Encode(struct {
			Pass        bool              `json:"pass"`
			Diagnostics []gate.Diagnostic `json:"diagnostics"`
		}{len(ds) == 0, append([]gate.Diagnostic{}, ds...)})
		if err != nil {
			return err
		}
	} else {
		for _, d := range ds {
			loc := d.Path
			if d.Line > 0 {
				loc += fmt.Sprintf(":%d", d.Line)
			}
			if d.Element != "" {
				loc += " " + d.Element
			}
			_, _ = fmt.Fprintf(out, "%s: [%s] %s\n", loc, d.Gate, d.Message)
			if d.Fix != "" {
				_, _ = fmt.Fprintf(out, "    fix: %s\n", d.Fix)
			}
		}
		if len(ds) == 0 {
			_, _ = fmt.Fprintln(out, "ok")
		}
	}
	if len(ds) > 0 {
		return errFailed
	}
	return nil
}

func trustCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "trust",
		Short: "Manage the keys whose signatures wasb accepts",
		Long: "Trusted keys live in " + trust.File + ", an append-only chain of key sets.\n" +
			"Adding or removing keys starts a new version, which wasb trust sign signs with a key\n" +
			"the previous version trusts. Version 1 must be signed by the key that signs the first\n" +
			"commit touching .wasb/. Keep a lost key in the set; remove only a compromised one,\n" +
			"since commits it signed stop verifying.",
	}
	load := func() (*trust.Chain, error) {
		root, err := repoRoot()
		if err != nil {
			return nil, err
		}
		return trust.Load(filepath.Join(root, trust.File))
	}

	list := &cobra.Command{
		Use:   "list",
		Short: "List the latest version's keys and whether it awaits a signature",
		Args:  cobra.NoArgs,
		RunE: func(c *cobra.Command, _ []string) error {
			ts, err := load()
			if err != nil {
				return err
			}
			keys, pending, err := ts.Keys()
			if err != nil {
				return err
			}
			text := ""
			for _, k := range keys {
				text += fmt.Sprintf("%s %s\n", k.Type, k.Fingerprint)
			}
			if pending {
				text += "unsigned: run wasb trust sign\n"
			}
			return emit(c, map[string]any{"keys": append([]trust.Key{}, keys...), "pending": pending}, text)
		},
	}

	add := &cobra.Command{
		Use:   "add <key-file|ssh-public-key|gpg-key-id>",
		Short: "Trust an SSH or GPG public key",
		Args:  cobra.ExactArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			ts, err := load()
			if err != nil {
				return err
			}
			k, err := ts.Add(args[0])
			if err != nil {
				return err
			}
			return emit(c, k, fmt.Sprintf("trusted %s %s; run wasb trust sign\n", k.Type, k.Fingerprint))
		},
	}

	remove := &cobra.Command{
		Use:   "remove <fingerprint>",
		Short: "Stop trusting a key",
		Args:  cobra.ExactArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			ts, err := load()
			if err != nil {
				return err
			}
			if err := ts.Remove(args[0]); err != nil {
				return err
			}
			return emit(c, map[string]string{"removed": args[0]}, fmt.Sprintf("removed %s; run wasb trust sign\n", args[0]))
		},
	}

	sign := &cobra.Command{
		Use:   "sign",
		Short: "Sign the pending version, by default with git's gpg.format and user.signingkey",
		Args:  cobra.NoArgs,
		RunE: func(c *cobra.Command, _ []string) error {
			ts, err := load()
			if err != nil {
				return err
			}
			format, _ := c.Flags().GetString("format")
			key, _ := c.Flags().GetString("key")
			if format == "" {
				format, _ = git.Run(viper.GetString("repo"), nil, "config", "--get", "gpg.format")
			}
			if key == "" {
				key, _ = git.Run(viper.GetString("repo"), nil, "config", "--get", "user.signingkey")
			}
			fpr, err := ts.Sign(format, key)
			if err != nil {
				return err
			}
			return emit(c, map[string]string{"signed": fpr}, fmt.Sprintf("signed by %s\n", fpr))
		},
	}
	sign.Flags().String("format", "", `"ssh" or "openpgp" (default: git config gpg.format, else openpgp)`)
	sign.Flags().String("key", "", "SSH key file or GPG key id (default: git config user.signingkey)")

	cmd.AddCommand(list, add, remove, sign)
	return cmd
}

func repoRoot() (string, error) {
	return git.Run(viper.GetString("repo"), nil, "rev-parse", "--show-toplevel")
}

// emit writes v as JSON with --json, else text.
func emit(cmd *cobra.Command, v any, text string) error {
	if viper.GetBool("json") {
		return json.NewEncoder(cmd.OutOrStdout()).Encode(v)
	}
	_, err := fmt.Fprint(cmd.OutOrStdout(), text)
	return err
}
