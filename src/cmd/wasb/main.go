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
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/realnedsanders/wearesoback/src/internal/app"
	"github.com/realnedsanders/wearesoback/src/internal/gate"
	"github.com/realnedsanders/wearesoback/src/internal/git"
	"github.com/realnedsanders/wearesoback/src/internal/pi"
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
	root.AddCommand(initCmd(), checkCmd(), importCmd(), generateCmd(), proposeCmd(), statusCmd(), coverageCmd(), trustCmd(), mcpCmd())
	return root
}

func initCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "init",
		Short: "Install the pi gate: an agent in pi cannot finish while wasb check fails",
		Long: "Write wasb's gate into pi's personal extensions ($PI_CODING_AGENT_DIR, else ~/.pi/agent),\n" +
			"pointed at this wasb binary by absolute path. It gates every pi session in a repository\n" +
			"where a commit has touched .wasb/, and leaves other directories alone. Run it again after\n" +
			"moving or upgrading wasb. Needs pi 1.4 or later.",
		Args: cobra.NoArgs,
		RunE: func(c *cobra.Command, _ []string) error {
			bin, err := os.Executable()
			if err != nil {
				return err
			}
			if bin, err = filepath.EvalSymlinks(bin); err != nil {
				return err
			}
			path, err := pi.Install(bin)
			if err != nil {
				return err
			}
			return emit(c, map[string]string{"extension": path, "wasb": bin},
				fmt.Sprintf("installed: %s\nwasb path: %s\nrestart pi or run /reload\n", path, bin))
		},
	}
}

func checkCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "check",
		Short: "Run every gate",
		Long:  "Run every gate. Until the first commit touching .wasb/ is signed, failures are warnings.",
		Args:  cobra.NoArgs,
		RunE:  func(c *cobra.Command, _ []string) error { return check(c, app.Gates...) },
	}
	cmd.PersistentFlags().Bool("if-managed", false, "pass without checking unless a commit has touched .wasb/ (the pi gate uses this)")
	for _, g := range app.Gates {
		cmd.AddCommand(&cobra.Command{
			Use:   g,
			Short: "Run the " + g + " gate",
			Args:  cobra.NoArgs,
			RunE:  func(c *cobra.Command, _ []string) error { return check(c, g) },
		})
	}
	return cmd
}

func check(cmd *cobra.Command, gates ...string) error {
	if ifManaged, _ := cmd.Flags().GetBool("if-managed"); ifManaged && !app.Managed(viper.GetString("repo")) {
		return emit(cmd, app.Report{Pass: true, Mode: "unmanaged", Diagnostics: []gate.Diagnostic{}}, "unmanaged: no commit has touched .wasb/\n")
	}
	root, err := repoRoot()
	if err != nil {
		return err
	}
	r, err := app.Check(cmd.Context(), root, gates...)
	if err != nil {
		return err
	}
	out := cmd.OutOrStdout()
	if viper.GetBool("json") {
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		if err := enc.Encode(r); err != nil {
			return err
		}
	} else {
		for _, d := range r.Diagnostics {
			loc := d.Path
			if d.Line > 0 {
				loc += fmt.Sprintf(":%d", d.Line)
			}
			if d.Element != "" {
				loc += " " + d.Element
			}
			if d.New {
				loc += " (new)"
			}
			_, _ = fmt.Fprintf(out, "%s: [%s] %s\n", loc, d.Gate, d.Message)
			if d.Fix != "" {
				_, _ = fmt.Fprintf(out, "    fix: %s\n", strings.ReplaceAll(strings.TrimSpace(d.Fix), "\n", "\n    "))
			}
		}
		if m := r.Manifest; m != nil {
			_, _ = fmt.Fprintf(out, "examined %d files, not %d; %d known gaps; %d requirements await non-structural evidence\n",
				len(m.Examined), len(m.NotExamined), len(m.KnownGaps), len(m.AwaitingEvidence))
		}
		switch {
		case r.Mode == "warning-only":
			_, _ = fmt.Fprintf(out, "warning-only: %d findings; the model is not authoritative until the commit adding .wasb/ is signed\n", len(r.Diagnostics))
		case r.Pass:
			_, _ = fmt.Fprintln(out, "ok")
		}
	}
	if !r.Pass {
		return errFailed
	}
	return nil
}

func importCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "import",
		Short: "Propose a model of the repository under .wasb/model/generated and stop",
		Long: "Walk the repository, write a model of every target to " + ".wasb/model/generated/import.sysml" + ",\n" +
			"and write the coverage report. The model is not authoritative until you add a trusted key\n" +
			"(wasb trust add, wasb trust sign) and commit .wasb/ signed with it.",
		Args: cobra.NoArgs,
		RunE: func(c *cobra.Command, _ []string) error {
			root, err := repoRoot()
			if err != nil {
				return err
			}
			force, _ := c.Flags().GetBool("force")
			res, err := app.Import(c.Context(), root, force)
			if err != nil {
				return err
			}
			text := fmt.Sprintf("modeled %v\nwrote %s\nnot examined: %d files (see %s)\nnext: wasb trust add <key>; wasb trust sign; git add .wasb && git commit -S\n",
				res.Targets, strings.Join(res.Written, ", "), len(res.Manifest.NotExamined), ".wasb/coverage/import.json")
			return emit(c, res, text)
		},
	}
	cmd.Flags().Bool("force", false, "rewrite the imported model when one exists")
	return cmd
}

func generateCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "generate",
		Short: "Show, or with --write create, Go stubs for modeled functions that do not exist yet",
		Args:  cobra.NoArgs,
		RunE: func(c *cobra.Command, _ []string) error {
			root, err := repoRoot()
			if err != nil {
				return err
			}
			write, _ := c.Flags().GetBool("write")
			d, err := app.Generate(c.Context(), root, write)
			if err != nil {
				return err
			}
			return emit(c, map[string]any{"diff": d, "written": write}, d)
		},
	}
	cmd.Flags().Bool("write", false, "write the stubs")
	return cmd
}

func proposeCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "propose <name> <model-file>=<proposed-file>...",
		Short: "Record a suggested model change with its delta, constraint changes, regeneration diff and impact",
		Long: "Record a proposal in .wasb/proposals/<name>.json. It changes nothing in the model.\n" +
			"Acceptance is a normal edit plus a signed commit that moves the content into the model,\n" +
			"removes its @WASB::AgentSuggested marks and deletes the proposal.",
		Args: cobra.MinimumNArgs(2),
		RunE: func(c *cobra.Command, args []string) error {
			root, err := repoRoot()
			if err != nil {
				return err
			}
			files := map[string]string{}
			for _, a := range args[1:] {
				target, src, ok := strings.Cut(a, "=")
				if !ok {
					return fmt.Errorf("%q: want <model-file>=<proposed-file>", a)
				}
				b, err := os.ReadFile(src)
				if err != nil {
					return err
				}
				files[target] = string(b)
			}
			p, err := app.Propose(c.Context(), root, args[0], files)
			if err != nil {
				return err
			}
			text := fmt.Sprintf("%s\nconstraints changing: %d\nnewly failing: %v\nnewly passing: %v\n", p.Delta, len(p.Constraints), p.Impact.NewlyFailing, p.Impact.NewlyPassing)
			return emit(c, p, text)
		},
	}
	list := &cobra.Command{
		Use:   "list",
		Short: "List proposals",
		Args:  cobra.NoArgs,
		RunE: func(c *cobra.Command, _ []string) error {
			root, err := repoRoot()
			if err != nil {
				return err
			}
			ps, err := app.ListProposals(root)
			if err != nil {
				return err
			}
			text := ""
			for _, p := range ps {
				text += fmt.Sprintf("%s %s %s\n", p.Name, p.Status, p.Reason)
			}
			return emit(c, ps, text)
		},
	}
	reject := &cobra.Command{
		Use:   "reject <name>",
		Short: "Record that a proposal was rejected",
		Args:  cobra.ExactArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			root, err := repoRoot()
			if err != nil {
				return err
			}
			reason, _ := c.Flags().GetString("reason")
			if err := app.Reject(root, args[0], reason); err != nil {
				return err
			}
			return emit(c, map[string]string{"rejected": args[0]}, "rejected "+args[0]+"\n")
		},
	}
	reject.Flags().String("reason", "", "why")
	cmd.AddCommand(list, reject)
	return cmd
}

func statusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Summarize the model, the gates, the trust chain and proposals",
		Args:  cobra.NoArgs,
		RunE: func(c *cobra.Command, _ []string) error {
			root, err := repoRoot()
			if err != nil {
				return err
			}
			s, err := app.GetStatus(c.Context(), root)
			if err != nil {
				return err
			}
			text := fmt.Sprintf("mode %s, pass %t, failures by gate %v\n%d targets, %d anchored elements\ntrust: %d keys, pending version %t\nproposals %v\n",
				s.Mode, s.Pass, s.Diagnostics, s.Targets, s.Elements, s.TrustKeys, s.TrustPending, s.Proposals)
			return emit(c, s, text)
		},
	}
}

func coverageCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "coverage",
		Short: "Report per-file and per-element coverage and run the coverage gate",
		Args:  cobra.NoArgs,
		RunE: func(c *cobra.Command, _ []string) error {
			root, err := repoRoot()
			if err != nil {
				return err
			}
			r, err := app.Check(c.Context(), root, "coverage")
			if err != nil {
				return err
			}
			if r.Manifest == nil {
				return fmt.Errorf("%s", r.Diagnostics[0].Message)
			}
			text := ""
			for _, f := range r.Manifest.Files {
				text += fmt.Sprintf("%-60s %3d/%-3d modeled  %5.1f%% generated\n", f.File, f.Modeled, f.Targets, 100*f.Generated)
			}
			for _, d := range r.Diagnostics {
				text += fmt.Sprintf("%s: %s\n", d.Element, d.Message)
			}
			if err := emit(c, r, text); err != nil {
				return err
			}
			if !r.Pass {
				return errFailed
			}
			return nil
		},
	}
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
