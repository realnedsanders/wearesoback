package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime/debug"
	"slices"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/spf13/cobra"

	"github.com/realnedsanders/wearesoback/src/internal/app"
	"github.com/realnedsanders/wearesoback/src/internal/model"
)

func mcpCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "mcp",
		Short: "Serve wasb's operations as MCP tools over stdio",
		Long:  "Serve wasb's operations as MCP tools over stdio. The server enforces nothing by itself;\nthe harness that runs wasb check before the agent may finish does.",
		Args:  cobra.NoArgs,
		RunE: func(c *cobra.Command, _ []string) error {
			root, err := repoRoot()
			if err != nil {
				return err
			}
			version := "dev"
			if info, ok := debug.ReadBuildInfo(); ok && info.Main.Version != "" {
				version = info.Main.Version
			}
			s := mcp.NewServer(&mcp.Implementation{Name: "wasb", Version: version}, nil)
			addTools(s, root)
			return s.Run(c.Context(), &mcp.StdioTransport{})
		},
	}
}

type (
	none    struct{}
	checkIn struct {
		Gate string `json:"gate,omitempty" jsonschema:"one gate: drift, unmodeled, requirements, signature or coverage; empty runs all"`
	}
	generateIn struct {
		Write bool `json:"write,omitempty" jsonschema:"write the stubs instead of only returning their diff"`
	}
	generateOut struct {
		Diff string `json:"diff"`
	}
	proposeIn struct {
		Name  string            `json:"name" jsonschema:"proposal name: letters, digits, '.', '_' and '-'"`
		Files map[string]string `json:"files" jsonschema:"proposed full contents of model files, by repo-relative path under .wasb/model"`
	}
	proposalsOut struct {
		Proposals []app.Proposal `json:"proposals"`
	}
	evaluateIn struct {
		Expression string `json:"expression" jsonschema:"a SysML expression, such as Generated::'app#New'::signature"`
	}
	evaluateOut struct {
		Value string `json:"value" jsonschema:"the value, JSON-encoded"`
	}
	elementsOut struct {
		Elements     []model.Element     `json:"elements"`
		Requirements []model.Requirement `json:"requirements"`
	}
	editIn struct {
		Path    string `json:"path" jsonschema:"model file under .wasb/model/generated"`
		Content string `json:"content" jsonschema:"its full new content"`
	}
)

func addTools(s *mcp.Server, root string) {
	mcp.AddTool(s, &mcp.Tool{Name: "check", Description: "Run wasb's gates. The harness will not let you finish while this fails."},
		func(ctx context.Context, _ *mcp.CallToolRequest, in checkIn) (*mcp.CallToolResult, *app.Report, error) {
			gates := app.Gates
			if in.Gate != "" {
				if !slices.Contains(app.Gates, in.Gate) {
					return nil, nil, fmt.Errorf("unknown gate %q", in.Gate)
				}
				gates = []string{in.Gate}
			}
			r, err := app.Check(ctx, root, gates...)
			return nil, r, err
		})
	mcp.AddTool(s, &mcp.Tool{Name: "status", Description: "Summarize the model, the gates, the trust chain and proposals."},
		func(ctx context.Context, _ *mcp.CallToolRequest, _ none) (*mcp.CallToolResult, *app.Status, error) {
			st, err := app.GetStatus(ctx, root)
			return nil, st, err
		})
	mcp.AddTool(s, &mcp.Tool{Name: "coverage", Description: "Per-file and per-element coverage, known gaps, and what was not examined."},
		func(ctx context.Context, _ *mcp.CallToolRequest, _ none) (*mcp.CallToolResult, *app.Report, error) {
			r, err := app.Check(ctx, root, "coverage")
			return nil, r, err
		})
	mcp.AddTool(s, &mcp.Tool{Name: "import", Description: "One-time: propose a model of the repository under .wasb/model/generated. Refuses when a model exists."},
		func(ctx context.Context, _ *mcp.CallToolRequest, _ none) (*mcp.CallToolResult, *app.ImportResult, error) {
			res, err := app.Import(ctx, root, false)
			return nil, res, err
		})
	mcp.AddTool(s, &mcp.Tool{Name: "generate", Description: "Go stubs for modeled functions that do not exist yet: add the model element first, then generate."},
		func(ctx context.Context, _ *mcp.CallToolRequest, in generateIn) (*mcp.CallToolResult, generateOut, error) {
			d, err := app.Generate(ctx, root, in.Write)
			return nil, generateOut{d}, err
		})
	mcp.AddTool(s, &mcp.Tool{Name: "propose", Description: "Suggest a model change, such as to user requirements, which you cannot accept yourself. Records its delta, the constraints whose status changes, the regeneration diff and the impact."},
		func(ctx context.Context, _ *mcp.CallToolRequest, in proposeIn) (*mcp.CallToolResult, *app.Proposal, error) {
			p, err := app.Propose(ctx, root, in.Name, in.Files)
			return nil, p, err
		})
	mcp.AddTool(s, &mcp.Tool{Name: "proposals", Description: "List proposals, including rejected ones and why they were rejected."},
		func(ctx context.Context, _ *mcp.CallToolRequest, _ none) (*mcp.CallToolResult, proposalsOut, error) {
			ps, err := app.ListProposals(root)
			return nil, proposalsOut{ps}, err
		})
	mcp.AddTool(s, &mcp.Tool{Name: "model_evaluate", Description: "Evaluate a SysML expression against the model with OpenSysML."},
		func(ctx context.Context, _ *mcp.CallToolRequest, in evaluateIn) (*mcp.CallToolResult, evaluateOut, error) {
			m, err := app.LoadModel(ctx, root, nil)
			if err != nil {
				return nil, evaluateOut{}, err
			}
			defer m.Close()
			v, err := m.Evaluate(ctx, in.Expression)
			if err != nil {
				return nil, evaluateOut{}, err
			}
			b, err := json.Marshal(v)
			return nil, evaluateOut{string(b)}, err
		})
	mcp.AddTool(s, &mcp.Tool{Name: "model_elements", Description: "Every model element carrying wasb metadata, and every requirement with its evidence class."},
		func(ctx context.Context, _ *mcp.CallToolRequest, _ none) (*mcp.CallToolResult, elementsOut, error) {
			m, err := app.LoadModel(ctx, root, nil)
			if err != nil {
				return nil, elementsOut{}, err
			}
			defer m.Close()
			return nil, elementsOut{m.Elements, m.Requirements}, nil
		})
	mcp.AddTool(s, &mcp.Tool{Name: "model_edit", Description: "Replace a model file under .wasb/model/generated. Refused unless the whole model still parses. User requirements change only through propose."},
		func(ctx context.Context, _ *mcp.CallToolRequest, in editIn) (*mcp.CallToolResult, none, error) {
			p := filepath.ToSlash(filepath.Clean(in.Path))
			if !strings.HasPrefix(p, model.Dir+"/generated/") || !strings.HasSuffix(p, ".sysml") {
				return nil, none{}, fmt.Errorf("%s is not a model file under %s/generated", in.Path, model.Dir)
			}
			m, err := app.LoadModel(ctx, root, map[string]string{p: in.Content})
			if err != nil {
				return nil, none{}, err
			}
			m.Close()
			if err := os.MkdirAll(filepath.Dir(filepath.Join(root, p)), 0o755); err != nil {
				return nil, none{}, err
			}
			return nil, none{}, os.WriteFile(filepath.Join(root, p), []byte(in.Content), 0o644)
		})
}
