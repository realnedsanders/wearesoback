# We Are So Back (wasb)

**wasb** is what happens when you get tired of your agents treating your instructions like optional lore.

It keeps a SysML v2 model in `.wasb/` and demands the rest of the repo to explain itself.
When the agents try to pretend like they didn't know not to delete your NetworkPolicies (for the hundredth time), the gates return structured diagnostics and refuse to let the loop continue.

## What it does

- Import: write fanfic about your repo.
- Drift gate: "forgot to update the 978 docs pages that reference this one line of code".
- Unmodeled gate: "added a function / template / job / resource and pretended we wouldn't notice (we didn't)".
- Requirements gate: "did the opposite of what you asked it to do 3 seconds ago".
- Signature gate: "tried to larp as you approving itself".
- Coverage metrics: shows the futility of your efforts in real time.

## Installation

1. Install

```bash
go install github.com/realnedsanders/wearesoback/src/cmd/wasb@latest
wasb init
```

2. Accept that you are now the person who has to explain this name in standup.

## Usage (vibe)

```bash
wasb import                      # propose the model; nothing is authoritative yet
wasb trust add ~/.ssh/id_ed25519.pub   # or a GPG key id
wasb trust sign                  # uses git's gpg.format and user.signingkey
git add .wasb && git commit -S   # sign it, or live in warning-only mode forever

wasb check                       # all gates; --json if you ask nicely
wasb check drift                 # also: unmodeled, requirements, signature, coverage
wasb generate --write            # Go stubs for functions the model has and the code doesn't
wasb propose tighten .wasb/model/user/requirements.sysml=proposed.sysml
                                 # a suggestion nobody is allowed to merge without signing
wasb propose reject tighten --reason "no"
wasb status
wasb coverage
wasb mcp                         # the same operations as MCP tools, minus the teeth
```

Trusted keys live in `.wasb/trust.yaml`.
Any key of the previous version signs the next one, and version 1 must be signed by whoever signed the first commit touching `.wasb/`.
Lost your key?
A teammate runs `wasb trust add <your new key>` and `wasb trust sign`.

The gates are enforced by a pi (>= 1.4) extension.
Before the agent may stop, it runs `wasb check --json`; on failure it pastes the diagnostics back in and declines to stop.
There is no "just this once".

## The bit

wasb works like [structural backpressure](https://reubenbrooks.dev/blog/structural-backpressure-beats-smarter-agents/).

If the agent wants to change an invariant it must show the blast radius, the constraints that flip, and the regeneration diff.
You sign or you don't.
The history remembers which suggestions you rejected.
Later turns can see the pattern.

Best-practice libraries layer like agent configs: global, then user, then repo.
Specialization and redefinition handle overrides.

## Status

We are so back.  

## License

AGPL-v3

