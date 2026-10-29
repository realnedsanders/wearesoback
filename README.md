# We Are So Back (wasb)

> the agent said “we’re so back”  
> the gate responds “this is slop”  
> the signed commit said “no.”

**wasb** is an unhinged structural backpressure harness I vibe coded after my agents kept quietly deleting NetworkPolicies and then writing a heartfelt retrospectives about how the architecture is now “more fluid”.

It keeps a SysML v2 model in `.wasb/` as the only adult in the repository.
Everything else is either generated from that model or living on borrowed time inside an anchor. 
When the agent tries to freestyle, the gates return structured diagnostics and refuse to let the loop continue until the model and the files are on speaking terms again.

## What it actually does

- One-time import that stares at your Go, zarf.yaml, Helm chart, tasks.yaml, UDS Package CR, and GitHub Actions and proposes a model. The model is not real until you sign the commit.
- Drift gate: “you changed the file and not the model.”
- Unmodeled gate: “you added a function / template / job / resource and pretended we wouldn’t notice”.
- Requirements gate: evaluates the actual constraints. Structural green does not discharge a runtime-class requirement. EvidenceClass is not optional.
- Signature gate: user-declared requirements live behind a YubiKey (or equivalent). The agent can *suggest*. It cannot *accept*.
- Coverage metrics so you can watch the generated fraction slowly evaporate and feel something.
- Explicit known gaps, so the tool doesn’t get to pretend it sees everything.

Hard stops live in a thin harness wrapper, not in “the MCP server probably has a tool for that”.
The agent gets the diagnostics.
The loop does not advance.
This is the entire product.

## Installation

1. Install

```bash
go install github.com/realnedsanders/wearesoback/src/cmd/wasb@latest
```

2. Accept that you are now the person who has to explain this name in stand-up.

## Usage (vibe)

```bash
wasb init                        # once per machine: pi won't let an agent finish while wasb check fails
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

Requirements live in `.wasb/model/user/` and need an `@WASB::EvidenceClass`.
Generated elements are typed by `WASB::UDSAllow`, `WASB::GoFunc` and friends, so a requirement can read their attributes:

```sysml
requirement def KeycloakEgress {
    @UserDeclared;
    @EvidenceClass { evidence = EvidenceClassKind::structural; }
    subject rule : UDSAllow;
    require constraint { rule.remoteNamespace == "keycloak" }
}
requirement keycloakEgress : KeycloakEgress { @UserDeclared; }
satisfy keycloakEgress by Generated::'chart/templates/uds-package.yaml#Keycloak egress';
```

Trusted keys live in `.wasb/trust.yaml`.
Any key of the previous version signs the next one, and version 1 must be signed by whoever signed the first commit touching `.wasb/`.
Lost your key?
A teammate runs `wasb trust add <your new key>` and `wasb trust sign`.

The harness is a pi (>= 1.4) extension, and `wasb init` installs it into `~/.pi/agent/extensions/` with wasb's absolute path baked in.
Re-run it after moving or upgrading wasb.
Before the agent may stop, it runs `wasb check --json --if-managed`; on failure it pastes the diagnostics back in and declines to stop.
Repositories where no commit has touched `.wasb/` are left alone. Deleting `.wasb/` doesn't count.
There is no “just this once".

## The bit

wasb does not make your agent smarter.
It makes the substrate less forgiving.

If the agent wants to change an invariant it must show the blast radius, the constraints that flip, and the regeneration diff.
You sign or you don’t.
The history remembers which suggestions you rejected.
Later turns can see the pattern.

This is as close to “accountability” as a language model is going to get without a union.

Best-practice libraries layer like agent configs: global, then user, then repo.
Specialization and redefinition handle overrides.
The signature gate still applies if you marked the result `UserDeclared`.

## Status

We are so back.  

## License

AGPL-v3

