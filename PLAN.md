# chezmoi-sops — implementation plan

A Go CLI that manages **sops-encrypted secret groups** for chezmoi, and
optionally exposes them to chezmoi templates.

## The problem it solves

chezmoi has no native sops support ([issue #3823](https://github.com/twpayne/chezmoi/issues/3823)
is open). Today the only way to use sops with chezmoi is to shell out to the
`sops` binary from a template. That works, but it means:

- the encryption logic lives in Go template code inside a dotfiles repo,
- the file layout, the group model and the merge rules are reinvented per
  project,
- there is no reusable tool.

chezmoi-sops extracts that into a real program: one implementation, one
binary per platform, usable by anyone with chezmoi + sops + age.

## Design principles

1. **Byte-compatible with the sops CLI.** A file written by chezmoi-sops must
   be readable by `sops -d`, and vice versa. Verified in CI against the real
   `sops` binary.
2. **Never require a runtime dependency it can do itself.** age and sops are
   Go libraries; the tool does not shell out to `sops` unless asked to.
3. **The dotfiles repo stays authoritative for the layout.** The tool
   implements a documented convention; it does not hardcode your repo.
4. **Fail loudly, never silently.** A group that cannot be decrypted is
   reported, not skipped.

## Scope

| Phase | Deliverable | Risk |
|---|---|---|
| 0 | repo hygiene: module, toolchain, CI, README skeleton | none |
| 1 | core library + CLI (`edit`, `new`, `groups`, `delete`) | low — a port of the working shell implementation |
| 2 | `data` command: the shape-aware secret namespace for chezmoi templates | medium — moves logic out of the config template |
| 3 | release engineering (GoReleaser), docs, install instructions | low |
| 4 | dotfiles repo migration (separate repo, separate decision) | — |
| 5 | *optional* upstream PR to chezmoi | — |

Phases 0–3 make this a useful standalone tool. Phase 4 is what makes it
*yours*.

## Architecture

```
cmd/chezmoi-sops/main.go      thin main: cobra root, no logic
internal/
  cli/          cobra commands, one file per command
  groups/       the group model: discovery, recipients registry, merge, flatten
  payload/      the two payload formats behind one interface
  keyring/      age identity discovery
  editor/       the decrypt → $EDITOR → encrypt round trip
```

### Core types

```go
// payload/payload.go
type Payload interface {
    // Decrypt returns the plaintext tree.
    Decrypt(ctx context.Context, id age.Identity) (map[string]any, error)
    // Encrypt writes an encrypted payload for the given recipients.
    Encrypt(ctx context.Context, tree map[string]any, recipients []age.Recipient) ([]byte, error)
    // Shape returns the key structure with all values blanked.
    // ok is false when the format cannot expose a shape (whole-file age).
    Shape(ctx context.Context) (tree map[string]any, ok bool, err error)
    // Format name, for display.
    Name() string
}
```

Two implementations:

- `payload.SOPS` — sops YAML. `Shape` reads the file with the plain loader,
  so the values come back as the literal `ENC[AES256_GCM,…]` strings; a walk
  blanks them. This is the mechanism that lets a machine without access still
  know the *shape* of the secrets.
- `payload.Age` — whole-file age. No shape is available.

### The group model

```go
// groups/group.go
type Group struct {
    Name       string
    Recipients []string // age public keys
    Format     payload.Format
}

// groups/registry.go
type Registry struct { Groups []*Group }

// Merge combines the groups: real values first, then shapes fill the gaps.
func (r *Registry) Merge(ctx context.Context, id age.Identity) (Result, error)

type Result struct {
    Tree  map[string]any // merged, nested
    Flat  map[string]any // flattened: path joined with "_", uppercased
    Status map[string]GroupStatus
}
```

The merge order is the subtle part and must match the current implementation
exactly: **real values are merged before shapes, so a shape can never shadow a
value the machine is allowed to read.** The first group wins a conflict, and
the conflict is reported.

### Identity discovery

`keyring` resolves the age identity in this order, and the first hit wins:

1. `--identity` flag
2. `$SOPS_AGE_KEY_FILE` (sops' own convention)
3. the `age.identity` of the chezmoi config, when a source dir is known
4. `~/.chezmoi-age-identity.txt`
5. `~/.age/key.txt`
6. `~/.config/sops/age/keys.txt`

This is a superset of what chezmoi and sops each look for on their own, so
the tool works with either ecosystem's setup.

## Dependencies (verified against the module proxy)

| Module | Version | Note |
|---|---|---|
| `filippo.io/age` | v1.3.2 | the age library; stable API |
| `github.com/getsops/sops/v3` | v3.13.3 | **the module path moved** — it used to be `go.mozilla.org/sops/v3`, and that path now fails to resolve |
| `github.com/spf13/cobra` | v1.10.2 | the CLI framework sops and chezmoi both use |
| `gopkg.in/yaml.v3` | – | for the YAML shape walk |

Go 1.27 is available through mise. The module proxy is reachable.

## Decisions to make before writing code

### D1 — Licence (blocking for publishing)

The repo currently has **GPL-3.0** (GitHub's generator). For a tool meant to
be used by others, that is a strong copyleft: anyone redistributing a binary
must offer the source, and the licence is viral. Compare: sops is MPL-2.0,
age is BSD-3-Clause, chezmoi is MIT.

Options: keep GPL-3.0, or switch to MIT / Apache-2.0 / BSD-3. Changing it
now is free; changing it after people have started using it is not.

### D2 — How to handle the sops format

The sops root package says, verbatim:

> This package should not be used directly. […] We do not guarantee API
> stability for any package other than `github.com/getsops/sops/v3/decrypt`.

Three ways forward:

| | Approach | Upside | Downside |
|---|---|---|---|
| **a** | use the library, pin `v3.13.3`, test against the CLI in CI | least code | breaks on a sops release; CI catches it |
| **b** | shell out to the `sops` binary | byte-identical by construction | needs sops installed; not self-contained |
| **c** | implement the format ourselves with `filippo.io/age` + AES-GCM | fully self-contained, no unstable API | ~400 lines of crypto-format code; must match the MAC and AAD rules exactly |

**Recommendation: (a)**, with a CI job that round-trips against the real
`sops` binary. A sops release that changes the API breaks CI, not users.
Note that only `decrypt` is API-stable, and it covers decryption only —
encryption would still need (a), (b) or (c).

**Spike result (verified against sops v3.13.3):** option (a) works — but
the API is genuinely awkward, and it moved in v3.13. The working shape is:

```go
x25519 := ids[0].(*age.X25519Identity)        // filippo.io/age.Identity is an interface
mk, _ := sopsage.MasterKeyFromRecipient(x25519.Recipient().String())
parsed := sopsage.ParsedIdentities{}
parsed.Import(x25519.String())
parsed.ApplyToMasterKey(mk)                     // age.MasterKey.Identity is deprecated

tree := sops.Tree{
    Branches: branches,
    Metadata: sops.Metadata{KeyGroups: []sops.KeyGroup{{mk}}, Version: "3.13.3"},
}
tree.Metadata.LastModified = time.Now().UTC().Truncate(time.Second)
dataKey, _ := tree.GenerateDataKey()
mac, _ := tree.Encrypt(dataKey, aes.NewCipher())   // returns the MAC - do not discard it
tree.Metadata.MessageAuthenticationCode, _ = aes.NewCipher().Encrypt(
    mac, dataKey, tree.Metadata.LastModified.Format(time.RFC3339))
out, _ := store.EmitEncryptedFile(tree)
```

The gotchas that cost the most time in the spike — all of which become unit
tests:

1. `Tree.Encrypt` **returns** the MAC. Ignore it and the file has no MAC, and
   the sops CLI rejects it with *"MAC mismatch. File has no MAC"*.
2. The MAC's additional data is `LastModified` in RFC3339, so the timestamp
   must be set **before** the MAC is computed.
3. `sops.Tree` has no `Keys` field; the master keys live in
   `Metadata.KeyGroups`.
4. `age.MasterKey.Identity` is deprecated; the private key is injected via
   `age.ParsedIdentities.ApplyToMasterKey`.
5. `filippo.io/age.Identity` is an interface — `Recipient()` and `String()`
   need a type assertion to `*age.X25519Identity`.
6. `store.LoadPlainFile` takes `[]byte`, not a path.

**Verified end to end:** a file written by the Go library is decrypted
correctly by the real `sops` CLI, and a file written by the CLI is decrypted
by the stable Go helper. Both directions work.

One more finding: the "stable" `decrypt` helper still pulls in the CLI's
dependency tree (`blang/semver`, `urfave/cli`) — heavier than the name
suggests.

**This is the concrete argument for option (c).** The stable surface is tiny
(`decrypt` only), and the encryption path is exactly where the API is awkward
and unstable. Implementing the format ourselves against `filippo.io/age` —
whose API *is* stable — removes the dependency on an API sops explicitly
declines to guarantee, at the cost of reimplementing the data-key wrapping and
the MAC. The compatibility matrix in CI is the safety net for either option.

### D3 — Language for messages

The current shell implementation speaks German. A public tool should speak
English. Recommend English, and keep the German output only in the dotfiles
wrapper if that matters to you.

## Task breakdown

### Phase 0 — repo hygiene

- [ ] `go.mod` — module `github.com/derphilipp/chezmoi-sops`, Go 1.27
- [ ] `.gitignore`, `.editorconfig`
- [ ] `README.md` — what it is, install, the group layout, a worked example
- [ ] `Makefile` — `build`, `test`, `lint`, `snapshot`
- [ ] `.github/workflows/ci.yml` — build, `go test ./...`, `go vet`, golangci-lint
- [ ] `LICENSE` — per D1
- [ ] `CONTRIBUTING.md`

### Phase 1 — core + CLI

- [ ] **T1.1** `internal/payload` — interface, plus `Shape` for sops (the walk that blanks `ENC[…]` values)
- [ ] **T1.2** `internal/payload` — sops encrypt/decrypt against the library (per D2)
- [ ] **T1.3** `internal/payload` — whole-file age format
- [ ] **T1.4** `internal/keyring` — identity discovery
- [ ] **T1.5** `internal/groups` — discovery of `*.recipients.txt`, the recipients registry (`# hostname` → key), the key→host reverse lookup
- [ ] **T1.6** `internal/groups` — merge and flatten, matching the current semantics exactly
- [ ] **T1.7** `internal/editor` — decrypt → temp file (0600) → `$EDITOR` → re-encrypt, including the empty-payload rule (`{}`) and the "undecryptable → refuse" rule
- [ ] **T1.8** `internal/cli` — cobra root + `edit`, `new`, `groups`, `delete`
- [ ] **T1.9** `internal/cli` — `--json` output for every command (scriptability)
- [ ] **T1.10** golden tests — every command's output, and the payload files themselves

Exit criteria: the tool replaces the shell implementation in the dotfiles repo
with **no behavioural change**. The existing sh script is the reference
implementation and its quirks are the spec.

### Phase 2 — data provider

- [ ] **T2.1** `chezmoi sops data --format json` — emits the merged tree, the flat
      map and the per-group status
- [ ] **T2.2** the dotfiles config template switches to
      `fromJson (output "chezmoi-sops" "data" --format json)`
- [ ] **T2.3** the template's ~150 lines of jq/merge logic is deleted

Note the coupling: the tool must exist before the first `chezmoi init` —
the same bootstrap situation sops is in today. The graceful degradation
("group unavailable → empty values") must be preserved exactly.

### Phase 3 — release engineering

- [ ] `.goreleaser.yaml` — linux/darwin/windows × amd64/arm64, tarballs, checksums
- [ ] `.github/workflows/release.yml` — on tag → goreleaser → GitHub release
- [ ] install docs: `mise install github:derphilipp/chezmoi-sops`, plus
      `go install` and a package-manager note
- [ ] `chezmoi sops doctor` — report the identity in use, the groups found,
      which ones decrypt, and why not the others

## Testing strategy

**Unit** — merge/flatten semantics, shape extraction, identity discovery,
recipient parsing (including host names with spaces).

**Compatibility** (the important one) — a CI matrix that, for each group:
1. encrypts with chezmoi-sops → decrypts with the `sops` CLI → equal
2. encrypts with the `sops` CLI → decrypts with chezmoi-sops → equal
3. checks the shape of an undecryptable file equals the shape of a decryptable
   one, with values blanked

**Golden** — the payload files and command output, byte for byte, so a change
in the sops library cannot silently alter the on-disk format.

**Integration** — a temporary source dir with a synthetic group set; run
every command; assert the resulting files.

**Migration** — run the new tool against the existing dotfiles repo and diff
the payloads. They should be unchanged apart from the sops metadata
timestamp.

## Risks

| Risk | Impact | Mitigation |
|---|---|---|
| sops library API breaks | build failure on a sops release | pin the version; CI round-trips against the CLI; the `decrypt` package is stable for the decrypt path |
| Our output drifts from the CLI's | files unreadable by `sops -d` | the compatibility matrix in CI, and the `sops` CLI in CI as the oracle |
| The merge semantics change | secrets silently empty or shadowed | golden tests derived from the current sh implementation, which is the spec |
| Scope creep into a chezmoi fork | never finishes | the tool is a plugin and a data provider, never a chezmoi replacement |
| The dotfiles repo depends on the tool | secrets break if the tool is broken | phase 4 keeps the config template self-contained unless the data provider is proven |

## Open questions

1. **Licence** (D1) — keep GPL-3.0, or switch to MIT/Apache-2.0?
2. **sops API approach** (D2) — library, subprocess, or own implementation?
3. **Message language** (D3) — English?
4. Should the tool also support `age`-format groups with a shape, e.g. by
   storing the shape in a sidecar file? (Currently the age format has no
   shape, so an unreadable age group contributes nothing.)
5. Should `chezmoi sops data` become the only way the dotfiles template gets
   secrets, or stay optional?
