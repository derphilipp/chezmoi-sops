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

## The chezmoi integration — what is actually possible

This section answers the question that drove the design: **can the tool
replace chezmoi's use of `age` entirely, so that chezmoi itself does the
encryption?**

The answer is **yes, with one important limitation**, and the limitation is
worth stating precisely because it shapes the whole architecture.

### What chezmoi offers as extension points

Verified against chezmoi v2.73.3 (`internal/cmd/config.go`,
`internal/chezmoi/ageencryption.go`):

| Extension point | What it does | Usable here? |
|---|---|---|
| `encryption = "age"` | selects the encryption scheme | **fixed enum** — `age`, `gpg`, `transparent`. There is no custom-scheme hook. |
| `[age] command` | the binary chezmoi shells out to for `age` | **yes** — this is the hook |
| `[age] args` | extra arguments for that command | yes |
| `[age] identity` / `identities` | paths to the age private key(s) | yes — this is the identity source |
| `[age] recipient` / `recipients` / `recipientsFile` | the age public key(s) | yes — but **one global list**, not per group |
| `encrypted_` source attribute | marks a source file as encrypted | yes — the file-level mechanism |
| `age.suffix` | suffix for encrypted files, default `.age` | yes |

`[age] command` is the whole story. chezmoi does:

```go
cmd := exec.Command(e.Command, append(e.decryptArgs(), e.Args...)...)
cmd.Stdin = bytes.NewReader(ciphertext)
```

with `decryptArgs()` = `--decrypt --identity <path>` and `encryptArgs()` =
`--armor --encrypt --recipient <key>` / `--recipients-file <path>`.

So chezmoi treats the age command as a **stream filter**: ciphertext on stdin,
plaintext on stdout. Any binary honouring that contract works.

### The limitation: `age.command` is a *file* filter, not a *group* filter

This is the crux, and it is why the tool has two surfaces rather than one.

chezmoi's `encrypted_` attribute encrypts **one file at a time** into **one
opaque blob**. There is no per-group recipient list, no readable key names,
no shape. If the machine cannot decrypt, chezmoi's only options are "error
out" or "leave the file out".

The group model needs all three of:

1. **per-group recipient lists** — `[age] recipientsFile` is a single global
   list, so it cannot express "the `home` group is readable by two machines
   and the `work` group by one",
2. **readable key names** — the point of the sops format: `HA_FRITZ_TOKEN`
   stays visible in the repository even when its value is encrypted,
3. **graceful degradation** — a machine outside a group still renders the
   template with empty values instead of failing.

None of that fits through `age.command`, because that hook encrypts a whole
file into a blob. A blob has no shape.

### The design that follows

**The tool does the crypto; chezmoi keeps doing chezmoi.**

```
                chezmoi's own config (chezmoi.toml)
                    [age] identity / recipientsFile
                              │
                              ▼
   ┌──────────────────────────────────────────────────────┐
   │  chezmoi-sops                                        │
   │                                                      │
   │   surface A: group management  (chezmoi sops edit …) │
   │     .secrets/<group>.recipients.txt                  │
   │     .secrets/<group>.sops.yaml                       │
   │                                                      │
   │   surface B: data provider (chezmoi sops data)       │
   │     merged, shape-aware tree for templates           │
   └──────────────────────────────────────────────────────┘
```

- The tool reads chezmoi's **own** config for the identity and the default
  recipients — one source of truth, no second config file. `chezmoi data
  --format json` exposes `.chezmoi.config.age` and `.chezmoi.sourceDir`
  for exactly this, so the tool never parses TOML itself.
- The **identity** stays chezmoi's: `[age] identity` says which key this
  machine holds. The tool honours it.
- The **recipients** stay per group: the tool owns
  `.secrets/<group>.recipients.txt`, because chezmoi's
  `[age] recipientsFile` cannot express per-group access.
- `chezmoi sops data` is what the template calls, replacing the ~150 lines of
  Go template + jq that do it today.

### Could the tool also be `age.command`?

Technically yes — it could implement `--decrypt`/`--encrypt` and be set as
`age.command = "chezmoi-sops"`. But then chezmoi's `encrypted_` files would
be sops-format blobs, and:

- the *shape* is still lost (a blob has no key names),
- per-group recipients are still impossible (chezmoi passes one global list),
- and the tool would have to be a **second** encryption format alongside the
  group format, doubling the surface for no gain.

So: **not recommended.** The group format is the better model, and the tool
sits beside chezmoi's encryption rather than inside it.

What *is* recommended: **chezmoi's `[age]` section is left alone** and used as
the identity source. The tool does not replace chezmoi's encryption; it
provides the richer, group-aware alternative.

## Architecture

```
cmd/chezmoi-sops/main.go      thin main: cobra root, no logic
internal/
  cli/          cobra commands, one file per command
  access/       the access file: the machines and the groups
  groups/       the layout: discovery, the merge, the flattening
  payload/      the two payload formats behind one interface
  keyring/      age identity discovery
  editor/       the decrypt → $EDITOR → encrypt round trip
  chezmoi/      the chezmoi configuration the tool works with
```

## The layout of the secrets

```
.secrets/
  access.yaml                   the machines and the groups
  groups/<group>/<file>        the payloads of a group
  hosts/<host>/<file>          the payloads of one machine
```

```yaml
# .secrets/access.yaml
hosts:
  laura:
    age: [age1...]
  leela:
    age: [age1...]

groups:
  common: [laura, leela]
  home: [laura]
```

The rules:

- **The recipients of a group are derived from its members.** A key is only
  ever written once, in the hosts section.
- **The directory tree carries the access.** A file in `groups/<group>/` is
  readable by the members of that group; a file in `hosts/<host>/` is
  readable by that machine alone. Adding a secret is adding a file, with no
  configuration change at all.
- **The order of the groups in the access file is the merge order.** The
  first group that holds a value wins, and the conflict is reported. The
  file is read as an ordered document so the order is the order of the file,
  not the order of a map.
- **A group contributes its shape when it cannot be read**, so a template
  renders empty values instead of failing. A host contributes no shape: its
  secrets are for that machine alone, so their names belong to it alone.
- **A directory without an entry in the access file is an error.** It would
  either be readable by nobody or by everybody, and neither is ever meant.
- **Every key belongs to a named machine.** A group cannot list a host that
  does not exist, so a key cannot be left behind without an owner.
- **The shared group is called `common`**, not `default`. The old `default`
  group did two jobs: it was the recipient registry as well as a group. It
  also sorts first, which keeps the merge order the same.

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

### D1 — Licence — **DECIDED: MIT**

Done. `LICENSE` was GPL-3.0 (GitHub's generator) and is now MIT.

For reference: sops is MPL-2.0, age is BSD-3-Clause, chezmoi is MIT — so MIT
puts the tool in the same licence family as the tools it sits between.

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

### D2 — How to handle the sops format — **DECIDED: (a), the pinned library, in-process**

Option (b) is out: it would put a `sops` binary on every machine, which is
exactly the "another tool on board" this project is trying to avoid. Option
(c) is out: reimplementing the format is reimplementing the wheel.

So the tool uses `github.com/getsops/sops/v3` v3.13.3 as a library, pinned, and
does the crypto in-process. The library's API stability is a non-issue in
practice: the version is pinned in `go.mod`, and CI round-trips against the
real `sops` binary as the oracle, so a breaking upstream release breaks *CI*,
not users.

### D3 — Language for messages — **DECIDED: English**

All messages, help text and documentation are in English. The shell
implementation in the dotfiles repo spoke German; that goes away with it.

## Task breakdown

### Phase 0 — repo hygiene — **DONE**

- [x] `go.mod` — module `github.com/derphilipp/chezmoi-sops`, Go 1.27
- [x] `.gitignore`
- [x] `README.md` — what it is, install, the group layout, a worked example
- [x] `Makefile` — `build`, `test`, `lint`, `install`
- [x] `.github/workflows/ci.yml` — build, `go test -race ./...`, `go vet`, gofmt
- [x] `LICENSE` — MIT, per D1
- [ ] `CONTRIBUTING.md`
- [ ] `.editorconfig`

### Phase 1 — core + CLI — **DONE**

- [x] **T1.1** `internal/payload` — the interface, plus `Shape` for sops (the walk that blanks `ENC[…]` values)
- [x] **T1.2** `internal/payload` — sops encrypt/decrypt against the library (per D2)
- [x] **T1.3** `internal/payload` — whole-file age format
- [x] **T1.4** `internal/keyring` — identity discovery
- [x] **T1.5** `internal/groups` — discovery of `*.recipients.txt`, the recipients registry (`# hostname` → key), the key→host reverse lookup
- [x] **T1.6** `internal/groups` — merge and flatten, matching the current semantics exactly
- [x] **T1.7** `internal/editor` — decrypt → temp file (0600) → `$EDITOR` → re-encrypt, including the empty-payload rule (`{}`) and the "undecryptable → refuse" rule
- [x] **T1.8** `internal/cli` — cobra root + `edit`, `new`, `groups`, `delete`, `data`
- [x] **T1.9** `internal/chezmoi` — read chezmoi's own configuration, so there is no second config file
- [ ] **T1.10** `--json` output for every command (scriptability)
- [x] **T1.11** tests — the merge semantics, the group discovery, the host registry, and the sops compatibility with the real `sops` binary

Exit criteria: the tool replaces the shell implementation in the dotfiles repo
with **no behavioural change**. The existing sh script is the reference
implementation and its quirks are the spec.

**Verified:** `chezmoi sops data` produces exactly what the current template
produces — the merged tree, the flat map, the per-group values and the
per-group status all match, byte for byte.

### Phase 2 — data provider — **DONE (the tool side)**

- [x] **T2.1** `chezmoi sops data --format json` — emits the merged tree, the flat
      map, the per-group values and the per-group status
- [ ] **T2.2** the dotfiles config template switches to
      `fromJson (output "chezmoi-sops" "data" --format json)`
- [ ] **T2.3** the template's ~150 lines of jq/merge logic is deleted

Note the coupling: the tool must exist before the first `chezmoi init` —
the same bootstrap situation sops is in today. The graceful degradation
("group unavailable → empty values") must be preserved exactly.

T2.2 and T2.3 belong to the dotfiles repo, which is a separate decision
(Phase 4).

### Phase 3 — release engineering — **DONE**

- [x] `.goreleaser.yaml` — linux/darwin/windows × amd64/arm64, tarballs, checksums
- [x] `.github/workflows/release.yml` — on tag → goreleaser → GitHub release
- [x] install docs: `mise install github:derphilipp/chezmoi-sops`, plus
      `go install` and a package-manager note
- [x] `chezmoi sops doctor` — report the identity in use, the groups found,
      which ones decrypt, and why not the others
- [x] `chezmoi sops <command> --json` — machine-readable output

The binary is about 43 MB. That is the price of the sops library: its root
package imports the key service, which pulls in the AWS, Google Cloud and
Azure key-management SDKs even though only age is used here. For
comparison, the `sops` binary itself is about 50 MB and `chezmoi` about
41 MB.

## A gotcha worth knowing: `chezmoi init` writes to the default config

`chezmoi init` writes the rendered configuration to the *default* config
path, even when `--source` points somewhere else. A test that runs
`chezmoi init --source /tmp/test` therefore overwrites
`~/.config/chezmoi/chezmoi.toml` with the test's configuration.

The isolation flag is `--config-path`, and it belongs to `init`:

```sh
chezmoi --source /tmp/test init --config-path /tmp/test/chezmoi.toml
chezmoi --source /tmp/test --config /tmp/test/chezmoi.toml apply
```

This cost an afternoon of debugging a "mysterious" mismatch between the
tool and chezmoi. The tool itself is not affected — it reads
`CHEZMOI_SOURCE_DIR`, which chezmoi sets for the invocation it belongs to.

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

1. **Name — recommended: `chezmoi-sops`.** It is what the code uses now, and
   the three names are tied together: the module path
   `github.com/derphilipp/chezmoi-sops`, the binary `chezmoi-sops`, and the
   plugin command `chezmoi sops` (chezmoi looks for `chezmoi-<command>` on
   the PATH, so the command name *is* the binary name).

   `chezmoi sops` does not clash with any builtin chezmoi command — the
   encryption commands are `age`, `age-keygen`, `decrypt`, `edit-encrypted`
   and `encrypt`, and the only secret-related one is `secret` (the keyring),
   which is why `chezmoi-secrets` would be a bad name.

   The alternatives are `chezmoi-groups` (describes the group model, but
   says nothing about the sops encryption) and `chezmoi-keys` (too vague,
   and "keys" suggests key material rather than secret groups).

   The name only has to be settled before the first release, because it is
   baked into the module path, the binary name and the command.
2. Should the tool also support `age`-format groups with a shape, e.g. by
   storing the shape in a sidecar file? (Currently the age format has no
   shape, so an unreadable age group contributes nothing.)
3. Should `chezmoi sops data` become the only way the dotfiles template gets
   secrets, or stay optional?
