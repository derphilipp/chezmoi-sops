# chezmoi-sops

Manage [sops](https://github.com/getsops/sops)-encrypted secret groups for
[chezmoi](https://github.com/twpayne/chezmoi).

chezmoi has no native sops support — [issue #3823](https://github.com/twpayne/chezmoi/issues/3823)
is open. This tool fills that gap: it keeps the readable structure that sops
gives you (only the *values* are encrypted), adds per-group access control,
and hands the merged secrets to chezmoi templates.

## Before you start: install the tool before `chezmoi init`

**`chezmoi-sops` has to be installed and on your `PATH` before you run
`chezmoi init` for the first time on a machine.**

This is not a "nice to have". The chezmoi configuration template calls the
tool while chezmoi renders it, and that happens at the very start of
`chezmoi init` — before anything else, and before any `run_` script gets a
chance to execute. If the binary is missing, `chezmoi init` fails outright
and writes no configuration at all:

```
chezmoi: template: chezmoi.toml:53:26: executing "chezmoi.toml" at
<output "chezmoi-sops" "data">: error calling output: chezmoi-sops data:
exec: "chezmoi-sops": executable file not found in $PATH
```

Note that this is *not* the same as "the secrets are unavailable". An
unavailable secret group is handled gracefully — the template renders with
empty values. A missing *binary* is fatal.

### The order on a new machine

1. Install chezmoi itself.
2. Install `chezmoi-sops` and make sure it is on the `PATH` of the shell
   that will run `chezmoi`. See [Install](#install) below.
3. Run `chezmoi init`.

A dotfiles repository can list the tool in its mise configuration, so that
every machine installs and updates it:

```toml
[tools]
chezmoi-sops = "go:github.com/derphilipp/chezmoi-sops/cmd/chezmoi-sops@latest"
```

That covers every machine *after* its first initialisation — the mise
install happens in a `run_` script, which chezmoi executes after it has
rendered the configuration. The very first `chezmoi init` on a machine
still needs the tool installed by hand, for the reason above.

Check it at any time:

```sh
chezmoi-sops doctor
```

`doctor` reports the chezmoi installation, the identity files it looked
at, and every group: whether it can be decrypted, and why not when it
cannot.

### Why it cannot install itself

chezmoi renders the configuration template *before* it runs the `run_`
scripts in the source directory. A `run_` script that installs the tool
therefore runs too late to help the first `chezmoi init`. The installation
has to be done by hand, once per machine.

This replaces the previous arrangement, which needed the `sops` binary
*and* a `chezmoi-secrets` script (a POSIX shell script plus a PowerShell
one) to be present before `chezmoi init` could read the secrets. It is now
one binary, for every platform.

## Why groups

The secrets live in a directory tree that carries the access control:

```
.secrets/
  access.yaml                   the machines and the groups
  groups/<group>/<file>         readable by the members of the group
  hosts/<host>/<file>           readable by that machine alone
```

`access.yaml` is the only place the access control is written down:

```yaml
hosts:
  laura:
    age: [age1...]
  leela:
    age: [age1...]

groups:
  common: [laura, leela]
  home: [laura]
```

The recipients of a group are **derived from its members**, so a public key
is only ever written once. Adding a machine is one edit to this file, and
forgetting one is impossible — a group cannot name a machine that does not
exist.

Because sops encrypts only the values, the key names stay readable in the
repository:

```yaml
HA_FRITZ_TOKEN: ENC[AES256_GCM,data:...,iv:...,tag:...,type:str]
database:
    host: ENC[AES256_GCM,data:...,iv:...,tag:...,type:str]
```

And because the *shape* is readable, a machine that is not a member of a
group still knows which secrets exist — it just sees empty values.
Templates therefore render everywhere instead of failing on one machine.

Adding a secret is adding a file. There is no configuration change at all.

The order of the groups in `access.yaml` is the merge order, and the first
group that holds a value wins.

## Install

With [mise](https://mise.jdx.dev):

```sh
mise install github:derphilipp/chezmoi-sops@0.2.0
```

With Go:

```sh
go install github.com/derphilipp/chezmoi-sops/cmd/chezmoi-sops@v0.2.0
```

> **A note on `@latest` with mise.** mise hides releases that are younger
> than its `minimum_release_age` setting (24 hours by default), so
> `mise install github:derphilipp/chezmoi-sops` — without a version — will
> not find a release published in the last day. Pin the version, as above,
> or use `mise install github:derphilipp/chezmoi-sops@0.2.0` to install a
> fresh release straight away. `go install ...@latest` is not affected.

Either way, verify that the shell that runs `chezmoi` can find it:

```sh
chezmoi-sops --version
```

If that fails, the `PATH` is the problem — and `chezmoi init` will fail
with the error shown above.

### Platforms

Prebuilt binaries are published for:

| Platform | Architecture |
|---|---|
| Linux | x86-64 (`amd64`) and arm64 |
| macOS | Apple silicon (`arm64`) and Intel (`amd64`) |
| Windows | x86-64 (`amd64`) |

There is no 32-bit build. The release archives are `.tar.gz` everywhere
except Windows, which gets a `.zip`, together with a `checksums.txt`.

## Use

It runs as a [chezmoi plugin](https://www.chezmoi.io/reference/plugins/): with
`chezmoi-sops` on your `PATH`, `chezmoi sops ...` runs it.

```sh
chezmoi sops groups                  # the groups, the machines, and who can read what
chezmoi sops hosts                   # the machines and their keys
chezmoi sops new work                 # create a group
chezmoi sops members work laura leela # who may read a group
chezmoi sops edit group/work          # decrypt, edit, re-encrypt
chezmoi sops edit host/laura          # the secrets of one machine
chezmoi sops delete group/work        # remove a group
chezmoi sops data                     # the merged secrets, as JSON
chezmoi sops doctor                   # what works and what does not
```

The order of the groups in the access file is the merge order, and the first
group that holds a value wins.

Every command takes `--json` for machine-readable output.

### In a chezmoi template

The call goes in the **configuration template** — the one chezmoi renders
before anything else — and nowhere else:

```toml
{{- $secrets := fromJson (output "chezmoi-sops" "data") -}}
```

Everything else is unchanged. The `data` command returns the four keys
below, and the configuration template puts them in chezmoi's `[data]`
section, which is **global**: every template in the repository can then
read `.secrets` and `.secretsEnv` without calling anything.

```toml
[data]
secrets      = {{ get $secrets "secrets" | toJson }}
secretsEnv   = {{ get $secrets "secretsEnv" | toJson }}
secretGroups = {{ get $secrets "secretGroups" | toJson }}
secretStatus = {{ get $secrets "secretStatus" | toJson }}
```

So a template that uses a secret needs **no change at all**:

```toml
{{ .secrets.HA_FRITZ_TOKEN }}
{{ get .secrets "DATABASE_PASSWORD" }}
```

| Key | What it holds |
|---|---|
| `secrets` | the merged tree: the values this machine can read, with the shapes of the groups it cannot read filling the gaps |
| `secretsEnv` | the same, flattened: `database.password` becomes `DATABASE_PASSWORD` |
| `secretGroups` | the values of each group, before they were merged |
| `secretStatus` | whether each group could be read, and why not |

### The identity

The identity comes from **chezmoi's own configuration**, so a machine is
configured in exactly one place:

```toml
encryption = "age"

[age]
    identity = "~/.config/sops/age/keys.txt"
```

The tool also accepts `--identity`, and falls back to `$SOPS_AGE_KEY_FILE`
and the usual sops locations (`~/.config/sops/age/keys.txt`,
`~/.age/key.txt`). On Windows, `%AppData%\sops\age\keys.txt` is looked at
too.

There is no separate configuration file for the tool: it is specific to
chezmoi and sops, and chezmoi's config already says everything it needs to
know.

## How it works

- The sops format is used **in-process**, through the pinned
  `github.com/getsops/sops/v3` library. No `sops` binary is needed at
  runtime — only `chezmoi-sops` itself.
- Files written by the tool are readable by the real `sops` binary, and
  files written by `sops` are readable by the tool. This is checked in CI
  against the real binary — sops is the oracle, not our own code.
- The whole-file `age` format is supported too, for payloads that are not
  structured. It has no shape: without the key there is nothing to show.
- The tool reads chezmoi's own configuration, so there is nothing to
  configure twice.

### The binary is large

About 43 MB. That is the price of the sops library: its root package
imports the key service, which pulls in the AWS, Google Cloud and Azure
key-management SDKs, even though only age is used here.

For comparison, the `sops` binary itself is about 50 MB and `chezmoi`
about 41 MB, so the tool is in the same ballpark as the tools it sits
between. Writing the sops file format by hand would avoid the SDKs, at
the cost of a reimplementation that has to track the format exactly.

## Troubleshooting

**`chezmoi init` fails with `executable file not found in $PATH`.**
The tool is not installed, or not on the `PATH` of the shell that runs
chezmoi. See [the section at the top](#before-you-start-install-the-tool-before-chezmoi-init).

**`chezmoi init` fails with `chezmoi-sops: command not found`.**
Same problem, different shell. Check `which chezmoi-sops` in the shell that
runs chezmoi.

**`chezmoi sops doctor` reports no identity.**
No age private key was found. Restore an authorised key to
`~/.config/sops/age/keys.txt` (or `~/.age/key.txt`), or point chezmoi's
`[age] identity` at it.

**A group is reported as `not-authorized`.**
This machine is not a member of that group, or the payload was not
re-encrypted after the members changed. The secrets of that group stay
unavailable here — but the templates still render, with empty values,
because the key names are readable without the key.

**`the directory groups/<name> has no entry in access.yaml`.**
A directory without an entry in the access file would be readable by
nobody or by everybody, and neither is ever meant. Add the group to
`access.yaml`, or remove the directory.

## Status

Phases 1 to 3 are done: the group management commands, the data provider
and the release engineering. See [PLAN.md](PLAN.md) for the implementation
plan and what is left.

## Licence

MIT — see [LICENSE](LICENSE).
