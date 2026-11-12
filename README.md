# chezmoi-sops

Manage [sops](https://github.com/getsops/sops)-encrypted secret groups for
[chezmoi](https://github.com/twpayne/chezmoi).

chezmoi has no native sops support — [issue #3823](https://github.com/twpayne/chezmoi/issues/3823)
is open. This tool fills that gap: it keeps the readable structure that sops
gives you (only the *values* are encrypted), adds per-group access control,
and hands the merged secrets to chezmoi templates.

## Why groups

A **group** is a set of recipients plus a payload:

```
.secrets/
  default.recipients.txt   the age public keys allowed to decrypt the group
  default.sops.yaml        the payload, sops encrypted
```

Because sops encrypts only the values, the key names stay readable in the
repository:

```yaml
HA_FRITZ_TOKEN: ENC[AES256_GCM,data:...,iv:...,tag:...,type:str]
database:
    host: ENC[AES256_GCM,data:...,iv:...,tag:...,type:str]
```

And because the *shape* is readable, a machine that is not a recipient of a
group still knows which secrets exist — it just sees empty values. Templates
therefore render everywhere instead of failing on one machine.

Each group has its own recipient list, so a machine can read the groups it
is allowed to read and only those.

## Install

```sh
mise install github:derphilipp/chezmoi-sops
```

or

```sh
go install github.com/derphilipp/chezmoi-sops/cmd/chezmoi-sops@latest
```

## Use

It runs as a [chezmoi plugin](https://www.chezmoi.io/reference/plugins/): with
`chezmoi-sops` on your `PATH`, `chezmoi sops ...` runs it.

```sh
chezmoi sops groups              # who is in which group
chezmoi sops new work age1...     # create a group
chezmoi sops edit private         # decrypt, edit, re-encrypt
chezmoi sops delete work          # remove a group
chezmoi sops data                 # the merged secrets, as JSON
```

### In a chezmoi template

```toml
{{- $secrets := fromJson (output "chezmoi-sops" "data" --quiet) -}}

{{ $secrets.secrets.HA_FRITZ_TOKEN }}
{{ get $secrets.secrets "DATABASE_PASSWORD" }}
```

The `data` command emits:

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
`~/.age/key.txt`).

There is no separate configuration file for the tool: it is specific to
chezmoi and sops, and chezmoi's config already says everything it needs to
know.

## How it works

- The sops format is used **in-process**, through the pinned
  `github.com/getsops/sops/v3` library. No `sops` binary is needed at
  runtime.
- Files written by the tool are readable by the real `sops` binary, and
  files written by `sops` are readable by the tool. This is checked in CI
  against the real binary — sops is the oracle, not our own code.
- The whole-file `age` format is supported too, for payloads that are not
  structured. It has no shape: without the key there is nothing to show.

### The binary is large

About 43 MB. That is the price of the sops library: its root package
imports the key service, which pulls in the AWS, Google Cloud and Azure
key-management SDKs, even though only age is used here.

For comparison, the `sops` binary itself is about 50 MB and `chezmoi`
about 41 MB, so the tool is in the same ballpark as the tools it sits
between. Writing the sops file format by hand would avoid the SDKs, at
the cost of a reimplementation that has to track the format exactly.

## Status

Phases 1 and 2 are done: the group management commands and the data
provider. See [PLAN.md](PLAN.md) for the implementation plan and what is
left.

## Licence

MIT — see [LICENSE](LICENSE).
