# chezmoi-sops

Manage [sops](https://github.com/getsops/sops)-encrypted secret groups for
[chezmoi](https://github.com/twpayne/chezmoi).

chezmoi has no native sops support — [issue #3823](https://github.com/twpayne/chezmoi/issues/3823)
is open. This tool fills that gap: it keeps the readable structure that sops
gives you (only the *values* are encrypted), adds per-group access control, and
can hand the merged secrets to chezmoi templates.

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
```

## Status

Early. See [PLAN.md](PLAN.md) for the implementation plan and the phases.

## Licence

MIT — see [LICENSE](LICENSE).
