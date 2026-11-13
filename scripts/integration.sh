#!/usr/bin/env bash
# The whole thing, end to end: chezmoi runs the tool as a plugin, the tool
# decrypts the groups, and the secrets end up in the rendered configuration.
#
# It runs against a temporary chezmoi installation, so it changes nothing.

set -euo pipefail

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

SOURCE="$WORK/source"
DEST="$WORK/dest"
HOME_DIR="$WORK/home"
SCRIPT_DIR=$(cd -- "$(dirname -- "$0")" && pwd)

mkdir -p "$SOURCE/.secrets/groups/common" "$DEST" "$HOME_DIR"

# An age identity for this machine, and one for a machine that is not a
# recipient.
age-keygen -o "$HOME_DIR/key.txt" >/dev/null 2>&1
RECIPIENT=$(age-keygen -y "$HOME_DIR/key.txt")
age-keygen -o "$WORK/other.txt" >/dev/null 2>&1
OTHER_RECIPIENT=$(age-keygen -y "$WORK/other.txt")

# The access file: one machine, one group.
cat > "$SOURCE/.secrets/access.yaml" <<EOF
hosts:
  testmachine:
    age:
      - $RECIPIENT
groups:
  common:
    - testmachine
EOF

# The tool creates the payload, the way a user would.
chezmoi-sops --source-dir "$SOURCE" --identity "$HOME_DIR/key.txt" \
    --editor "$SCRIPT_DIR/fake-editor.sh" group edit common >/dev/null

# The payload must be encrypted, and the key name must still be readable.
if grep -q "the-secret-value" "$SOURCE/.secrets/groups/common/common.sops.yaml"; then
    echo "FAIL: the secret is still in the clear"
    exit 1
fi
if ! grep -q "SECRET_TOKEN" "$SOURCE/.secrets/groups/common/common.sops.yaml"; then
    echo "FAIL: the key name is not readable"
    exit 1
fi
echo "ok: the payload is encrypted and the key names are readable"

# The real sops binary has to be able to read it.
if command -v sops >/dev/null 2>&1; then
    PLAIN=$(SOPS_AGE_KEY_FILE="$HOME_DIR/key.txt" sops --decrypt \
        --input-type yaml --output-type yaml "$SOURCE/.secrets/groups/common/common.sops.yaml")
    if ! echo "$PLAIN" | grep -q "the-secret-value"; then
        echo "FAIL: the sops binary could not read the payload"
        exit 1
    fi
    echo "ok: the sops binary can read the payload"
fi

# The config template asks the tool for the secrets.
cat > "$SOURCE/.chezmoi.toml.tmpl" <<EOF
encryption = "age"

[age]
    identity = "$HOME_DIR/key.txt"

[data]
    token = {{ get (fromJson (output "chezmoi-sops" "data" "--quiet")).secrets "SECRET_TOKEN" | quote }}
EOF

mkdir -p "$SOURCE/private_dot_config"
cat > "$SOURCE/private_dot_config/app.conf.tmpl" <<'EOF'
token = {{ .token | quote }}
EOF

# chezmoi runs the tool as a plugin.
cat > "$SOURCE/.chezmoi.toml" <<EOF
encryption = "age"

[age]
    identity = "$HOME_DIR/key.txt"
EOF

HOME="$HOME_DIR" chezmoi --source "$SOURCE" --destination "$DEST" \
    --config "$SOURCE/.chezmoi.toml" init >/dev/null

HOME="$HOME_DIR" chezmoi --source "$SOURCE" --destination "$DEST" \
    --config "$SOURCE/.chezmoi.toml" apply >/dev/null

# The secret must have reached the target file.
if ! grep -q "the-secret-value" "$DEST/.config/app.conf"; then
    echo "FAIL: the secret did not reach the target file"
    cat "$DEST/.config/app.conf" 2>/dev/null || true
    exit 1
fi
echo "ok: the secret reached the target file"

# A machine that is not a recipient must see the shape, with empty values.
# The payload is still encrypted for the first machine, so the tool has to
# run with the identity of the other one.
SHAPE=$(chezmoi-sops --source-dir "$SOURCE" --identity "$WORK/other.txt" data --quiet 2>/dev/null)
if ! echo "$SHAPE" | grep -q '"SECRET_TOKEN": ""'; then
    echo "FAIL: the shape of the secret is not there"
    echo "$SHAPE"
    exit 1
fi
echo "ok: a machine that cannot read the group still sees the shape"

echo "PASS: the integration works"
