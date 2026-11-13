#!/bin/sh
# A fake editor for the integration test: it writes a payload with one
# secret in it.

cat > "$1" <<'EOF'
SECRET_TOKEN: the-secret-value
EOF
