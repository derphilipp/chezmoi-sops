#!/usr/bin/env bash
# Downloads a release asset and installs it.
#
# The download is retried, because GitHub sometimes answers with an error
# page instead of the asset, and the result is checked, so a broken download
# fails loudly instead of installing a page of HTML.
#
# The target directory is $INSTALL_DIR, or /usr/local/bin.

set -euo pipefail

NAME=$1
VERSION=$2
REPO=$3
ASSET=$4

INSTALL_DIR=${INSTALL_DIR:-/usr/local/bin}
URL="https://github.com/${REPO}/releases/download/${VERSION}/${ASSET}"
TARGET="/tmp/${NAME}-download"

echo "installing ${NAME} ${VERSION} from ${URL}"

for attempt in 1 2 3; do
    if curl -fsSL --retry 3 --retry-delay 2 -o "$TARGET" "$URL"; then
        break
    fi
    if [ "$attempt" = 3 ]; then
        echo "could not download ${URL}" >&2
        exit 1
    fi
    echo "the download failed, retrying (${attempt}/3)" >&2
    sleep 5
done

# A GitHub error page is HTML, not the binary.
if head -c 100 "$TARGET" | grep -qi "<!DOCTYPE html"; then
    echo "the download returned a web page instead of the asset:" >&2
    head -c 200 "$TARGET" >&2
    exit 1
fi

if [ ! -s "$TARGET" ]; then
    echo "the downloaded asset is empty" >&2
    exit 1
fi

mkdir -p "$INSTALL_DIR"

# A tarball is unpacked and everything in it is installed, a raw binary is
# installed as it is. The asset name decides, not the name of the temporary
# file.
case "$ASSET" in
    *.tar.gz)
        WORK=$(mktemp -d)
        tar -xzf "$TARGET" -C "$WORK"
        find "$WORK" -type f -perm -u+x -exec install -m 0755 {} "$INSTALL_DIR/" \;
        ;;
    *)
        install -m 0755 "$TARGET" "$INSTALL_DIR/$NAME"
        ;;
esac

"$INSTALL_DIR/$NAME" --version || true
