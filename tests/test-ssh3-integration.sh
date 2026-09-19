#!/bin/sh
set -eu

repo=$(dirname -- "$0")
repo=$(cd -- "$repo/.." && pwd)
upstream_commit=c5d8de70b5327145858b984db54948a82fdbeb0a
tmp_dir=$(mktemp -d)
cleanup() {
    rm -rf "$tmp_dir"
}
trap cleanup EXIT

git clone -q https://github.com/francoismichel/ssh3.git "$tmp_dir/ssh3"
git -C "$tmp_dir/ssh3" fetch -q origin pull/166/head
git -C "$tmp_dir/ssh3" checkout -q FETCH_HEAD
[ "$(git -C "$tmp_dir/ssh3" rev-parse HEAD)" = "$upstream_commit" ]
git -C "$tmp_dir/ssh3" apply --check "$repo/ssh3-uid-helper.patch"
git -C "$tmp_dir/ssh3" apply "$repo/ssh3-uid-helper.patch"
cp "$repo/src/dial_uid.go" "$tmp_dir/ssh3/cmd/dial_uid.go"

python3 "$repo/tests/check_ssh3_forwarding.py" \
    "$tmp_dir/ssh3/cmd/ssh3-server.go"

(
    cd "$tmp_dir/ssh3"
    go test ./client ./cmd/ssh3-server
)

echo "SSH3 integration passed at $upstream_commit"
