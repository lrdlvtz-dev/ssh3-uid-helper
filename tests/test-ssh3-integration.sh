#!/bin/sh
set -eu

repo=$(dirname -- "$0")
repo=$(cd -- "$repo/.." && pwd)
upstream_commit=5b4b242db02a5cfbb9ebf9dfc5aad2c32e10f245
tmp_dir=$(mktemp -d)
cleanup() {
    rm -rf "$tmp_dir"
}
trap cleanup EXIT

git clone -q https://github.com/francoismichel/ssh3.git "$tmp_dir/ssh3"
git -C "$tmp_dir/ssh3" checkout -q "$upstream_commit"
git -C "$tmp_dir/ssh3" apply --check "$repo/ssh3-uid-helper.patch"
git -C "$tmp_dir/ssh3" apply "$repo/ssh3-uid-helper.patch"
cp "$repo/src/dial_uid.go" "$tmp_dir/ssh3/cmd/dial_uid.go"

if grep -Eq 'net\.Dial(TCP|UDP)\(' "$tmp_dir/ssh3/cmd/ssh3-server.go"; then
    echo 'SSH3 still opens a forwarding socket outside the helper' >&2
    exit 1
fi

(
    cd "$tmp_dir/ssh3"
    go test ./cmd/ssh3-server
)

echo "SSH3 integration passed at $upstream_commit"
