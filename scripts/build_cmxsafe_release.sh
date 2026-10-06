#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 3 ]]; then
    printf 'usage: %s <version> <source-commit> <output-dir>\n' "$0" >&2
    exit 2
fi

version="$1"
source_commit="$2"
output_dir="$3"

if [[ ! "$version" =~ ^[0-9A-Za-z][0-9A-Za-z._+-]*$ ]]; then
    printf 'invalid release version: %s\n' "$version" >&2
    exit 2
fi
if [[ ! "$source_commit" =~ ^[0-9a-f]{40}$ ]]; then
    printf 'source commit must be a full lowercase Git SHA-1\n' >&2
    exit 2
fi

for tool in git jq sha256sum tar gzip file readelf; do
    command -v "$tool" >/dev/null 2>&1 || {
        printf 'required tool not found: %s\n' "$tool" >&2
        exit 2
    }
done

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
actual_commit="$(git -C "$repo_root" rev-parse HEAD)"
if [[ "$actual_commit" != "$source_commit" ]]; then
    printf 'source commit %s does not match checked-out commit %s\n' "$source_commit" "$actual_commit" >&2
    exit 2
fi

mkdir -p "$output_dir"
output_dir="$(cd "$output_dir" && pwd)"
work_dir="$(mktemp -d -t ssh3-helper-release.XXXXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT

source_date_epoch="$(git -C "$repo_root" show -s --format=%ct "$source_commit")"
export SOURCE_DATE_EPOCH="$source_date_epoch"

artifacts_json='[]'
for arch in amd64 arm64; do
    if [[ "$arch" == "amd64" ]]; then
        compiler="${CXX_AMD64:-c++}"
    else
        compiler="${CXX_ARM64:-aarch64-linux-gnu-g++}"
    fi
    command -v "$compiler" >/dev/null 2>&1 || {
        printf 'required %s compiler not found: %s\n' "$arch" "$compiler" >&2
        exit 2
    }

    stage="$work_dir/ssh3-uid-helper_${version}_linux_${arch}"
    mkdir -p "$stage"
    "$compiler" -O2 -std=c++17 -Wall -Wextra -Werror -Wpedantic \
        -D_FORTIFY_SOURCE=2 -fstack-protector-strong -fPIE \
        "-ffile-prefix-map=$repo_root=." "-fdebug-prefix-map=$repo_root=." \
        -Wl,-z,relro,-z,now,--build-id=none -pie -s \
        -o "$stage/cmxsafe-ssh3-helper" "$repo_root/src/helper_daemon_v2.cpp"
    file "$stage/cmxsafe-ssh3-helper" | grep -q 'pie executable'
    readelf -h "$stage/cmxsafe-ssh3-helper" | grep -Eq 'Type:.*DYN'
    readelf -l "$stage/cmxsafe-ssh3-helper" | grep -q 'GNU_RELRO'
    readelf -d "$stage/cmxsafe-ssh3-helper" | grep -q 'BIND_NOW'
    install -m 0644 "$repo_root/packaging/cmxsafe-ssh3-helper.service" "$stage/cmxsafe-ssh3-helper.service"
    install -m 0644 "$repo_root/README.md" "$stage/README.md"
    install -m 0644 "$repo_root/LICENSE" "$stage/LICENSE"

    artifact_name="ssh3-uid-helper_${version}_linux_${arch}.tar.gz"
    tar --sort=name --mtime="@$source_date_epoch" --owner=0 --group=0 --numeric-owner \
        -C "$work_dir" -cf - "$(basename "$stage")" | gzip -n > "$output_dir/$artifact_name"
    artifact_sha256="$(sha256sum "$output_dir/$artifact_name" | awk '{print $1}')"
    artifacts_json="$(jq -c \
        --arg name "$artifact_name" \
        --arg arch "$arch" \
        --arg sha256 "$artifact_sha256" \
        '. + [{name:$name, os:"linux", arch:$arch, sha256:$sha256}]' \
        <<<"$artifacts_json")"
done

jq -n \
    --arg version "$version" \
    --arg commit "$source_commit" \
    --argjson artifacts "$artifacts_json" \
    '{
      schema_version: 1,
      component: "ssh3-uid-helper",
      release_version: $version,
      source: {
        repository: "https://github.com/lrdlvtz-dev/ssh3-uid-helper",
        commit: $commit
      },
      build: {
        source_date_epoch: env.SOURCE_DATE_EPOCH,
        linkage: "dynamic-glibc",
        minimum_glibc: "2.35",
        hardening: ["PIE", "RELRO", "NOW", "FORTIFY_SOURCE=2", "stack-protector-strong"]
      },
      lifecycle: "experimental",
      protocol: {
        name: "cmxsafe-ssh3-uid-helper",
        version: 2
      },
      capabilities: [
        "cmxsafe-uid-helper-protocol-v2",
        "authenticated-uid-ipv6-socket-factory",
        "tcp-connect",
        "udp-connect",
        "tcp-listen-accept",
        "udp-bind",
        "supplementary-group-clearing",
        "scm-rights"
      ],
      artifacts: $artifacts
    }' > "$output_dir/cmxsafe-component.json"

(
    cd "$output_dir"
    sha256sum ./*.tar.gz cmxsafe-component.json > SHA256SUMS
)
