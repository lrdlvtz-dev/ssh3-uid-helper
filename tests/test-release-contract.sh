#!/bin/sh
set -eu

if [ "$#" -ne 1 ]; then
    echo "usage: $0 <release-directory>" >&2
    exit 2
fi

release_dir=$1
manifest="$release_dir/cmxsafe-component.json"

jq -e '
  .schema_version == 1 and
  .component == "ssh3-uid-helper" and
  .build.linkage == "dynamic-glibc" and
  .protocol == {name:"cmxsafe-ssh3-uid-helper", version:2} and
  (.executables | map(.name) | sort) == ["cmxsafe-endpointd", "cmxsafe-ssh3-helper"] and
  (.executables[] | select(.name == "cmxsafe-endpointd") |
    .protocol == {name:"cmxsafe-endpoint-lease", version:1}) and
  (.capabilities | index("cmxsafe-uid-helper-protocol-v2")) != null and
  (.capabilities | index("cmxsafe-endpoint-lease-protocol-v1")) != null and
  (.capabilities | index("canonical-ipv6-endpoint-alias-leases")) != null and
  (.capabilities | index("peer-credential-lease-ownership")) != null and
  (.artifacts | length) == 2 and
  (.artifacts | map(.arch) | sort) == ["amd64", "arm64"]
' "$manifest" >/dev/null

for archive in "$release_dir"/ssh3-uid-helper_*_linux_*.tar.gz; do
    members=$(tar -tzf "$archive")
    printf '%s\n' "$members" | grep -Eq '/cmxsafe-ssh3-helper$'
    printf '%s\n' "$members" | grep -Eq '/cmxsafe-endpointd$'
    printf '%s\n' "$members" | grep -Eq '/ENDPOINTD\.md$'
    printf '%s\n' "$members" | grep -Eq '/ENDPOINTD-NOTICE$'
done

(cd "$release_dir" && sha256sum --check SHA256SUMS)
echo 'release contract checks passed'
