#!/bin/sh
set -eu

repo=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
ssh3_repo=${SSH3_CMXSAFE_REPO:-/root/.openclaw/workspace/projects/ssh3-cmxsafe}
ssh3_commit=${SSH3_CMXSAFE_COMMIT:-92eb43fe668758e79d7e4b8b0228b32a2ad00e5d}
image=${CMXSAFE_MIRROR_TEST_IMAGE:-cmxsafe-mirror-e2e:test}
context=$(mktemp -d)

cleanup() { rm -rf "$context"; }
trap cleanup EXIT INT TERM

command -v docker >/dev/null
test "$(git -C "$ssh3_repo" rev-parse "$ssh3_commit^{commit}")" = "$ssh3_commit"
mkdir -p "$context/helper" "$context/ssh3"
tar -C "$repo" --exclude=.git --exclude=.tmp --exclude=build \
    --exclude=endpoint/cmxsafe-endpointd -cf - . | tar -C "$context/helper" -xf -
git -C "$ssh3_repo" archive "$ssh3_commit" | tar -C "$context/ssh3" -xf -
cp "$repo/tests/Dockerfile.mirror" "$context/Dockerfile"

docker build --pull=false -t "$image" "$context"
docker run --rm --privileged "$image"
