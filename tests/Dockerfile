FROM golang:1.23-bookworm

RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      build-essential iproute2 nftables passwd python3 shellcheck \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY Makefile /src/Makefile
COPY go.mod go.sum /src/
COPY src/ /src/src/
COPY tests/ /src/tests/
COPY packaging/ /src/packaging/

RUN make all \
 && make DESTDIR=/staging install \
 && go mod download \
 && shellcheck tests/*.sh \
 && python3 -m py_compile tests/helper_client.py tests/helper_services.py \
 && test -x /staging/usr/libexec/cmxsafe-ssh3-helper \
 && test -f /staging/usr/lib/systemd/system/cmxsafe-ssh3-helper.service

CMD ["sh", "tests/test-daemon-kernel.sh", "/src/build/cmxsafe-ssh3-helper"]
