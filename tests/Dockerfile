FROM golang:1.23-bookworm

RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      build-essential ca-certificates git iproute2 nftables openssh-client openssl \
      passwd python3 shellcheck \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY Makefile /src/Makefile
COPY go.mod go.sum /src/
COPY src/ /src/src/
COPY tests/ /src/tests/
COPY packaging/ /src/packaging/
COPY ssh3-uid-helper.patch /src/ssh3-uid-helper.patch

RUN make all \
 && make DESTDIR=/staging install \
 && go mod download \
 && shellcheck tests/*.sh \
 && python3 -m py_compile tests/helper_client.py tests/helper_services.py \
      tests/check_ssh3_forwarding.py tests/forwarding_echo.py \
      tests/forwarding_probe.py \
 && test -x /staging/usr/libexec/cmxsafe-ssh3-helper \
 && test -f /staging/usr/lib/systemd/system/cmxsafe-ssh3-helper.service

RUN git clone -q https://github.com/francoismichel/ssh3.git /opt/ssh3/source \
 && git -C /opt/ssh3/source fetch -q origin pull/166/head \
 && git -C /opt/ssh3/source checkout -q FETCH_HEAD \
 && test "$(git -C /opt/ssh3/source rev-parse HEAD)" = c5d8de70b5327145858b984db54948a82fdbeb0a \
 && git -C /opt/ssh3/source apply /src/ssh3-uid-helper.patch \
 && cp /src/src/dial_uid.go /opt/ssh3/source/cmd/dial_uid.go \
 && mkdir -p /opt/ssh3/bin \
 && cd /opt/ssh3/source \
 && go build -o /opt/ssh3/bin/ssh3 ./cmd/ssh3 \
 && go build -o /opt/ssh3/bin/ssh3-server ./cmd/ssh3-server

CMD ["sh", "-c", "tests/test-daemon-kernel.sh /src/build/cmxsafe-ssh3-helper && tests/test-ssh3-forwarding-e2e.sh /src/build/cmxsafe-ssh3-helper"]
