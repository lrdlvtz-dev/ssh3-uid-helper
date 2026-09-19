CXX ?= c++
CXXFLAGS ?= -O2 -g -std=c++17 -Wall -Wextra -Werror -Wpedantic
PREFIX ?= /usr
DESTDIR ?=

BUILD_DIR := build
HELPER := $(BUILD_DIR)/cmxsafe-ssh3-helper

.PHONY: all clean test test-kernel test-ssh3 install

all: $(HELPER)

$(HELPER): src/helper_daemon_v2.cpp src/protocol.h
	mkdir -p $(BUILD_DIR)
	$(CXX) $(CXXFLAGS) -o $@ src/helper_daemon_v2.cpp

test: $(HELPER)
	go test src/dial_uid.go src/dial_uid_test.go src/dial_uid_integration_test.go
	sh tests/test-static.sh

test-ssh3:
	sh tests/test-ssh3-integration.sh

test-kernel:
	docker build -t cmxsafe-ssh3-helper-test -f tests/Dockerfile .
	docker run --rm --privileged cmxsafe-ssh3-helper-test

install: $(HELPER)
	install -D -m 0755 $(HELPER) $(DESTDIR)$(PREFIX)/libexec/cmxsafe-ssh3-helper
	install -D -m 0644 packaging/cmxsafe-ssh3-helper.service \
		$(DESTDIR)$(PREFIX)/lib/systemd/system/cmxsafe-ssh3-helper.service

clean:
	rm -rf $(BUILD_DIR)
