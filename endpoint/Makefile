CC ?= cc
CFLAGS ?= -O2 -g
WARNINGS = -std=c17 -Wall -Wextra -Werror -Wconversion -Wshadow -Wformat=2

.PHONY: all clean test test-privileged

all: cmxsafe-endpointd

cmxsafe-endpointd: cmxsafe-endpointd.c
	$(CC) $(CFLAGS) $(WARNINGS) -o $@ $<

test: cmxsafe-endpointd
	python3 test_endpointd.py ./cmxsafe-endpointd

test-privileged: cmxsafe-endpointd
	./test_namespace.sh ./cmxsafe-endpointd

clean:
	rm -f cmxsafe-endpointd
