# Copyright (C) 2017, Cyberhaven
# All rights reserved.
#
# Licensed under the Cyberhaven Research License Agreement.

TARGETS := $(wildcard *-softmmu)

all: $(TARGETS)
.PHONY: $(TARGETS)

$(TARGETS):
	$(MAKE) -C $@

clean:
	for f in $(TARGETS); do $(MAKE) -C $$f clean; done
