DEBUG=-g
LIBS=-luring
BINARIES=\
	client \
	trad_client \
	trad_echo_server \
	simple_echo_server

binaries:	$(BINARIES) ## Build all the binaries

%:	%.c
	gcc $(DEBUG) -o $@ $< $(LIBS)

clean:	## Remove generated files
	rm -f $(BINARIES)

help:	## This help
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

.PHONY: help
.DEFAULT_GOAL := help
