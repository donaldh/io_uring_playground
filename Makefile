DEBUG=-g
LIBS=-luring
BINARIES=\
	client \
	trad_client \
	trad_echo_server \
	simple_echo_server

binaries:	bin $(BINARIES:%=bin/%) ## Build all the binaries

bin:
	mkdir bin

bin/%:	%.c
	gcc $(DEBUG) -o $@ $< $(LIBS)

clean:	## Remove generated files
	rm -rf bin/

help:	## This help
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

.PHONY: help
.DEFAULT_GOAL := help
