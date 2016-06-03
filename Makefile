#
# Copyright 2016, Joyent, Inc. All rights reserved.
#

#
# Files
#
JS_FILES	:= $(shell find lib -name '*.js')
JSL_CONF_NODE	 = tools/jsl.node.conf
JSL_FILES_NODE   = $(JS_FILES)
JSSTYLE_FLAGS	 = -f tools/jsstyle.conf
JSSTYLE_FILES	 = $(JS_FILES)

#
# Tools
#
NPM_EXEC        := npm
TAPE		:= ./node_modules/.bin/tape

include ./tools/mk/Makefile.defs

#
# Repo-specific targets
#
.PHONY: all
all:
	$(NPM_EXEC) install

.PHONY: test
test: all
	$(TAPE) test/*.test.js

include ./tools/mk/Makefile.deps
include ./tools/mk/Makefile.targ
