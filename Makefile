#
# Copyright (c) 2014, Joyent, Inc. All rights reserved.
#

#
# Files
#
JS_FILES	:= $(shell find lib -name '*.js')
JSL_CONF_NODE	 = tools/jsl.node.conf
JSL_FILES_NODE   = $(JS_FILES)
JSSTYLE_FILES	 = $(JS_FILES)
JSSTYLE_FLAGS    = -o indent=4,doxygen,unparenthesized-return=0

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
