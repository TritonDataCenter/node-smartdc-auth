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


include ./tools/mk/Makefile.defs

#
# Repo-specific targets
#
.PHONY: all
all: 
	npm install

include ./tools/mk/Makefile.deps
include ./tools/mk/Makefile.targ
