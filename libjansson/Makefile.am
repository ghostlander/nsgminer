lib_LTLIBRARIES = libjansson.la

libjansson_la_SOURCES = \
	dump.c \
	error.c \
	hashtable.c \
	hashtable.h \
	hashtable_seed.c \
	jansson_private.h \
	load.c \
	lookup3.h \
	memory.c \
	pack_unpack.c \
	strbuffer.c \
	strbuffer.h \
	strconv.c \
	utf.c \
	utf.h \
	value.c

libjansson_la_LDFLAGS = \
	-no-undefined \
	-export-symbols-regex '^json_' \
	-version-info 11:0:7

include_HEADERS = jansson.h jansson_config.h

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = jansson.pc

dist_noinst_SCRIPTS = autogen.sh
dist_doc_DATA = CHANGES LICENSE jansson.def




