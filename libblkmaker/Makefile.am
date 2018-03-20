# Copyright 2012-2013 Luke Dashjr
#
# This program is free software; you can redistribute it and/or modify it
# under the terms of the standard MIT license.  See COPYING for more details.

lib_LTLIBRARIES = \
	libblkmaker_jansson-@LIBBLKMAKER_API_VERSION@.la \
	libblkmaker-@LIBBLKMAKER_API_VERSION@.la


libblkmaker_@LIBBLKMAKER_API_VERSION@_la_SOURCES = \
	base58.c \
	blkmaker.c \
	blktemplate.c \
	hex.c \
	private.h

libblkmaker_@LIBBLKMAKER_API_VERSION@_la_CFLAGS = \
	-I../libbase58

libblkmaker_@LIBBLKMAKER_API_VERSION@_la_LDFLAGS = \
	-L../libbase58 -lbase58 \
	-no-undefined \
	-version-info $(LIBBLKMAKER_SO_VERSION)

libblkmaker_includedir = $(includedir)/libblkmaker-$(LIBBLKMAKER_API_VERSION)
libblkmaker_include_HEADERS = \
	blkmaker.h \
	blktemplate.h

libblkmaker_jansson_@LIBBLKMAKER_API_VERSION@_la_SOURCES = blkmaker_jansson.c
libblkmaker_jansson_@LIBBLKMAKER_API_VERSION@_la_DEPENDENCIES = libblkmaker-$(LIBBLKMAKER_API_VERSION).la
libblkmaker_jansson_@LIBBLKMAKER_API_VERSION@_la_CFLAGS = -I../libjansson
libblkmaker_jansson_@LIBBLKMAKER_API_VERSION@_la_LDFLAGS = \
	-L.libs \
	-lblkmaker-$(LIBBLKMAKER_API_VERSION) \
	-L../libjansson -ljansson \
	-no-undefined \
	-version-info $(LIBBLKMAKER_SO_VERSION)

libblkmaker_jansson_includedir = $(includedir)/libblkmaker-$(LIBBLKMAKER_API_VERSION)
libblkmaker_jansson_include_HEADERS = \
	blkmaker_jansson.h

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = \
	libblkmaker_jansson-$(LIBBLKMAKER_API_VERSION).pc

dist_noinst_SCRIPTS = autogen.sh test.sh
dist_noinst_DATA = \
	AUTHORS COPYING README \
	example.c \
	testinput.c
	
if HAVE_LIBGCRYPT
check_PROGRAMS = test
test_SOURCES = test.c
test_CFLAGS = -I../libbase58 -I../libjansson $(LIBGCRYPT_CFLAGS)
test_LDADD = -L../libbase58 -lbase58 -L../libjansson -ljansson $(LIBGCRYPT_LIBS) \
	libblkmaker-@LIBBLKMAKER_API_VERSION@.la libblkmaker_jansson-@LIBBLKMAKER_API_VERSION@.la
TESTS = test.sh

EXTRA_PROGRAMS = example
example_SOURCES = example.c
example_CFLAGS = -I../libbase58 -I../libjansson $(LIBGCRYPT_CFLAGS)
example_LDADD = -L../libbase58 -lbase58 -L../libjansson -ljansson  $(LIBGCRYPT_LIBS) \
	libblkmaker-@LIBBLKMAKER_API_VERSION@.la libblkmaker_jansson-@LIBBLKMAKER_API_VERSION@.la
else
example:
	@echo "libgcrypt is required to build the example, but was not found"
.PHONY: example
endif
