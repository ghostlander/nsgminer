# Copyright 2012-2013 Luke Dashjr
# Copyright 2012 zefir
# Copyright 2011-2013 Con Kolivas
# Copyright 2013 James Z.M. Gao
# Copyright 2015-2016 John Doering
#
# This program is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the Free
# Software Foundation; either version 3 of the License, or (at your option)
# any later version.  See COPYING for more details.

ACLOCAL_AMFLAGS = -I m4

EXTRA_DIST	= example.conf m4/gnulib-cache.m4 linux-usb-miner \
		  api-example.php miner.php	\
		  api-example.c windows-build.txt \
		  bitstreams/*.bi? bitstreams/COPYING_* API-README FPGA-README SCRYPT-README

SUBDIRS		= lib ccan

# Without a redirected rule, code depending on different lib/*.h files may try to build dependencies of that in parallel, which can fail
lib/%: lib_directory
	@test -e $@
lib_directory:
	$(MAKE) -C lib
ccan/libccan.a:
	$(MAKE) -C ccan $*

INCLUDES	= $(PTHREAD_FLAGS) -fno-strict-aliasing

bin_PROGRAMS	= nsgminer

bin_SCRIPTS	= *.cl

nsgminer_LDFLAGS	= $(PTHREAD_FLAGS)
nsgminer_LDADD	= $(DLOPEN_FLAGS) @LIBCURL_LIBS@ @PTHREAD_LIBS@ \
		  @NCURSES_LIBS@ @PDCURSES_LIBS@ @WS2_LIBS@ \
		  @UDEV_LIBS@ @LIBUSB_LIBS@ \
		  @MATH_LIBS@ lib/libgnu.a ccan/libccan.a
nsgminer_CPPFLAGS = -I$(top_builddir)/lib -I$(top_srcdir)/lib @LIBUSB_CFLAGS@ @LIBCURL_CFLAGS@

nsgminer_CPPFLAGS +=
nsgminer_CPPFLAGS += $(NCURSES_CPPFLAGS)

# common sources
nsgminer_SOURCES := miner.c

nsgminer_SOURCES	+= elist.h miner.h compat.h bench_block.h	\
		   util.c util.h uthash.h logging.h		\
		   sha2.c sha2.h api.c
EXTRA_nsgminer_DEPENDENCIES =

if NEED_LIBBLKMAKER
SUBDIRS           += libblkmaker
nsgminer_CPPFLAGS += -Ilibblkmaker
nsgminer_LDFLAGS  += -Llibblkmaker/.libs -Wl,-rpath,\$$ORIGIN/libblkmaker/.libs$(origin_LDFLAGS)
nsgminer_LDADD    += -lblkmaker_jansson-0.1 -lblkmaker-0.1
EXTRA_nsgminer_DEPENDENCIES += libblkmaker_directory
libblkmaker_directory:
	cd libblkmaker && $(MAKE)

if HAVE_CYGWIN
EXTRA_nsgminer_DEPENDENCIES += cygblkmaker-0.1-0.dll cygblkmaker_jansson-0.1-0.dll

cyg%.dll: libblkmaker/.libs/cyg%.dll
	cp -p $< $@
endif

endif

if NEED_LIBBASE58
SUBDIRS           += libbase58
nsgminer_CPPFLAGS += -Ilibbase58
nsgminer_LDFLAGS  += -Llibbase58/.libs -Wl,-rpath,\$$ORIGIN/libbase58/.libs$(origin_LDFLAGS)
nsgminer_LDADD    += -lbase58
EXTRA_nsgminer_DEPENDENCIES += libbase58_directory
libbase58_directory:
	cd libbase58 && $(MAKE)

if HAVE_CYGWIN
EXTRA_nsgminer_DEPENDENCIES += cygbase58-0.dll

cyg%.dll: libbase58/.libs/cyg%.dll
	cp -p $< $@
endif

endif

if NEED_LIBJANSSON
SUBDIRS           += libjansson
nsgminer_CPPFLAGS += -Ilibjansson
nsgminer_LDFLAGS  += -Llibjansson/.libs -Wl,-rpath,\$$ORIGIN/libjansson/.libs$(origin_LDFLAGS)
nsgminer_LDADD    += -ljansson
EXTRA_nsgminer_DEPENDENCIES += libjansson_directory
libjansson_directory:
	cd libjansson && $(MAKE)

if HAVE_CYGWIN
EXTRA_nsgminer_DEPENDENCIES += cygjansson-4.dll

cyg%.dll: libjansson/.libs/cyg%.dll
	cp -p $< $@
endif

endif

nsgminer_SOURCES	+= logging.c

# GPU sources, TODO: make them selectable
# the GPU portion extracted from original main.c
nsgminer_SOURCES += driver-opencl.h driver-opencl.c

# the original GPU related sources, unchanged
nsgminer_SOURCES += ocl.c ocl.h findnonce.c findnonce.h
nsgminer_SOURCES += adl.c adl.h adl_functions.h
nsgminer_SOURCES += nvml.c
nsgminer_SOURCES += *.cl

# NeoScrypt and Scrypt dependency
nsgminer_SOURCES += neoscrypt.c neoscrypt.h

if HAS_CPUMINE
# original CPU related sources, unchanged
nsgminer_SOURCES	+= \
		  sha256_generic.c sha256_4way.c sha256_via.c	\
		  sha256_cryptopp.c sha256_sse2_amd64.c		\
		  sha256_sse4_amd64.c sha256_sse2_i386.c	\
		  sha256_altivec_4way.c

# the CPU portion extracted from original main.c
nsgminer_SOURCES += driver-cpu.h driver-cpu.c

if HAS_YASM
AM_CFLAGS	= -DHAS_YASM
if HAVE_x86_64
SUBDIRS		+= x86_64
x86_64/libx8664.a:
	$(MAKE) -C x86_64 $*
nsgminer_LDADD	+= x86_64/libx8664.a
else # HAVE_x86_64
SUBDIRS		+= x86_32
x86_32/libx8632.a:
	$(MAKE) -C x86_32 $*
nsgminer_LDADD	+= x86_32/libx8632.a
endif # HAVE_x86_64
endif # HAS_YASM
endif # HAS_CPUMINE

if NEED_FPGAUTILS
nsgminer_SOURCES += fpgautils.c fpgautils.h
endif

if NEED_DYNCLOCK
nsgminer_SOURCES += dynclock.c dynclock.h
endif

if HAS_BITFORCE
nsgminer_SOURCES += driver-bitforce.c

if HAVE_WINDOWS
else
bin_PROGRAMS += bitforce-firmware-flash
bitforce_firmware_flash_SOURCES = bitforce-firmware-flash.c
endif
endif

if HAS_ICARUS
nsgminer_SOURCES += driver-icarus.c icarus-common.h
nsgminer_SOURCES += driver-cairnsmore.c
endif

if HAS_MODMINER
nsgminer_SOURCES += driver-modminer.c
bitstreamsdir = $(bindir)/bitstreams
dist_bitstreams_DATA = bitstreams/*.bi? bitstreams/COPYING_*
endif

if HAS_X6500
nsgminer_SOURCES += driver-x6500.c ft232r.c ft232r.h jtag.c jtag.h
bitstreamsdir = $(bindir)/bitstreams
dist_bitstreams_DATA = bitstreams/*.bi? bitstreams/COPYING_*
endif

if HAS_ZTEX
nsgminer_SOURCES += driver-ztex.c libztex.c libztex.h
bitstreamsdir = $(bindir)/bitstreams
dist_bitstreams_DATA = bitstreams/*.bi? bitstreams/COPYING_*
endif

bin_PROGRAMS += nsgminer-rpc
nsgminer_rpc_SOURCES = api-example.c
nsgminer_rpc_LDADD = @WS2_LIBS@
