#!/bin/sh -e
# Written by Luke Dashjr in 2012
# This program is released under the terms of the Creative Commons "CC0 1.0 Universal" license and/or copyright waiver.

bs_dir="$(dirname "$0")"

#if test -z "$NOSUBMODULES" ; then
#	echo 'Getting submodules...'
#	(
#		cd "${bs_dir}"
#		git submodule update --init
#	)
#fi

echo 'Running autoreconf -ifv...'
(
	cd "${bs_dir}"
	rm -rf autom4te.cache
	rm -f aclocal.m4 ltmain.sh
	autoreconf -ifv
)

if test -z "$NOCONFIGURE" ; then
	echo 'Configuring...'
	"${bs_dir}"/configure CFLAGS="-O2 -fomit-frame-pointer -fno-stack-protector" "$@"
fi
