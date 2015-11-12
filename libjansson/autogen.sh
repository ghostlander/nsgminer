#!/bin/sh

if test -z "$srcdir"; then srcdir=`dirname "$0"`
	if test -z "$srcdir"; then srcdir=.
	fi
fi

autoreconf -vif "$srcdir"
