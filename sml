#!/bin/sh

QDIR=$HOME/.smq

for x in $QDIR/mail*
do
	egrep -h -s --color '^(From:|To:|Subject:)' "$x"
	echo ""
done
