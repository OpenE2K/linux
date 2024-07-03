 # SPDX-License-Identifier: GPL-2.0
 # Copyright (c) 2023 MCST
 
#!/bin/sh
#
# lcc-version lcc-command
#
# MCST: Print the lcc version of `lcc-command' in a 5 or 6-digit
# form such as `12614' for lcc-1.26.14,`12706' for lcc-1.27.6, etc.
# Return 0 if compiler is not lcc.

compiler="$*"

if [ ${#compiler} -eq 0 ]; then
	echo "Error: No compiler specified." >&2
	printf "Usage:\n\t$0 <lcc-command>\n" >&2
	exit 1
fi

if $compiler --version | head -n 1 | grep -q lcc; then
	MAJOR=$(echo __LCC__ | $compiler -E -x c - | tail -n 1)
	MINOR=$(echo __LCC_MINOR__ | $compiler -E -x c - | tail -n 1)
	printf "%d%02d\\n" $MAJOR $MINOR
else
	echo "0"
fi
