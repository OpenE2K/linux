#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
# Kiosk test suite: just run the script
#

try_run() {
  echo "Test: $*" >&2
  if "$@"; then
     echo "Success." >&2
  else
     echo "Failed: exit code $?" >&2
     exit 1
  fi
}

# File appending and removing

clean () {
  kiosk -m "0"

  for i in `kiosk --user-list`
  do
    kiosk -U "$i"
  done
}

check_empty() {
  TMPFILE=$(mktemp)
  try_run kiosk --user-list > $TMPFILE

  if [ -s "$TMPFILE" ]
  then
    echo "Failed: lists are not empty" >&2
    rm -f $TMPFILE
    exit 1
  fi

  rm -f $TMPFILE
}

kiosk_user_append() {
  echo `readlink -f "$1"` >> $TMPFILE
  try_run kiosk --user-list-append "$1"
}

kiosk_user_remove() {
  try_run kiosk --user-list-remove "$1"
}

kiosk_user_list_check() {
  TMPFILE=$1
  LISTFILE=$(mktemp)
  try_run kiosk --user-list > $LISTFILE

  for i in `cat "$LISTFILE"`
  do
    try_run kiosk_user_remove "$i"
  done

  if cmp --quiet $TMPFILE $LISTFILE; then
    echo "Success: user-list match" >&2
  else
    echo "Failed: user-list does not match" >&2
    diff -u $TMPFILE $LISTFILE
    exit 1
  fi

  rm -f $TMPFILE $LISTFILE
}

TMPFILE=$(mktemp)

clean

kiosk_user_append /bin/sh
kiosk_user_append /bin/bash
kiosk_user_append /bin/date
kiosk_user_append /bin/ls
kiosk_user_list_check "$TMPFILE"

# Mode changing
kiosk_set_mode() {
  echo "$1" > $TMPFILE
  try_run kiosk --set-mode "$1"
}

kiosk_check_mode() {
  TMPFILE=$1
  MODEFILE=$(mktemp)
  try_run kiosk --get-mode > $MODEFILE

  if cmp --quiet $TMPFILE $MODEFILE; then
    echo "Success: mode match" >&2
  else
    echo "Failed: mode does not match" >&2
    exit 1
  fi

  rm -rf $TMPFILE $MODEFILE
}

check_empty

TMPFILE=$(mktemp)

kiosk_set_mode "1"
kiosk_check_mode "$TMPFILE"
kiosk_set_mode "0"
kiosk_check_mode "$TMPFILE"

# Exec testing
try_exec() {
  REACT=$1
  shift

  echo "Executing $@" >&2
  "$@" >/dev/null
  if [ "x$REACT" = "xdeny" -a $? -ne 126 ]
  then
    echo "Error: application was executed while it should not be" >&2
    echo "React is $REACT, error code is $?" >&2
    exit 1
  fi
  if [ "x$REACT" = "xperm" -a $? -eq 126 ]
  then
    echo "Error: application was not executed while it should be" >&2
    echo "React is $REACT, error code is $?" >&2
    exit 1
  fi
}

try_exec_user() {
  REACT=$1
  shift

  try_exec $1 su - -c \"$@\" test
}

check_empty

#necessary
raise_guard() {
  kiosk_user_append /bin/bash
  kiosk_user_append /usr/bin/id
  kiosk_user_append /bin/egrep
  kiosk_user_append /bin/grep
  kiosk_user_append /bin/hostname
  kiosk_user_append /usr/bin/natspec
  kiosk_user_append /usr/share/console-scripts/vt_activate_unicode
  kiosk_user_append /usr/share/console-scripts/vt_activate_user_map
  kiosk_user_append /sbin/consoletype
}

stop_guard() {
  kiosk_user_remove /bin/bash
  kiosk_user_remove /usr/bin/id
  kiosk_user_remove /bin/egrep
  kiosk_user_remove /bin/grep
  kiosk_user_remove /bin/hostname
  kiosk_user_remove /usr/bin/natspec
  kiosk_user_remove /usr/share/console-scripts/vt_activate_unicode
  kiosk_user_remove /usr/share/console-scripts/vt_activate_user_map
  kiosk_user_remove /sbin/consoletype
}

raise_guard
kiosk_user_append /bin/false

kiosk_set_mode "0"
try_exec_user perm /bin/false
try_exec_user perm /bin/true
kiosk_set_mode "1"
try_exec_user perm /bin/false
try_exec_user deny /bin/true
kiosk_set_mode "0"

kiosk_user_remove /bin/false
stop_guard

# TODO:
# bogus append to list (non-exist file)
check_empty
kiosk_user_append /bin/tru

# bogus append to list (no params)
kiosk_user_append ""
kiosk_user_append

kiosk_user_append /bin/true
kiosk_user_append /bin/false

# bogus remove from list (non-exist file)
kiosk_user_remove /bin/tru

# bogus remove from list (file is not in list)
kiosk_user_remove /bin/date
kiosk_user_remove /bin/false
kiosk_user_remove /bin/true

# bogus remove from list (list is empty)
check_empty
kiosk_user_remove /bin/false

# bogus remove from list (no params)
kiosk_user_remove ""
kiosk_user_remove

# bogus mode (no params)
kiosk_set_mode ""

# bogus mode
kiosk_set_mode "3"

FILE="/home/test/test"
cp /bin/true $FILE
kiosk_user_append $FILE
kiosk_set_mode "1"

raise_guard

# user executes his own script
chmod 555 $FILE
chown test $FILE
chgrp test $FILE
try_exec_user deny $FILE

# user executes his script with his group
chown root $FILE
try_exec_user perm $FILE
chmod g+w $FILE
try_exec_user deny $FILE
chmod g-w $FILE

# user executes script without permissions
chgrp root $FILE
try_exec_user perm $FILE
chmod o+w $FILE
try_exec_user deny $FILE
chmod o-w $FILE

chmod 000 $FILE
setfacl -m "u:test:rwx" $FILE
try_exec_user deny $FILE
setfacl -m "u:test:r-x" $FILE
try_exec_user perm $FILE
getfacl $FILE

stop_guard

kiosk_set_mode "0"
kiosk_user_remove $FILE
rm -fv $FILE
