#!/bin/sh

# Copyright 2012 Google Inc. All Rights Reserved.
#
# Load mem2alloc

module="mem2alloc"
device="/dev/mem2alloc"
mode="666"

echo

#insert module
rm_module=`lsmod |grep $module`
if [ ! -z "$rm_module" ]
then
   rmmod $module || exit 1
fi
modprobe $module $* || exit 1

echo "module $module inserted"

#remove old nod
rm -f $device

#read the major asigned at loading time
major=`cat /proc/devices | grep $module | cut -c1-3`

echo "$module major = $major"

#create dev node
mknod $device c $major 0

echo "node $device created"

#give all 'rw' access
chmod $mode $device

echo "set node access to $mode"

#the end
echo
