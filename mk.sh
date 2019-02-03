#!/bin/sh

sh bld_bin.sh
sh flsh.sh
picocom -b115200 /dev/ttyUSB0
