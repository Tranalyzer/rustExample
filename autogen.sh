#!/usr/bin/env bash

# Plugin name
PLUGINNAME=rustExample

# Plugin execution order, as 3-digit decimal
PLUGINORDER=654

# --------------------- DO NOT EDIT BELOW HERE --------------------------

T2BUILD_BACKEND=cargo
. "$(dirname "$0")/../autogen.sh"
