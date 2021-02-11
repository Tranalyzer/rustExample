#!/usr/bin/env bash

# Plugin name
PLUGINNAME=rustExample

# Plugin execution order, as 3-digit decimal
PLUGINORDER=654

# --------------------- DO NOT EDIT BELOW HERE --------------------------

# code adapted from autogen_plugin.sh for rust/cargo instead of gcc/autotools

source "$(dirname "$0")/../../scripts/t2utils.sh"

if [ -z "$PLUGINNAME" ] || [ "$PLUGINNAME" != "tranalyzer2" -a -z "$PLUGINORDER" ]; then
    printf "\n\e[0;31mPLUGINNAME and PLUGINORDER MUST be defined\e[0m\n\n"
    exit 1
fi

# Plugin installation directory (-p option)
PLUGIN_DIR="${PLUGIN_DIR:-$HOME/.tranalyzer/plugins}"

# format of the compressed archive (-k option)
PKGEXT="${PKGEXT:-.tar.gz}"

function fatal() {
    echo "$@" >&2
    exit 1
}

function usage() {
    echo "Usage:"
    echo "    ./autogen.sh [OPTION...]"
    echo
    echo "Optional arguments:"
    echo "    -c        execute make clean and remove automatically generated files"
    echo "    -d        compile in debug and profiling mode"
    echo "    -r        force rebuild of makefiles"
    echo "    -u        unload/remove the plugin from the plugin folder"
    echo "    -k        create a compressed archive"
    echo
    echo "    -f        force the copy of extra files"
    echo
    echo "    -p dir    plugin installation directory"
    echo
    echo "    -o level  gcc optimization level"
    echo
    echo "    --rename name  rename plugin"
    echo
    echo "    -h        Show help options and exit"
    echo
}

# https://stackoverflow.com/a/17841619
function join_by { local IFS="$1"; shift; echo "$*"; }

function test_define() {
    cat << EOF | gcc -E -I"$T2HOME/utils/" -I"$T2HOME/tranalyzer2/src/" - > /dev/null 2>&1
#include "tranalyzer.h"
#include "networkHeaders.h"
int main () {
    #if $1
    #else
    #error "not defined"
    #endif
    return 0;
}
EOF
}

function set_features() {
    local nh='../../tranalyzer2/src/networkHeaders.h'
    if [ ! -w "Cargo.toml" ]; then
        fatal "Missing 'Cargo.toml' file"
    fi
    if [ ! -r "$nh" ]; then
        fatal "Could not find 'networkHeaders.h' file."
    fi

    # check that feature key for t2plugin exists in Cargo.toml
    command grep -q '^t2plugin *= *{.*features *= *\[.*\] *}$' Cargo.toml || \
            fatal "Feature $f missing in Cargo.toml"

    local features1=()
    local features2=()

    for f in ETH_ACTIVATE IPV6_ACTIVATE SCTP_ACTIVATE SCTP_STATFINDEX MULTIPKTSUP T2_PRI_HDRDESC; do
        # get define value from networkHeaders.h
        local val="$(perl -nle 'print $1 if /^#define\s+'$f'\s+(\d+).*$/' "$nh")"
        if [ "$f" == "IPV6_ACTIVATE" ] && [ "$val" == "2" ]; then
            # Rust cfg features can be set or not set, so we have to use an additional feature to
            # represent IPV6_ACTIVATE = 2
            features1+=('"IPV6_DUALMODE"')
            features2+=(IPV6_DUALMODE)
        elif [ "$val" == "1" ]; then
            features1+=('"'$f'"')
            features2+=($f)
        fi
    done

    if test_define 'SUBNET_INIT != 0'; then
        features1+=('"SUBNET_INIT"')
        features2+=(SUBNET_INIT)
    fi
    if test_define '(FDURLIMIT > 0 && FDLSFINDEX == 1)'; then
        features1+=('"FLOW_LIFETIME"')
        features2+=(FLOW_LIFETIME)
    fi
    if test_define '((SUBNET_INIT != 0) || (AGGREGATIONFLAG & (SUBNET | SRCIP | DSTIP)))'; then
        features1+=('"FLOW_AGGREGATION"')
        features2+=(FLOW_AGGREGATION)
    fi

    local tmp1="$(join_by , "${features1[@]}")"
    perl -i -pe 's/(^t2plugin *= *\{.*features *= *\[)[^\[\]]*(\] *\}$)/\1'$tmp1'\2/' Cargo.toml
    local tmp2="$(join_by ' ' "${features2[@]}")"
    if [ -n "$tmp2" ]; then
        CARGO_FLAGS+=("--features" "$tmp2")
    fi
}

function check_rust() {
    for cmd in rustc cargo; do
        command -v "$cmd" > /dev/null || fatal "Missing dependency: $cmd"
    done
}

function clean() {
    check_rust
    cargo clean
    type t2_clean &> /dev/null && t2_clean
    return 0
}

unload() {
    local suffix="_${PLUGINNAME}.so"
    if [ -f "$PLUGIN_DIR/"[0-9][0-9][0-9]"$suffix" ]; then
        rm -f "$PLUGIN_DIR/"[0-9][0-9][0-9]"$suffix"
    fi
    exit 0
}

package() {
    local dest="${PLUGINNAME}${PKGEXT}"
    tar --exclude-vcs --exclude-backups --exclude=".*.swp" --exclude="Cargo.lock" -C .. -caf "../$dest" "$PLUGINNAME"
    [ $? -eq 0 ] && mv "../$dest" .
    if [ $? -ne 0 ]; then
        printerr "\nFailed to package plugin $PLUGINNAME\n"
        exit 1
    else
        printok "\nPackage '$dest' successfully created\n"
    fi
}

rename_plugin() {
    local prev="${PLUGINNAME}"
    local new="$(basename "$(pwd)")"

    if ! [[ $new =~ ^[a-z][A-Za-z0-9_]*$ ]]; then
        printerr "invalid plugin name: must start with lowercase and only have chars in [A-Za-z0-9_]"
        exit 1
    fi

    local prev_struct="${prev^}"
    local new_struct="${new^}"

    perl -p -i -e "s/${prev}/${new}/g" Cargo.toml autogen.sh README.md doc/Makefile "doc/${prev}.tex"
    perl -p -i -e "s/${prev_struct}/${new_struct}/g" src/lib.rs
    mv "doc/${prev}.tex" "doc/${new}.tex"

    printok "Successfully renamed plugin: $prev -> $new"
}

build() {
    if type t2_prebuild &> /dev/null; then
        t2_prebuild
        if [ $? -ne 0 ]; then
            printerr "\nt2_prebuild failed for plugin $PLUGINNAME\n"
            exit 1
        fi
    fi

    check_rust
    cargo build "${CARGO_FLAGS[@]}"

    if [ $? -ne 0 ]; then
        printerr "\nFailed to build plugin $PLUGINNAME\n"
        exit 1
    fi
}

install() {
    if [ ! -d "$PLUGIN_DIR" ]; then
        mkdir -p "$PLUGIN_DIR"
    fi

    local parent="$(ps -ocommand= -p $PPID | awk -F/ '{print $NF}' | awk '{print $1}')"
    if [ "$parent" != "autogen.sh" ] && [ -f "$PLUGIN_DIR/${PLUGINORDER}_${PLUGINNAME}.so" ] && [ -n "$(pgrep tranalyzer)" ]; then
        printf "\n${ORANGE}Tranalyzer is currently running... Overwrite the $PLUGINNAME plugin anyway (y/N)? $NOCOLOR"
        read ans
        case $ans in
            Y|y);;
            *) printf "\n"; exit 1
        esac
    fi

    if [ "$DEBUG" == 1 ]; then
        cp "target/debug/lib${PLUGINNAME}.so" "$PLUGIN_DIR/${PLUGINORDER}_${PLUGINNAME}.so"
    else
        cp "target/release/lib${PLUGINNAME}.so" "$PLUGIN_DIR/${PLUGINORDER}_${PLUGINNAME}.so"
    fi

    if [ $? -ne 0 ]; then
        printerr "\nFailed to copy plugin $PLUGINNAME into $PLUGIN_DIR\n"
        exit 1
    else
        printok "\nPlugin $PLUGINNAME copied into $PLUGIN_DIR\n"
    fi

    if type t2_preinst &> /dev/null; then
        t2_preinst
        if [ $? -ne 0 ]; then
            printerr "\nt2_preinst failed for plugin $PLUGINNAME\n"
            exit 1
        fi
    fi

    if [ ${#EXTRAFILES[@]} -ne 0 ]; then
        for i in ${EXTRAFILES[@]}; do
            if type t2_inst &> /dev/null; then
                t2_inst "$i"
                ret=$?
                if [ $ret -eq 0 ]; then
                    echo
                    continue
                elif [ $ret -ne 2 ]; then
                    printerr "\nt2_inst failed for file $i\n"
                    exit 1
                fi
            fi
            if [[ "$i" =~ \.gz$ ]]; then
                DEST="${i%.gz}"
            elif [[ "$i" =~ \.bz2$ ]]; then
                DEST="${i%.bz2}"
            else
                DEST="$i"
            fi
            if [ -e "$PLUGIN_DIR/$DEST" ] && [ "$FORCE" != 1 ]; then
                printwrn "$DEST already exists in $PLUGIN_DIR"
            else
                if [[ "$i" =~ \.gz$ ]]; then
                    gunzip -c "$i" > "$PLUGIN_DIR/$DEST"
                elif [[ "$i" =~ \.bz2$ ]]; then
                    bzcat "$i" > "$PLUGIN_DIR/$DEST"
                else
                    cp -r "$i" "$PLUGIN_DIR"
                fi
                if [ $? -ne 0 ]; then
                    printerr "\nFailed to copy $DEST into $PLUGIN_DIR\n"
                    exit 1
                else
                    printok "$DEST copied into $PLUGIN_DIR"
                fi
            fi
        done
        echo
    fi

    if type t2_postinst &> /dev/null; then
        t2_postinst
        if [ $? -ne 0 ]; then
            printerr "\nt2_postinst failed for $PLUGIN$PLUGINNAME\n"
            exit 1
        fi
    fi
}

# Process args
while [ $# -gt 0 ]; do
    case "$1" in
        -c|--clean) clean; exit 0;;
        -d|--debug) DEBUG=1;;
        -f|--force) FORCE=1;;
        -L|--lazy) unset CLEAN;;
        -r|--configure);;
        -u|--unload) unload;;
        -i|--install);;
        -p|--plugin-dir)
            validate_next_arg "$1" "$2"
            PLUGIN_DIR="$2"
            shift
            ;;
        -o)
            validate_next_num "$1" "$2"
            shift
            ;;
        -k|--package)
            clean && package
            exit $?
            ;;
        --rename)
            rename_plugin
            exit $?
            ;;
        -\?|-h|--help)
            usage
            exit 0
            ;;
        *)
            abort_option_unknown
            ;;
    esac
    shift
done

# Set the CFLAGS
if [ "$DEBUG" == 1 ]; then
    printinf "\nCompiling in debug and profiling mode...\n"
    CARGO_FLAGS=()
else
    CARGO_FLAGS=("--release")
fi

set_features
build
install
