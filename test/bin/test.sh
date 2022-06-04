#!/bin/bash

# A simple test suite for png-zip. Requires ImageMagick.

# Semi-strict mode.

set -eo pipefail
# For bash 4.3 and earlier empty arrays fail with "set -u".
if [[ $(( 10*BASH_VERSINFO[0] + BASH_VERSINFO[1] )) -ge 44 ]]
then
    set -u
fi

# Globals
bname="${0##*/}"
errors=0
top_dir=$(realpath `dirname $0`/../..)
in_dir="$top_dir/test/data/in"
out_dir="$top_dir/test/data/out"
png_zip_base="png-zip.py"
png_zip="$top_dir/bin/$png_zip_base"

# Functions
function cleanup()
{
    # Delete the temporary directory with various checks to make it safe.
    if [[ $errors -gt 0 ]]
    then
        echo "Keeping temporary directory \"$tmp_dir\" due to errors."
    else
        echo "Deleting temporary directory \"$tmp_dir\"."
        if [[ (-n $tmp_dir) && (-d $tmp_dir) && (${#tmp_dir} -ge 10) ]]
        then
            rm -rf "$tmp_dir"
        fi
    fi
}

# Main
tmp_dir=$(mktemp -td "${bname}.XXXXXXXXXX")
trap cleanup EXIT

# Test the help.
out_actual="$tmp_dir/help.txt"
out_expected="$out_dir/help.txt"
"$png_zip" -h > "$out_actual"
if ! diff -q "$out_actual" "$out_expected"
then
    let ++errors
    echo "The help (-h) was not as expected." 1>&2
fi

for in_png in "$in_dir"/*.png
do
    # Try listing each image with various options.
    in_base="${in_png##*/}"
    for opts in l cl rl rcl tcl
    do
        # Options -rl is just like -l since -r is a modifier of -c.
        if [[ $opts == "rl" ]]
        then
            opts="l"
        fi

        out_base="${in_base/.png/-$opts.txt}"
        out_actual="$tmp_dir/$out_base"
        out_expected="$out_dir/$out_base"
        "$png_zip" "-$opts" "$in_png" > "$out_actual"
        if ! diff -q "$out_actual" "$out_expected"
        then
            let ++errors
            echo "Output for -$opts does not match for \"$in_png\"." 1>&2
        fi
    done

    # Decompress and recompress each image, then compare.
    in_name="${in_base%.png}"
    out_unzipped="$tmp_dir/$in_name"
    out_actual="$tmp_dir/$in_base"
    "$png_zip" -u "$in_png"     "$out_unzipped"
    "$png_zip" -z "$out_actual" "$out_unzipped"
    if ! diff -q "$out_actual" "$in_png"
    then
        let ++errors
        echo "Recreated PNG does not match for \"$in_png\"." 1>&2
    fi

    # Test PPM for RGB only using the zipped PNG.
    if [[ $in_name == rgb ]]
    then
        out_actual_ppm="${out_actual/.png/.ppm}"
        out_expected="${out_actual_ppm/.ppm/-expected.ppm}"
        convert -comment "Created by $png_zip_base from $out_actual" "$out_actual" "$out_expected"
        "$png_zip" -p "$out_actual"
        if ! diff -q "$out_actual_ppm" "$out_expected"
        then
            let ++errors
            echo "PPM does not match for \"$in_png\"." 1>&2
        fi
    fi
done

if [[ $errors -gt 0 ]]
then
    echo "There were $errors errors." 1>&2
    exit 1
else
    echo "Success."
fi
