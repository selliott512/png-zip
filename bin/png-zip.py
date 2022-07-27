#!/usr/bin/env python3

# png-zip version 1.2
#   by Steven Elliott <selliott512@gmail.com>
#
# This program lists the sections of a PNG file, zips and unzips PNGs to a
# directory and converts PNGs to PPMs.
#
# This script is subject to the GPL version 2.  See
#     http://opensource.org/licenses/gpl-license.php
# for details.

# From http://www.3-t.com/pub/png/spec/1.2/PNG-Chunks.html#C.IHDR :
#
#  Color    Allowed    Interpretation
#  Type    Bit Depths
#
#  0       1,2,4,8,16  Each pixel is a grayscale sample.
#
#  2       8,16        Each pixel is an R,G,B triple.
#
#  3       1,2,4,8     Each pixel is a palette index;
#                      a PLTE chunk must appear.
#
#  4       8,16        Each pixel is a grayscale sample,
#                      followed by an alpha sample.
#
#  6       8,16        Each pixel is an R,G,B triple,
#                      followed by an alpha sample.

import os
from os.path import join
import re
import sys
import struct
from struct import pack, unpack, calcsize
from zlib import decompress
from errno import EEXIST, EISDIR
from optparse import OptionParser

# Pseudo constants
magic_hdr = pack("8B", 137, 80, 78, 71, 13, 10, 26, 10)
bname = os.path.basename(sys.argv[0])
float_re = re.compile("%[.0-9]*f")

# Chunks that can be displayed only knowing the upnack pattern and a format
# specifier.  Additional chunks can be added here.
decode_chunk = {
    "cHRM": [">8I",   "white=%.3f,%.3f red=%.3f,%.3f green=%.3f,%.3f \
blue=%.3f,%.3f "],
    "gAMA": [">I",   "%.4f"],
    "PLTE": [">3B",  "%02x,%02x,%02x"],
    "pHYs": [">2IB", "%dx%d %d"],
    "tIME": [">H5B", "%d-%d-%d %d:%d:%d GMT"]}

## Common functions

# No error if the directory exists.
def mkdir_exists(dir_name):
    try:
        os.mkdir(dir_name)
    except OSError as err:
        if (err.errno != EEXIST) and (err.errno != EISDIR):
            raise(err)

# Like the "mkdir -p" shell command.
def mkdir_p(dir_name):
    if dir_name[0] == "/":
        dir_accum = "/"
    else:
        dir_accum = ""

    for elem in dir_name.split("/"):
        dir_accum = join(dir_accum, elem)
        mkdir_exists(dir_accum)

# Like open() except it logs an error message and exits on failure.
def open_err(fname, mode = "rb"):
    do_write = (mode[0] == "w")
    try:
        hand = open(fname, mode)
    except IOError as err:
        print("Could not open %s for %s: %s" % (
            fname, do_write and "write" or "read", err), file=sys.stderr)
        sys.exit(1)
    return hand

def str_to_base16(a_str): # rep with .encode("base16")
    b16_str = ""
    for a_char in a_str:
        b16_str += "%02x " % a_char
    return b16_str

## Functions that have to do with PNG's CRC32

# Table of CRCs of all 8-bit messages.
crc_table = [0] * 256 # unsigned longs

# Flag: has the table been computed? Initially false.
crc_table_computed = False

# Make the table for a fast CRC.
def make_crc_table():
    global crc_table
    global crc_table_computed

    for n in range(256):
        c = n
        for k in range(8):
            if c & 1:
                c = 0xedb88320 ^ (c >> 1)
            else:
                c >>= 1
        crc_table[n] = c

    crc_table_computed = True

# Update a running CRC with the bytes buf[0..len-1]--the CRC should be
# initialized to all 1's, and the transmitted value is the 1's complement of
# the final running CRC (see the crc() routine below)).
def update_crc(crc, buf):
    c = crc

    if not crc_table_computed:
        make_crc_table()

    for n in range(len(buf)):
        c = crc_table[(c ^ buf[n]) & 0xff] ^ (c >> 8)
    return c

# Return the CRC of the bytes buf[0..len-1].
def crc(buf):
    return update_crc(0xffffffff, buf) ^ 0xffffffff

## Filter functions

# See http://www.3-t.com/pub/png/spec/1.2/PNG-Filters.html
#   Type    Name
#   0       None
#   1       Sub
#   2       Up
#   3       Average
#   4       Paeth

def filter_none(prow, crow, encode):
    pass

def filter_sub(prow, crow, encode):
    for x in range(bpp, row_len):
        pred = crow[x - bpp]
        if encode:
            crow[x] -= pred
        else:
            crow[x] += pred
        crow[x] %= 256

def filter_up(prow, crow, encode):
    for x in range(bpp, row_len):
        pred = prow[x]
        if encode:
            crow[x] -= pred
        else:
            crow[x] += pred
        crow[x] %= 256

def filter_average(prow, crow, encode):
    for x in range(bpp, row_len):
        pred = (crow[x - bpp] + prow[x]) >> 1
        if encode:
            crow[x] -= pred
        else:
            crow[x] += pred
        crow[x] %= 256

def filter_paeth(prow, crow, encode):
    for x in range(bpp, row_len):
        # Following is a,b,c in the documentation.
        left, upper, upper_left = crow[x - bpp], prow[x], prow[x - bpp]
        pred_init = left + upper - upper_left
        pred_left = abs(pred_init - left)
        pred_upper = abs(pred_init - upper)
        pred_upper_left = abs(pred_init - upper_left)

        # return nearest of a,b,c, breaking ties in order a,b,c.
        if (pred_left <= pred_upper) and (pred_left <= pred_upper_left):
            pred = left
        elif (pred_upper <= pred_upper_left):
            pred = upper
        else:
            pred = upper_left

        if encode:
            crow[x] -= pred
        else:
            crow[x] += pred
        crow[x] %= 256

filter_funcs = [filter_none, filter_sub, filter_up, filter_average,
                filter_paeth]
filter_funcs_len = len(filter_funcs)

## Functions that have to do with reading and writing PNGs

def parse_args():
    global args, cont_cols, opts, png_bname, png_fname, zip_dir

    parser = OptionParser(usage="usage: %prog [options] png_file [zip_dir]\n \
          where png_file can be unzipped (-u) or zipped (-z) to zip_dir")

    parser.add_option("-v", "--verbose", action="store_true", dest="verbose",
                      help="verbose output")
    parser.add_option("-l", "--list", action="store_true", dest="list",
                      help="list the chunks")
    parser.add_option("-c", "--cont", action="store_true", dest="cont",
                      help="consider the contents of chunks")
    parser.add_option("-n", "--none", action="store_true", dest="none",
                      help="assume filter type none for PPM")
    parser.add_option("-t", "--trunc", action="store_true", dest="trunc",
                      help="truncate the output to the TTY")
    parser.add_option("-r", "--raw", action="store_true", dest="raw",
                      help="show contents in a raw hex dump")
    parser.add_option("-p", "--ppm", action="store_true", dest="ppm",
                      help="convert png_file to a PPM in the cwd (implies -c)")
    parser.add_option("-f", "--filter-offset", action="store", type="int",
                      dest="foff",
                      help="add some offset to the filter type")
    parser.add_option("-u", "--unzip", action="store_true", dest="unzip",
                      help="unzip png_file to zip_dir")
    parser.add_option("-z", "--zip", action="store_true", dest="zip",
                      help="zip zip_dir to png_file")

    (opts, args) = parser.parse_args()

    if len(args) < 1:
        parser.error("png_file must be specified")

    if opts.ppm and not opts.cont:
        # We need to look at contents for PPMs.
        opts.cont = True
        opts.trunc = False

    cols_str = os.getenv("COLUMNS")
    if cols_str:
        cols = int(cols_str)
    else:
        cols = 80

    if opts.trunc:
        cont_cols = cols - 30
        opts.trunc = True # Show what fits on the screen
    else:
        cont_cols = 1 << 30
        opts.trunc = False

    png_fname = args[0]
    if png_fname.endswith(".png"):
        png_bname = png_fname[:-4]
    else:
        png_bname = png_fname
    if len(args) > 1:
        zip_dir = args[1]
    else:
        zip_dir = png_bname

def write_png():
    png_hand.write(magic_hdr)
    while True:
        chunk_bname = index_hand.readline().rstrip().decode("utf-8") # No \n
        if not chunk_bname:
            index_hand.close()
            png_hand.close()
            return # Done
        chunk_fname = join(zip_dir, chunk_bname)
        try:
            chunk_hand = open(chunk_fname, "rb")
        except:
            print("WARNING: Chunk %s is missing.  Skipping." % chunk_bname, file=sys.stderr)
            continue
        chunk_cont = chunk_hand.read()
        chunk_hand.close()
        chunk_length = len(chunk_cont)
        chunk_type = chunk_bname[:4] # First four chars
        chunk_crc = crc(chunk_type.encode("utf-8") + chunk_cont)

        # Write out the chunk info determined above.
        png_hand.write(pack(">I", chunk_length))
        png_hand.write(chunk_type.encode("utf-8"))
        png_hand.write(chunk_cont)
        png_hand.write(pack(">I", chunk_crc))


# PNG stores floats as ints * 100000.
def png_float(png_int):
    return png_int / 100000.0

def chunk_to_str(chlength, chtype):
    try:
        chunpack, chformat = decode_chunk[chtype]
    except KeyError:
        return None

    chunpack_size = calcsize(chunpack)
    chread = 0
    chcont_str = ""
    sep_char = ""
    # Assume that the format specifier is either all ints or all floats.
    use_floats = float_re.search(chformat) and True or False
    while True:
        if chread + chunpack_size > chlength:
            break
        chpeice = png_hand.read(chunpack_size)
        chread += chunpack_size
        if use_floats:
            chitems = map(png_float, unpack(chunpack, chpeice))
        else:
            chitems = unpack(chunpack, chpeice)

        chcont_str += sep_char + chformat % tuple(chitems)
        sep_char = " "

        if len(chcont_str) == cont_cols:
            break
        elif len(chcont_str) > cont_cols:
            chunk_cont_str = chcont_str[:cont_cols]
            break

    return chcont_str

def read_png():
    global bpp, png_bdepth, png_comp, png_ctype, png_filter, png_height, \
           png_idat, png_width, png_inter

    hdr = png_hand.read(8)
    if hdr != magic_hdr:
        print("%s does not have the correct PNG magic header" % png_fname,
            file=sys.stderr)
        sys.exit(1)

    if opts.ppm:
        png_idat = b""

    if opts.unzip:
        chunk_count = {} # Number of each chunk type.

    if opts.list:
        print("%6s %6s %4s %8s%s" % ("Offset", "Length", "Type", "CRC",
                                     opts.cont and " Contents" or ""))

    while True:
        chunk_offset = png_hand.tell()
        try:
            chunk_length, = unpack(">I", png_hand.read(4))
        except struct.error:
            break # Assume that any unpacking exception is due to EOF
        chunk_type = png_hand.read(4).decode("utf-8")

        if opts.cont:
            if opts.raw and chunk_type != "IHDR":
                # Just do a hex dump of all chunks.  But it is still
                # necessary to parse the header.
                chunk_cont = png_hand.read(min(chunk_length, cont_cols // 3))
                chunk_cont_str = str_to_base16(chunk_cont)
            else:
                # See if it is a "simple" chunk, meaning that we just want to
                # dump out the data based on an unpack pattern and a fromat
                # specifier.
                chunk_cont_str = chunk_to_str(chunk_length, chunk_type)

            # Consider all special chunks.
            if chunk_cont_str:
                pass
            # Following chunk types are in alphabetical order.
            elif chunk_type == "IDAT":
                if opts.ppm:
                    chunk_cont = png_hand.read(chunk_length)
                    png_idat += chunk_cont
                else:
                    chunk_cont = png_hand.read(min(chunk_length, cont_cols // 3))
                if opts.list:
                    chunk_cont_str = str_to_base16(
                        chunk_cont[:min(chunk_length, cont_cols // 3)])
            elif chunk_type == "IHDR":
                chunk_cont = png_hand.read(chunk_length)
                png_width, png_height, png_bdepth, png_ctype, png_comp, \
                           png_filter, png_inter = unpack(">2I5B", chunk_cont)
                if opts.raw:
                    chunk_cont_str = str_to_base16(chunk_cont)
                else:
                    chunk_cont_str = "%dx%d bdepth=%d ctype=%d comp=%d \
filter=%d inter=%d" % (png_width, png_height, png_bdepth, png_ctype,
                       png_comp, png_filter, png_inter)
                if png_ctype == 0:
                    channels = 1
                elif png_ctype == 2:
                    channels = 3
                elif png_ctype == 3:
                    channels = 1
                elif png_ctype == 4:
                    channels = 2
                elif png_ctype == 6:
                    channels = 4
                # Bytes per pixel.  Should have "png_" prefix, but it is used
                # for both PNG and PPM.
                bpp = channels * (png_bdepth >> 3) # Bytes per pixel
            elif chunk_type in ("bKGD", "tRNS"):
                chunk_cont = png_hand.read(min(chunk_length, cont_cols // 3))
                if png_ctype == 3:          # Indexed color
                    chunk_cont_str = str_to_base16(chunk_cont)
                elif png_ctype in (0, 4):  # Greyscale
                    chunk_cont_str = "%02x" % unpack(">H", chunk_cont)
                elif png_ctype in (2, 6):  # True color
                    chunk_cont_str = "%02x,%02x,%02x" % unpack(">3H",
                                                               chunk_cont)
            elif chunk_type == "tEXt":
                chunk_cont_str = png_hand.read(min(chunk_length,
                                     cont_cols)).decode("utf-8").rstrip()
                chunk_cont_str = chunk_cont_str.replace("\x00", "|")
            else:
                # Do a raw hex dump of all unknown chunks.
                chunk_cont = png_hand.read(min(chunk_length, cont_cols // 3))
                chunk_cont_str = str_to_base16(chunk_cont)
            if opts.list and (len(chunk_cont_str) > cont_cols):
                chunk_cont_str = chunk_cont_str[:cont_cols]

        if opts.unzip:
            if chunk_type in chunk_count:
                chunk_count[chunk_type] += 1
            else:
                chunk_count[chunk_type] = 1
            chunk_bname = "%s.%d" % (chunk_type, chunk_count[chunk_type])
            index_hand.write((chunk_bname + "\n").encode("utf-8"))
            chunk_fname = join(zip_dir, chunk_bname)
            chunk_hand = open_err(chunk_fname, "wb")
            # Seek to the chunk's data.
            png_hand.seek(chunk_offset + 8)
            chunk_hand.write(png_hand.read(chunk_length))
            chunk_hand.close()

        png_hand.seek(chunk_offset + chunk_length + 8) # Ignore remaining

        chunk_crc, = unpack(">I", png_hand.read(4))

        if opts.list:
            print("%6d %6d %4s %08x %s" % (chunk_offset, chunk_length,
                                           chunk_type, chunk_crc,
                                           opts.cont and chunk_cont_str or ""))

## Functions that have to do with PPMs

def write_ppm():
    global row_len

    # For PPM format: http://en.wikipedia.org/wiki/Portable_Pixmap_file_format
    if (png_bdepth != 8) or (png_ctype not in (0, 2)) or png_inter:
        print("PPMs can only be created for bdepth=8 and \
non-palette, non-transparent, non-interlaced images", file=sys.stderr)
        sys.exit(1)

    # Array of ints to be fast and mutable.  +bpp  to make left margin easy.
    row_len = (png_width + 1) * bpp
    cur_row = [0] * row_len

    ppm_body = b""
    png_idat_decom = decompress(png_idat)
    scan_num = png_height
    scan_len = 1 + bpp * png_width
    if opts.verbose:
        filter_funcs_count = [0] * filter_funcs_len
    for scan_idx in range(scan_num):
        scan_row = png_idat_decom[scan_len * scan_idx: scan_len * scan_idx +
                                  scan_len]
        filter_type = scan_row[0]
        if filter_type >= filter_funcs_len:
            print("WARNING: Uknown filter type %d" % filter_type, file=sys.stderr)
            filter_type = 0 # Use none for bad filters
        if opts.verbose:
            filter_funcs_count[filter_type] += 1
        if opts.foff:
            # Should make a weird looking PPM.
            filter_type += opts.foff
            filter_type %= filter_funcs_len
        if opts.none:
            filter_type = 0
        filter_func = filter_funcs[filter_type]
        pre_row = cur_row
        cur_row = [0] * bpp + [b for b in scan_row[1:]]
        filter_func(pre_row, cur_row, False)
        ppm_body += bytes(cur_row[bpp:])

    if opts.verbose:
        # Print out stats about the filters.
        print("Count of filter types:", filter_funcs_count)

    ppm_fname = png_bname + ".ppm"
    ppm_hand = open_err(ppm_fname, "wb")

    ppm_hand.write(((png_ctype == 0) and "P5\n" or "P6\n").encode("utf-8"))
    ppm_hand.write(("#Created by %s from %s\n" % (bname, png_fname)).encode("utf-8"))
    ppm_hand.write(("%d %d\n" % (png_width, png_height)).encode("utf-8"))
    ppm_hand.write("255\n".encode("utf-8"))
    ppm_hand.write(ppm_body)

    ppm_hand.close()

### start of main ###

parse_args()

png_hand = open_err(png_fname, opts.zip and "wb" or "rb")

if opts.zip or opts.unzip: # Common to zipping.
    mkdir_p(zip_dir)
    index_fname = join(zip_dir, "index")
    index_hand = open_err(index_fname, opts.unzip and "wb" or "rb")

if opts.zip:
    write_png()
    sys.exit(0) # No other actions are supported for zip.
else:
    read_png()

png_hand.close()

if opts.unzip:
    index_hand.close()

# If -p is specified write the decompressed IDATs out to a PPM.
if  opts.ppm:
    try:
        import psyco
        psyco.bind(write_ppm) # Get a specific func.  Faster than profile().
    except:
        print("WARNING: Psyco not found, PPM will be slow", file=sys.stderr)
    write_ppm()
