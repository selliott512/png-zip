# png-zip.py

An open source command line tool for viewing (listing), decomposing (unzipping) and composing (zipping) PNG files.

I wrote this sometime before 2012. Recently I added a unit test and ported to Python 3, but otherwise I have not changed it much.

### Installation

You can just run `png-zip.py` in place from the `bin` directory, or copy it somewhere in the path.

#### Examples

##### Listing

List (-l) all chunks, but also consider the contents of the chunks (-c) while truncating (-t) long lines.
```shell
png-zip.py -tcl image.png
```

##### Unzip

Unzip (-u) all chunks from `image.png` into a directory named `image`.
```shell
png-zip.py -u image.png
```
##### Zip

Zip (-z) all chunks from a directory named `image`to `image.png`.
```shell
png-zip.py -z image.png
```
