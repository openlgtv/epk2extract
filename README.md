[![Build Status](https://travis-ci.org/openlgtv/epk2extract.svg?branch=master)](https://travis-ci.org/openlgtv/epk2extract)

epk2extract
===========

[![Join the chat at https://gitter.im/openlgtv/epk2extract](https://badges.gitter.im/openlgtv/epk2extract.svg)](https://gitter.im/openlgtv/epk2extract?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge&utm_content=badge)

Join on Discord: https://discord.gg/xWqRVEm

epk2extract is a tool that can extract, decrypt, convert multiple file formats that can be found in LG TV sets and similar devices.

Supported Formats:
===========================================
**NOTE: To unpack epk v2 and v3 you need proper AES and RSA keys for decryption. To get them you will need to dump them from a running TV.**

**NOTE: To decrypt PVR recordings you need a dump of the unique AES-128 key from your TV**

| Format	| Notes
| :-----	| :-----
| epk v1	| First version of epk format, not encrypted and not signed
| epk v2	| Introduces signing and encryption, keys needed
| epk v3   	| Introduced with WebOS. Keys needed
| Mediatek pkg | UPG/PKG files used by Hisense/Sharp/Philips (missing Philips AES key) and possibly others
| Philips "fusion" | Upgrade files used by some Philips TVs
| squashfs	| 
| cramfs	| 
| lz4		| Slightly modified version with header magic
| lzo		| 
| gzip		| 
| jffs2		| 
| lzhs		| Special compression for MTK bootloaders (boot.pak, tzfw.pak), uses lzss + huffman
| lzhs_fs   | LZHS compressed filesystem used in MTK Upgrade files for the external writable partition (3rdw)
| mtdinfo/partinfo |  LG Partition table format (mtdi.pak, part.pak)
| str/pif	| PVR recording format that can be found in netcast models
| sym		| LG Debugging symbols. Can extract function names and addresses to an IDA script file (idc)

Although epk2extract is only tested on LG firmware files, you may use it to extract other files like a general unpack tool, as long as they are supported according to the table above.

**!!WARNING!!**<br>
**epk2extract isn't designed to repack files**<br>
**If you wish to repack modified files, follow the openlgtv wiki/forum, and do it in a Linux environment (no cygwin)**<br>
**Don't repack files extracted in cygwin environment**<br>
**In any case, you do so at your own risk**<br>

*THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
OTHER DEALINGS IN THE SOFTWARE*

| Tools:	| Description
| :----		| :----
| lzhsenc	| Compresses a given file with lzhs algorithm
| lzhs_scanner	| Scans a given file to find lzhs files, and extracts them
| idb_extract | Extracts Image Database (IDB) files that can be found in LG firmwares
| jffs2extract | Extracts JFFS2 images. Supports various compression algorithms


To compile on Linux:
===========================================

### Install build dependencies:
Ubuntu/Debian:
```shell
apt-get install git build-essential cmake liblzo2-dev libssl-dev libc6-dev
```
Mandriva/Mageia:
```shell
urpmi git task-c++-devel cmake liblzo-devel libopenssl-devel glibc-devel --auto
```

### Build it
```shell
./build.sh
```

After building, epk2extract can be found in ./build_\<platform\>/ 


To compile on Cygwin:
=====================

### Install Cygwin and during setup select following packages:

    Devel -> gcc-g++, git, cmake, make
    Libs  -> liblzo2-devel, zlib-devel
    Net   -> openssl-devel
    Utils -> ncurses

### Build it
```shell
./build.sh
```

The build script automatically copies required shared libraries to the ./build_cygwin/ folder, so you can use epk2extract standalone/portable without a full cygwin installation.


=====================
### How to speed up extraction process
You can build the test build, which contains compiler optimizations, with this command
```shell
CMAKE_FLAGS=-DCMAKE_BUILD_TYPE=Test ./build.sh
```
The Test build is orders of magnitude faster than the Debug build

### To use:

Put *.pem and AES.key files in the same directory as the epk2extract binary.

Run it via sudo/fakeroot to avoid warnings (while extracting device nodes from rootfs):

    fakeroot ./epk2extract file

## To get IDC from SYM run:

    ./epk2extract xxxxxxxx.sym
    
## To decode part.pak or mtdi.pak do:

    ./epk2extract part.pak

Or use partinfo.py (**deprected**)

    python partinfo.py part.pak
