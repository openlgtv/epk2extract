epk2extract
===========
epk2extract is a tool that can extract, decrypt, convert multiple file formats that can be found in LG TVs.

Supported Formats:
===========================================
**NOTE: To unpack epk v2 and v3 you need proper AES and RSA keys for decryption. To get the keys you will need to dump them from a running TV. We're thinking about releasing the keys extracted so far in the future.**

**NOTE: To decrypt PVR recordings you need a dump of the unique AES-128 key from your TV**

| Format	| Notes
| :-----	| :-----
| epk v1	| First version of epk format, not encrypted and not signed
| epk v2	| Introduces signing and encryption, keys needed
| epk v3   	| Keys needed
| squashfs	| 
| cramfs	| 
| lz4		| Slightly modified version with header
| lzo		| 
| gzip		| 
| jffs2		| 
| lzhs		| Special compression for MTK bootloaders (boot.pak, tzfw.pak), uses lzss + huffman
| mtinfo/partinfo |  Partition table format (mtdi.pak, part.pak)
| str/pif	| PVR recording format that can be found in netcast models
| sym		| Debugging symbols. Can extracts function names and addresses to an IDA script file (idc)

Although epk2extract is only tested on LG firmware files, you may use it to extract other files like a general unpack tool, as long as they have a supported format in the table above.

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
| lzhs_scanner	| Scans a given file to find lzhs files, and can extracts them


To compile on Linux (Ubuntu, Debian, Linux Mint, Mandriva or Mageia):
===========================================

## 1. Install build dependencies:

    In Ubuntu, do: sudo apt-get install git build-essential cmake liblzo2-dev libssl-dev libc6-dev
    In Mandriva or Mageia, do: urpmi git task-c++-devel cmake liblzo-devel libopenssl-devel glibc-devel --auto

## 2. Get sources

    git clone https://github.com/lprot/epk2extract

## 3. Run building

    cd epk2extract ; ./build.sh

After building epk2extract can be found in ./build_linux/ 


To compile on Cygwin:
=====================

## 1. Install Cygwin and during setup select following packages:

    Devel-> gcc-g++, git, cmake, make
    Libs-> liblzo2-devel, zlib-devel
    Net-> openssl-devel
    Utils-> ncurses
    Editors-> nano

## 2. Run Cygwin Terminal and get sources

    git clone https://github.com/lprot/epk2extract

## 3. Run building

    cd epk2extract ; ./build.sh

After compilation epk2extract and Cygwin *.dll libs can be found in ./build_cygwin/
The build script automatically copies Cygwin shared libraries to the ./build_cygwin/ folder, so you can use epk2extract without having to install Cygwin

To change default editor for commits to nano:
	
	git config --global core.editor "nano"

## To use:

Put *.pem and AES.key files beside epk2extract binary.

Run it via sudo or su because rootfs extraction requires root-access:

In Ubuntu, Debian or Linux Mint, run:
    sudo ./epk2extract file

Alternatively you can use fakeroot to avoid rootfs extraction warnings

    fakeroot ./epk2extract file

In Mandriva or Mageia, run:
    su
    ./epk2extract file

## To to get IDC from SYM run:

    ./epk2extract xxxxxxxx.sym
    
## To to decode part.pak or mtdi.pak do:

    ./epk2extract part.pak

Or use partinfo.py

    python partinfo.py part.pak

## Known issues:
Sometimes Uncramfs segfaults or Unsquashfs does "Read on filesystem failed because Bad file descriptor".
In that case just run epk2extract again and it will do the job right.

epk2extract might use a large amount of RAM while running and thus slow down your computer.
If the program or your computer seem frozen or not responding please be patient and give it some time to finish.
