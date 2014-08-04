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
