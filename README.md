To compile on Linux (Ubuntu or Limux Mint):
===========================================

# 1 - Install build dependencies:
sudo apt-get install git build-essential cmake liblzo2-dev libssl-dev libc6-dev-i386

# 2 - Get sources
git clone https://github.com/lprot/epk2extract

# 3 - Run building
cd epk2extract ; ./build.sh

After compilation epk2extract will be in folder ./build_linux/ 


To compile on cygwin:
==============================

# 1 - Install cygwin and during setup select following packages:
Devel-> gcc, git, cmake, make
Libs-> liblzo2-devel, zlib-devel
Net-> openssl-devel
Utils-> ncurses

# 2 - Run Cygwin Terminal and get sources
git clone https://github.com/lprot/epk2extract

# 3 - Run building
cd epk2extract ; ./build.sh

After compilation epk2extract and cygwin libs will be in ./build_cygwin/
The build script automatically copies cygwin shared libraries to the bin folder, so you can use epk2extract
without having to install cygwin


## To use:
Put *.pem and AES.key to epk2extract folder.
Run it via sudo because rootfs extraction needs root:
sudo ./epk2extract file

## To to get IDC from SYM run:
./epk2extract xxxxxxxx.sym

## Known issues:
Sometimes Uncramfs segfaults or Unsquashfs does "Read on filesystem failed because Bad file descriptor". 
In that case just run epk2extract again and it will do the job right.

epk2extract might use a large amount of RAM while running and thus slow down your computer.
If the program or your computer seem frozen or not responding please be patient and give it some time to finish.
